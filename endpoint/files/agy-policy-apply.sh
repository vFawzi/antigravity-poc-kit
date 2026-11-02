#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Simulated MDM agent: push group policy to each member and lock it read-only.
# Runs at boot (agy-policy.service) and on every bootstrap run.
set -euo pipefail
POLICY_DIR=/etc/antigravity/policies

# lock_managed <src> <user> <grp> <dir> <name> <drift-tag>: <dir>/<name> becomes a read-only bind mount of the root-owned
# <src> (same pattern as settings.json); a user's own differing file is reported as drift and stays hidden under the mount
lock_managed() {
  local src=$1 user=$2 grp=$3 dir=$4 name=$5 tag=$6 tgt
  tgt="$dir/$name"
  install -d -o "$user" -g "$grp" -m 700 "$dir"; chown root:"$grp" "$dir"; chmod 1770 "$dir"
  [[ -e "$tgt" && ! -L "$tgt" ]] || { rm -f "$tgt"; touch "$tgt"; }
  while findmnt -rn -o TARGET | grep -qxF "$tgt"; do umount "$tgt" || break; done
  if [[ -s "$tgt" ]] && ! cmp -s "$src" "$tgt"; then
    logger -p auth.warning -t agy-mdm "user=$user $tag corrected: $name replaced by the managed copy"
  fi
  mount --bind "$src" "$tgt"; mount -o remount,bind,ro "$tgt"
}

# Enterprise Gateway mode (admin tier): re-assert and alert on drift
ADMIN_SRC=$POLICY_DIR/admin_settings.json; ADMIN_DST=/etc/antigravity/admin_settings.json
if [[ -f $ADMIN_SRC ]]; then
  if ! cmp -s "$ADMIN_SRC" "$ADMIN_DST" 2>/dev/null; then
    [[ -e $ADMIN_DST ]] && logger -p auth.warning -t agy-mdm "ADMIN_SETTINGS_DRIFT detected - restoring managed gateway config"
    install -o root -g root -m 644 "$ADMIN_SRC" "$ADMIN_DST"
  fi
fi
for grp in agy-dev agy-contractor; do
  policy="$POLICY_DIR/${grp}.settings.json"
  [[ -f "$policy" ]] || { logger -t agy-mdm "missing policy $policy"; continue; }
  gid=$(getent group "$grp" | cut -d: -f3)
  for user in $(awk -F: -v g="$gid" '$4==g{print $1}' /etc/passwd); do
    home=$(getent passwd "$user" | cut -d: -f6)
    cfg_dir="$home/.gemini/antigravity-cli"
    target="$cfg_dir/settings.json"
    install -d -o "$user" -g "$grp" -m 700 "$home/.gemini" "$cfg_dir"
    # parent directories of the policy file are root-owned so the user (or agent)
    # cannot rename them away from the mount; app state lives in sub-dirs it can write
    chown root:"$grp" "$home/.gemini" "$cfg_dir"; chmod 1770 "$home/.gemini" "$cfg_dir"
    [[ -e "$target" && ! -L "$target" ]] || { rm -f "$target"; touch "$target"; }
    # `mountpoint` is unreliable for file bind mounts -> use the mount table; also clears stacked mounts
    while findmnt -rn -o TARGET | grep -qxF "$target"; do umount "$target" || break; done
    if [[ -f "/etc/antigravity/enrollment/$user" ]]; then
      # first-run window: user-writable copy seeded from policy; onboarding state merged back by agy-enroll end
      chown "$user":"$grp" "$cfg_dir"
      [[ -s "$target" ]] || cp "$policy" "$target"
      chown "$user":"$grp" "$target"; chmod 600 "$target"
      logger -t agy-mdm "policy=$grp user=$user status=skipped reason=enrollment-mode"; continue
    fi
    mount --bind "$policy" "$target"
    mount -o remount,bind,ro "$target"
    # The CLI can't persist the terms/onboarding step to the read-only settings file, so the interactive TUI would
    # stop at that screen forever. Mark enterprise onboarding complete in the CLI's own (user-writable) state file;
    # existing keys are kept. Verified with CLI 1.4.7 (state file cache/onboarding.json).
    ob="$cfg_dir/cache/onboarding.json"
    install -d -o "$user" -g "$grp" -m 700 "$cfg_dir/cache"
    if ! jq -e '.enterpriseOnboardingComplete == true' "$ob" >/dev/null 2>&1; then
      { jq '. + {enterpriseOnboardingComplete: true}' "$ob" 2>/dev/null || echo '{"enterpriseOnboardingComplete": true}'; } > "$ob.new" \
        && install -o "$user" -g "$grp" -m 600 "$ob.new" "$ob"; rm -f "$ob.new"
      logger -t agy-mdm "user=$user onboarding-state seeded (read-only managed settings)"
    fi
    # corporate hooks: global hooks.json is a read-only bind mount of the root-owned copy (same pattern as settings.json)
    hooks_src=/etc/antigravity/hooks/hooks.json; hdir="$home/.gemini/config"; htarget="$hdir/hooks.json"
    if [[ -f $hooks_src ]]; then
      install -d -o "$user" -g "$grp" -m 700 "$hdir"; chown root:"$grp" "$hdir"; chmod 1770 "$hdir"
      [[ -e "$htarget" && ! -L "$htarget" ]] || { rm -f "$htarget"; touch "$htarget"; }
      while findmnt -rn -o TARGET | grep -qxF "$htarget"; do umount "$htarget" || break; done
      mount --bind "$hooks_src" "$htarget"; mount -o remount,bind,ro "$htarget"
    fi
    # MCP servers: managed per group (ships with no servers; approved servers are added to the policy copy)
    mcp_src="$POLICY_DIR/${grp}.mcp_config.json"
    if [[ -f $mcp_src ]]; then lock_managed "$mcp_src" "$user" "$grp" "$hdir" mcp_config.json MCP_CONFIG_DRIFT; fi
    # browser allowlist (localhost + agy-browser-allowlist), rendered by bootstrap
    bal_src="$POLICY_DIR/browserAllowlist.txt"
    if [[ -f $bal_src ]]; then
      lock_managed "$bal_src" "$user" "$grp" "$home/.gemini/antigravity" browserAllowlist.txt BROWSER_ALLOWLIST_DRIFT
    fi
    logger -t agy-mdm "policy=$grp user=$user target=$target sha256=$(sha256sum "$policy" | cut -c1-16) status=applied"
  done
done

# AGY version management (CLI to the policy's target version; swap only while no CLI runs) - never blocks the policy
if [[ -x /usr/local/sbin/agy-version-sync ]]; then
  /usr/local/sbin/agy-version-sync || logger -p auth.warning -t agy-mdm "AGY_VERSION_SYNC_ERROR: exit $?"
fi
