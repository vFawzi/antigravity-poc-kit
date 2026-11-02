#!/usr/bin/env bash
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
#
# AGY version management (Linux, root; run by agy-policy-apply.sh every 5 min). Brings the Antigravity CLI to the version
# the deployment policy selects from the support matrix /etc/antigravity/agy-versions.json:
#   /etc/antigravity/version-policy  latest-tested (default) | pinned:<x.y.z> | latest (manifest; not blocked / >= minimum)
#   /etc/antigravity/artifact-base   optional customer mirror (same object paths as storage.googleapis.com/antigravity-public/)
# Verified by sha512 before use; swapped only while no CLI process runs (next logon in practice); previous version kept
# (antigravity.prev) and restored if the new one doesn't report the expected version. Writes versions-state.json.
set -euo pipefail
M=/etc/antigravity/agy-versions.json; CLI=/opt/antigravity/cli; STATE=/etc/antigravity/versions-state.json
PEND=/var/lib/agy/versions-pending; PUBLIC=https://storage.googleapis.com/antigravity-public/
PLAT=linux_amd64
[[ -f $M ]] || exit 0
policy=$(cat /etc/antigravity/version-policy 2>/dev/null || echo latest-tested)
mirror=$(cat /etc/antigravity/artifact-base 2>/dev/null || true)
mkdir -p /var/lib/agy; touch "$PEND"

audit() { logger -p "auth.${2:-info}" -t agy-mdm "$1"; }
once() {  # one audit event per (key, value), not one every 5 minutes
  grep -qxF "$1=$2" "$PEND" && return 0
  sed -i "/^$1=/d" "$PEND"; echo "$1=$2" >> "$PEND"; audit "$3" "${4:-info}"
}
vge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }   # $1 >= $2

allowed() {  # version may run: >= minimum and not blocked
  local v=$1 min
  [[ $v =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  min=$(jq -r --arg p "$PLAT" '.minimum.cli[$p] // empty' "$M")
  [[ -z $min ]] || vge "$v" "$min" || return 1
  [[ $(jq -r --arg p "$PLAT" --arg v "$v" '[.releases[]|select(.component=="cli" and .platform==$p and .version==$v and .status=="blocked")]|length' "$M") == 0 ]]
}

target_json() {
  if [[ $policy == pinned:* ]]; then
    local want=${policy#pinned:}
    allowed "$want" || return 0
    jq -c --arg p "$PLAT" --arg v "$want" '[.releases[]|select(.component=="cli" and .platform==$p and .version==$v and .url!="")][0] // empty' "$M"
    return 0
  fi
  if [[ $policy == latest ]]; then
    local man; man=$(curl -fsS --max-time 20 "$(cat /etc/antigravity/cli-manifest-url 2>/dev/null)" || true)
    if [[ -n $man ]] && allowed "$(jq -r .version <<<"$man")"; then
      jq -c '{version, url, sha512, status: "untested"}' <<<"$man"; return 0
    fi
  fi
  # latest-tested (and the fallback for 'latest' when the manifest version is not allowed)
  jq -c --arg p "$PLAT" '[.releases[]|select(.component=="cli" and .platform==$p and .status=="supported" and .url!="")]
         | sort_by(.version | split(".") | map(tonumber)) | last // empty' "$M"
}

cur=$(cat "$CLI/.version" 2>/dev/null || true)
t=$(target_json || true)
tver=""; tstat=""; err=""
if [[ -n $t ]]; then
  tver=$(jq -r .version <<<"$t"); tstat=$(jq -r .status <<<"$t")
  if [[ $cur != "$tver" ]]; then
    url=$(jq -r .url <<<"$t"); sha=$(jq -r .sha512 <<<"$t")
    if [[ $url != "$PUBLIC"* || ! $sha =~ ^[a-f0-9]{128}$ ]]; then
      err="target $tver: url outside $PUBLIC or bad sha512"
    elif pgrep -x antigravity >/dev/null; then   # exact process name (a command line merely mentioning the path must not block)
      once cli "$tver" "AGY_CLI_UPGRADE_PENDING: $tver, applied when the CLI is not running (next logon)"
    else
      src=$url; [[ -n $mirror ]] && src="${mirror%/}/${url#"$PUBLIC"}"
      tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
      if curl -fsSL --retry 3 -o "$tmp/cli.tgz" "$src" && echo "$sha  $tmp/cli.tgz" | sha512sum -c --quiet - && tar -xzf "$tmp/cli.tgz" -C "$tmp"; then
        [[ -f $CLI/antigravity ]] && cp -p "$CLI/antigravity" "$CLI/antigravity.prev"
        install -o root -g root -m 755 "$tmp/antigravity" "$CLI/antigravity.new" && mv -f "$CLI/antigravity.new" "$CLI/antigravity"
        now=$("$CLI/antigravity" --version 2>/dev/null | head -1 | tr -d '[:space:]' || true)
        if [[ $now == "$tver" ]]; then
          echo "$sha" > "$CLI/.sha512"; echo "$tver" > "$CLI/.version"; sed -i '/^cli=/d' "$PEND"
          audit "AGY_CLI_UPGRADED: ${cur:-none} -> $tver (policy $policy, $tstat)"; cur=$tver; managed=1
        else
          [[ -f $CLI/antigravity.prev ]] && mv -f "$CLI/antigravity.prev" "$CLI/antigravity"
          err="new CLI reports '$now', expected $tver - rolled back to ${cur:-none}"
        fi
      else
        err="download / sha512 / unpack failed for $tver"
      fi
    fi
  fi
elif [[ -n $cur ]]; then
  once cli_no_target "$policy" "AGY_CLI_NO_TARGET: policy $policy selects no deployable CLI release for $PLAT - keeping $cur" warning
fi
[[ -n $err ]] && audit "AGY_CLI_UPGRADE_FAILED: $err" warning
# unmanaged change: the binary changed (size / mtime) without an upgrade by this script -> SIEM (D21)
key=$(stat -c '%s|%Y' "$CLI/antigravity" 2>/dev/null || true)
prev_key=$(jq -r '.cli_key // empty' "$STATE" 2>/dev/null || true)
prev_sig=$(jq -r '"cli=\(.cli) cli_target=\(.cli_target) policy=\(.policy)"' "$STATE" 2>/dev/null || true)
if [[ -n $prev_key && -n $key && $prev_key != "$key" && ${managed:-0} != 1 ]]; then
  audit "AGY_CLI_UNMANAGED_CHANGE: binary changed outside version management (now $cur)" warning
fi
# one event per change of the version picture + a daily heartbeat -> fleet view v_agy_versions
sig="cli=$cur cli_target=$tver policy=$policy"
reported=$(jq -r '.reported_at // 0' "$STATE" 2>/dev/null || echo 0); now=$(date +%s)
if [[ $sig != "$prev_sig" || $((now - reported)) -ge 86400 ]]; then
  audit "AGY_VERSIONS: $sig package=$(jq -r .package "$M")"; reported=$now
fi
jq -nc --arg policy "$policy" --arg cli "$cur" --arg t "$tver" --arg ts "$tstat" --arg err "$err" --arg key "$key" --argjson rep "$reported" --argjson mirror "$([[ -n $mirror ]] && echo true || echo false)" \
  '{policy:$policy, mirror:$mirror, cli:$cli, cli_target:$t, cli_target_status:$ts, cli_key:$key, reported_at:$rep, errors:(if $err=="" then [] else [$err] end)}' > "$STATE.new"
mv -f "$STATE.new" "$STATE"; chmod 644 "$STATE"
exit 0
