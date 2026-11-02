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

# agy-enroll start|end <user>  -  MDM enrollment window for Antigravity first-run (ToS, project)
#  start: unlock the user's settings.json + load the profile without the settings tamper rules
#  end:   merge NON-policy keys written during onboarding into the group policy, re-lock, enforce
set -euo pipefail
ACTION="${1:?start|end}"; USER_NAME="${2:?user}"
GRP="$(id -gn "$USER_NAME")"; POLICY="/etc/antigravity/policies/${GRP}.settings.json"
HOME_DIR="$(getent passwd "$USER_NAME" | cut -d: -f6)"; TARGET="$HOME_DIR/.gemini/antigravity-cli/settings.json"
FLAG="/etc/antigravity/enrollment/$USER_NAME"
[[ -f "$POLICY" ]] || { echo "no policy for group $GRP"; exit 1; }
reload_profile() {   # same logic as bootstrap step 7, without re-installing policy files
  local mode
  mode="$(curl -fsS -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/attributes/agy-apparmor-mode 2>/dev/null || echo enforce)"
  install -o root -g root -m 644 /opt/agy-poc/apparmor/antigravity-agent /etc/apparmor.d/antigravity-agent
  if compgen -G "/etc/antigravity/enrollment/*" >/dev/null; then
    sed -i '/# agy-tamper/d' /etc/apparmor.d/antigravity-agent; mode=complain
  fi
  apparmor_parser -r -W /etc/apparmor.d/antigravity-agent
  if [[ "$mode" == complain ]]; then aa-complain /etc/apparmor.d/antigravity-agent; else aa-enforce /etc/apparmor.d/antigravity-agent; fi
}

case "$ACTION" in
  start)
    install -d -m 755 /etc/antigravity/enrollment; date -Is > "$FLAG"
    systemctl stop agy-policy.timer
    /usr/local/sbin/agy-policy-apply.sh
    reload_profile
    logger -t agy-mdm "ENROLLMENT START user=$USER_NAME group=$GRP"
    echo "enrollment open for $USER_NAME - complete Antigravity first-run, exit agy, then: agy-enroll end $USER_NAME" ;;
  end)
    [[ -f "$FLAG" ]] || { echo "user not in enrollment"; exit 1; }
    python3 - "$POLICY" "$TARGET" <<'EOF'
import json, sys
policy_path, user_path = sys.argv[1], sys.argv[2]
POLICY_KEYS = {"permissions", "toolPermission", "enableTerminalSandbox", "trustedWorkspaces", "telemetryEnabled",
               "allowNonWorkspaceAccess", "artifactReviewPolicy", "showFeedbackSurvey"}
policy = json.load(open(policy_path)); user = json.load(open(user_path))
added = {k: v for k, v in user.items() if k not in POLICY_KEYS and policy.get(k) != v}
policy.update(added)
json.dump(policy, open(policy_path, "w"), indent=2); open(policy_path, "a").write("\n")
print("merged onboarding keys:", sorted(added))
EOF
    rm -f "$FLAG"
    /usr/local/sbin/agy-policy-apply.sh
    systemctl start agy-policy.timer
    reload_profile
    logger -t agy-mdm "ENROLLMENT END user=$USER_NAME policy_sha256=$(sha256sum "$POLICY" | cut -c1-16)"
    aa-status | grep -A1 'enforce mode' | head -2
    echo "--- merged policy (copy back to repo endpoint/files/policies/${GRP}.settings.json):"; cat "$POLICY" ;;
  *) echo "usage: agy-enroll start|end <user>"; exit 2 ;;
esac
