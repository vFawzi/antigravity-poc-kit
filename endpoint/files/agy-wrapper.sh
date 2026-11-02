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

# /usr/local/bin/agy - root-owned launcher (simulated MDM enforcement point)
#  * Enterprise Gateway mode is enforced by /etc/antigravity/admin_settings.json (admin tier wins over env
#    and user settings). This launcher only removes user-supplied overrides and disables
#    self-update; the binary is root-owned and integrity-checked at boot.
set -euo pipefail
REAL=/opt/antigravity/cli/antigravity
GROUP="$(id -gn)"

case "$GROUP" in
  agy-dev|agy-contractor) ;;
  *) echo "agy: user group '$GROUP' is not licensed for Antigravity (policy)" >&2
     logger -t agy-launch "BLOCKED user=$(id -un) group=$GROUP reason=unmanaged_group"; exit 126 ;;
esac
MODE="$(cat /etc/antigravity/client_mode 2>/dev/null || echo gateway)"
if [[ ! -s /etc/antigravity/admin_settings.json ]]; then
  echo "agy: managed configuration missing - contact IT (policy)" >&2
  logger -t agy-launch "BLOCKED user=$(id -un) reason=admin_settings_missing"; exit 126
fi

# strip any user-provided endpoint/credential overrides (defence in depth; admin tier already wins)
# seat mode also strips the ADC / project overrides so the pinned licence project and location can't be bypassed
for v in $(env | grep -oE '^(AGY_LLM_GATEWAY_[A-Z_]*|CLOUD_CODE_URL|GOOGLE_VERTEX_BASE_URL|GOOGLE_GEMINI_BASE_URL|BAICODE_[A-Z_]*|AICODE_ENDPOINT_URL|GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_GENAI_[A-Z_]*|AGY_ADC_AUTH|GOOGLE_CLOUD_QUOTA_PROJECT|GOOGLE_CLOUD_LOCATION|GOOGLE_CLOUD_PROJECT|GOOGLE_APPLICATION_CREDENTIALS)=' | tr -d '='); do
  unset "$v"
done
export AGY_CLI_DISABLE_AUTO_UPDATE=1
# standard users only: never root, never a root-equivalent group (the hook denies the same: deny_elevated_session)
if [[ "$(id -u)" -eq 0 ]]; then
  echo "agy: not permitted as root - use your standard account (policy)" >&2
  logger -t agy-launch "BLOCKED user=$(id -un) reason=elevated_session uid=0"; exit 126
fi
for g in $(id -Gn); do
  case "$g" in sudo|wheel|admin|docker|libvirt|lxd)
    echo "agy: not permitted for members of the root-equivalent group '$g' (policy)" >&2
    logger -t agy-launch "BLOCKED user=$(id -un) reason=elevated_session group=$g"; exit 126 ;;
  esac
done
# human review is mandatory: no review-bypass options (the hook enforces the same for any launch path; this only
# gives a clear message early)
prev=""
for a in "$@"; do
  m="${a,,}"
  if [[ "$m" == --dangerously-skip-permissions* || "$m" == --mode=auto || "$m" == --mode=accept-edits ||
        ( "$prev" == --mode && ( "$m" == auto || "$m" == accept-edits ) ) ]]; then
    echo "agy: '$a' skips human review and is not permitted (policy)" >&2
    logger -t agy-launch "BLOCKED user=$(id -un) reason=review_bypass arg=$a"; exit 126
  fi
  prev="$m"
done
if [[ "$MODE" == "seat" ]]; then
  # --project would override the pinned licence project
  for a in "$@"; do [[ "$a" == --project* ]] && { echo "agy: --project is managed by IT in seat mode (policy)" >&2; logger -t agy-launch "BLOCKED user=$(id -un) reason=project_override"; exit 126; }; done
fi
logger -t agy-launch "user=$(id -un) group=$GROUP cwd=$PWD mode=$([[ "$MODE" == seat ]] && echo seat || echo enterprise-gateway)"
exec "$REAL" "$@"
