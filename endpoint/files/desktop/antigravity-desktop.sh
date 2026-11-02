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

# /usr/local/bin/antigravity-desktop - root-owned launcher for the Antigravity Desktop app (same policy as agy)
set -euo pipefail
GROUP="$(id -gn)"
case "$GROUP" in agy-dev|agy-contractor) ;; *) echo "not licensed (policy)" >&2; exit 126 ;; esac
[[ -s /etc/antigravity/admin_settings.json ]] || { echo "managed gateway configuration missing" >&2; exit 126; }
for v in $(env | grep -oE '^(AGY_LLM_GATEWAY_[A-Z_]*|CLOUD_CODE_URL|GOOGLE_VERTEX_BASE_URL|GOOGLE_GEMINI_BASE_URL|BAICODE_[A-Z_]*|AICODE_ENDPOINT_URL|GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_GENAI_[A-Z_]*|ELECTRON_[A-Z_]*)=' | tr -d '='); do unset "$v"; done
export AGY_CLI_DISABLE_AUTO_UPDATE=1
logger -t agy-launch "user=$(id -un) group=$GROUP app=desktop mode=enterprise-gateway"
exec /opt/antigravity/hub/antigravity "$@"
