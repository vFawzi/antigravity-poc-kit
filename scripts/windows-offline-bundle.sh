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

# Builds dist/agy-windows-offline.zip for a Windows device outside Google Cloud:
#   bundle/ (bootstrap.ps1 + files/), Install-AGYEndpoint.ps1, params.json
# params.json is taken from a reference Windows VM's instance metadata (the settings Terraform computed: egress
# allowlist, hosts pins, client mode, seat project, ...) minus the Google-Cloud-only keys, plus offline defaults.
# Usage: scripts/windows-offline-bundle.sh [REF_VM] [ZONE] [PROJECT]   (defaults: agy-win-ws europe-west4-a $PROJECT_ID)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM="${1:-agy-win-ws}"; ZONE="${2:-${ZONE:-europe-west4-a}}"; PROJECT="${3:-${PROJECT_ID:-}}"
[[ -n "$PROJECT" ]] || { echo "usage: $0 [REF_VM] [ZONE] PROJECT" >&2; exit 2; }
OUT="$ROOT/dist/agy-windows-offline"; rm -rf "$OUT"; mkdir -p "$OUT/bundle"

python3 "$ROOT/windows/gen-policies.py" --check >/dev/null
cp "$ROOT/windows/bootstrap.ps1" "$OUT/bundle/bootstrap.ps1"
rsync -a --exclude '__pycache__/' --exclude '*.pyc' "$ROOT/windows/files/" "$OUT/bundle/files/"
cp "$ROOT/windows/install/Install-AGYEndpoint.ps1" "$OUT/"

gcloud compute instances describe "$VM" --zone "$ZONE" --project "$PROJECT" --format=json |
python3 -c '
import json, sys
md = {i["key"]: i["value"] for i in json.load(sys.stdin).get("metadata", {}).get("items", [])}
skip = {"agy-config-bucket", "agy-desktop-secrets", "agy-desktop-secret-ver", "agy-bundle-hash"}   # Google-Cloud-only
p = {k: v for k, v in md.items() if k.startswith("agy-") and k not in skip}
for k in ("agy-egress-allowlist", "agy-agent-sa", "agy-package-proxy"):   # JSON strings -> objects (readable file)
    if k in p:
        try: p[k] = json.loads(p[k])
        except ValueError: pass
p.setdefault("agy-workspace-root", "C:\\projects")   # D: is a temporary disk on Azure
p.setdefault("agy-personas", "dev,contractor")
p.setdefault("agy-desktop-windows-object", "antigravity-hub/2.24.0-5780333019398144/windows-x64/Antigravity-x64.exe")
p.setdefault("agy-desktop-sha256", "b707cce37f3df44a1b731a4cc88d657114267bb7ca11da9d44ac0a5b791643a3")
p.setdefault("agy-ops-agent", "false")   # needs a Google Cloud credential off Google Cloud
json.dump(dict(sorted(p.items())), sys.stdout, indent=2)
' > "$OUT/params.json"

(cd "$ROOT/dist" && rm -f agy-windows-offline.zip && zip -qr agy-windows-offline.zip agy-windows-offline)
echo "built $ROOT/dist/agy-windows-offline.zip ($(du -h "$ROOT/dist/agy-windows-offline.zip" | cut -f1)); settings from $VM:"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("  " + ", ".join(sorted(d)))' "$OUT/params.json"
