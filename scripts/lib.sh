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

# Shared helpers for AGY POC scripts.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/terraform"
GW_DIR="$ROOT/gateway"
[[ -x "$ROOT/.tools/bin/terraform" ]] && export PATH="$ROOT/.tools/bin:$PATH"   # pinned copy installed by install.sh

PROJECT_ID="$(awk -F'"' '/^project_id/{print $2}' "$TF_DIR/terraform.tfvars")"
REGION="$(awk -F'"' '/^region/{print $2}' "$TF_DIR/terraform.tfvars")"; REGION="${REGION:-europe-west4}"
ZONE="$(awk -F'"' '/^zone/{print $2}' "$TF_DIR/terraform.tfvars")"; ZONE="${ZONE:-europe-west4-a}"
export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"   # never touch the user's global gcloud config
# macOS python.org builds ship without a CA bundle (Linux / Cloud Shell unaffected)
[[ "$(uname)" == "Darwin" && -z "${SSL_CERT_FILE:-}" && -f /etc/ssl/cert.pem ]] && export SSL_CERT_FILE=/etc/ssl/cert.pem

log()  { printf '\033[1;34m[agy]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[agy] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
tf()   { terraform -chdir="$TF_DIR" "$@"; }
tfo()  {   # empty string when the output does not exist yet (terraform prints warnings to stdout)
  local out
  out="$(tf output -json "$1" 2>/dev/null)" || { echo ""; return 0; }
  python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(v if isinstance(v,str) else json.dumps(v))' "$out" 2>/dev/null || echo ""
}

gateway_image_tag() {   # content hash of the gateway source => immutable tag
  (cd "$GW_DIR" && cat main.py evidence.py dataprotect.py classifier.py seat_inspector.py requirements.txt Dockerfile | shasum -a 256 | cut -c1-16)
}

preflight() {
  command -v terraform >/dev/null || die "terraform not found"
  command -v gcloud >/dev/null || die "gcloud not found"
  gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud not authenticated (gcloud auth login)"
  gcloud auth application-default print-access-token >/dev/null 2>&1 || die "ADC missing (gcloud auth application-default login)"
  gcloud projects describe "$PROJECT_ID" --format='value(projectId)' >/dev/null || die "project $PROJECT_ID not accessible"
  log "project=$PROJECT_ID region=$REGION zone=$ZONE account=$(gcloud config get-value account 2>/dev/null)"
}

current_image() {      # image currently deployed, only if it is a valid Artifact Registry path
  local img; img="$(tfo gateway_image_in_use)"
  [[ "$img" =~ ^[a-z0-9-]+-docker\.pkg\.dev/[^[:space:]]+:[A-Za-z0-9._-]+$ ]] && echo "$img" || echo ""
}
