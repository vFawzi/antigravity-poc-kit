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

# fleet-probe.sh - run ON a certificate-only device (laptop, CI runner) with private connectivity to the gateway.
#
#   scripts/fleet-probe.sh <gateway-url> <device.crt> <device.key> <gateway-ca.pem> [model]
#
# Sends one unbuffered streaming request exactly as the local credential proxy would (no Compute Engine token)
# and reports the HTTP status, the time to the first streamed byte and the answer. Expected: HTTP 200, PONG.
set -euo pipefail
URL="${1:?gateway url, e.g. https://gateway.agy.internal}"; CRT="${2:?device certificate}"; KEY="${3:?device key}"
CA="${4:?gateway CA bundle}"; MODEL="${5:-agy-auto}"
DER_B64="$(openssl x509 -in "$CRT" -outform DER | base64 | tr -d '\n')"
out="$(mktemp)"; trap 'rm -f "$out"' EXIT
stats="$(curl -sS -N -m 120 -o "$out" -w '%{http_code} %{time_starttransfer} %{time_total}' \
  --cacert "$CA" --cert "$CRT" --key "$KEY" \
  -H "X-AGY-Device-Cert: $DER_B64" -H "X-AGY-User: $(id -un)" -H "Content-Type: application/json" \
  -H "User-Agent: antigravity/fleet-probe (aidev_client; auth_method=gateway)" \
  -d '{"contents":[{"role":"user","parts":[{"text":"Reply with the single word PONG"}]}]}' \
  "${URL%/}/v1beta/models/${MODEL}:streamGenerateContent?alt=sse")"
read -r code ttfb total <<<"$stats"
answer="$( { grep -o '"text": *"[^"]*"' "$out" || true; } | sed 's/.*: *"//; s/"$//' | tr -d '\n' | head -c 200)"
echo "http=$code  time_to_first_byte=${ttfb}s  total=${total}s  answer=${answer:-$(head -c 300 "$out" | tr -d '\n')}"
[[ "$code" == "200" ]] && grep -qi pong <<<"$answer"
