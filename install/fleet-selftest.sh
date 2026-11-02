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

# fleet-selftest.sh - prove the certificate-only (laptop) device path end to end, from the reference workstation.
#
#   install/fleet-selftest.sh <vm> <zone> <region> <fleet-pool> <fleet-spiffe-prefix> <gateway-url>
#
# The workstation plays a laptop WITHOUT using its Compute Engine identity:
#   * private keys are generated ON the workstation (root-only temp dir) and never leave it;
#   * the CSR is signed here by the installer identity from the FLEET pool, validity 1 hour
#     (the workstation SA has no rights on that pool, so a VM can never mint a laptop identity);
#   * curl calls the mTLS front door with no device token.
# Prints RESULT|STATUS|ID|check|detail lines (V15-V17); always removes the keys and certificates.
set -uo pipefail
VM="$1" ZONE="$2" REGION="$3" POOL="${4##*/}" PREFIX="$5" URL="$6"   # pool: short name (gcloud --issuer-pool)
ssh_vm() { gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet --command "$1" 2>/dev/null; }
res() { echo "RESULT|$1|$2|$3|${4:-}"; }
b64d() { python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))'; }
T=/root/.agy-fleet-selftest

# 1. keys + CSRs on the device
csrs="$(ssh_vm "sudo bash -c 'umask 077; rm -rf $T; mkdir -p $T; cd $T
  for d in agy-fleet-selftest agy-fleet-unregistered; do
    openssl ecparam -name prime256v1 -genkey -noout -out \$d.key
    openssl req -new -key \$d.key -subj /O=AGY-POC/CN=\$d -addext subjectAltName=URI:${PREFIX}\$d -out \$d.csr
    printf \"%s:%s\\n\" \$d \"\$(base64 -w0 \$d.csr)\"
  done'" | tr -d '\r')"
[[ "$(grep -c ':' <<<"$csrs")" -eq 2 ]] || { res FAIL V15 "Fleet device (certificate only) reaches the model" "could not create keys/CSRs on $VM"; exit 0; }

# 2. sign from the FLEET pool (1 hour), push the public certificates back
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; ssh_vm "sudo rm -rf $T" >/dev/null' EXIT
for d in agy-fleet-selftest agy-fleet-unregistered; do
  grep "^$d:" <<<"$csrs" | cut -d: -f2 | b64d > "$tmp/$d.csr"
  gcloud privateca certificates create --quiet --issuer-pool "$POOL" --issuer-location "$REGION" \
    --csr "$tmp/$d.csr" --validity PT1H --cert-output-file "$tmp/$d.crt" >/dev/null 2>"$tmp/err" \
    || { res FAIL V15 "Fleet device (certificate only) reaches the model" "issuance failed: $(tail -1 "$tmp/err")"; exit 0; }
  ssh_vm "sudo tee $T/$d.crt >/dev/null" < "$tmp/$d.crt" >/dev/null
done

# 3. call the front door as each "laptop" (no X-AGY-Device-Token) + the VM's own GCE cert without its token
out="$(ssh_vm "sudo bash -c 'cd $T
  call() { curl -s -m 60 -o \$1.out -w \"%{http_code}\" --cacert /etc/agy-credproxy/root.pem --cert \$2 --key \$3 \
    -H \"X-AGY-Device-Cert: \$(openssl x509 -in \$2 -outform DER | base64 -w0)\" -H \"X-AGY-User: root\" -H \"X-AGY-Group: agy-dev\" \
    -H \"Content-Type: application/json\" -H \"User-Agent: antigravity/fleet-selftest (aidev_client; auth_method=gateway)\" \
    -d \"{\\\"contents\\\":[{\\\"role\\\":\\\"user\\\",\\\"parts\\\":[{\\\"text\\\":\\\"Reply with the single word PONG\\\"}]}]}\" \
    ${URL}/v1beta/models/agy-auto:generateContent; }
  echo \"ok=\$(call ok agy-fleet-selftest.crt agy-fleet-selftest.key) \$(grep -io pong ok.out | head -1)\"
  echo \"unreg=\$(call unreg agy-fleet-unregistered.crt agy-fleet-unregistered.key) \$(grep -o fleet_device_unregistered unreg.out | head -1)\"
  echo \"vm=\$(call vm /etc/agy-credproxy/device.crt /etc/agy-credproxy/device.key) \$(grep -o fleet_cert_required vm.out | head -1)\"'" | tr -d '\r')"
ok="$(sed -n 's/^ok=//p' <<<"$out")"; unreg="$(sed -n 's/^unreg=//p' <<<"$out")"; vm="$(sed -n 's/^vm=//p' <<<"$out")"
[[ "$ok" == 200* ]] && grep -qi pong <<<"$ok" \
  && res PASS V15 "Fleet device (certificate only) reaches the model" "registered agy-fleet-selftest, 1-hour cert, no device token -> http 200" \
  || res FAIL V15 "Fleet device (certificate only) reaches the model" "http ${ok:-none}"
[[ "$unreg" == "401 fleet_device_unregistered" ]] \
  && res PASS V16 "Attack: valid fleet certificate for an unregistered device rejected" "http 401 fleet_device_unregistered" \
  || res FAIL V16 "Attack: valid fleet certificate for an unregistered device rejected" "got: ${unreg:-none}"
[[ "$vm" == "401 fleet_cert_required" ]] \
  && res PASS V17 "Attack: workstation certificate without its identity token rejected" "http 401 fleet_cert_required" \
  || res FAIL V17 "Attack: workstation certificate without its identity token rejected" "got: ${vm:-none}"
