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

# agy-device-enroll - issue / renew the device mTLS certificate (root; called by bootstrap and a daily timer)
#  * key generated on the device, never leaves it (root:agy-credproxy 0640)
#  * certificate requested from CAS via the device template only (IAM condition on the VM SA)
#  * renews when less than 10 days remain (template max lifetime 30 days)
set -euo pipefail
MD="http://metadata.google.internal/computeMetadata/v1/instance"
md() { curl -fsS -H "Metadata-Flavor: Google" "$MD/$1"; }
POOL="$(md attributes/agy-device-ca-pool 2>/dev/null || true)"
TEMPLATE="$(md attributes/agy-device-template 2>/dev/null || true)"
SPIFFE="$(md attributes/agy-spiffe-prefix 2>/dev/null || true)"
[[ -n "$POOL" && -n "$TEMPLATE" && -n "$SPIFFE" ]] || { echo "mTLS not configured - skipping enrolment"; exit 0; }
INSTANCE="$(md name)"; ZONE="$(md zone | awk -F/ '{print $NF}')"; REGION="${ZONE%-*}"
D=/etc/agy-credproxy
install -d -o root -g agy-credproxy -m 750 "$D"

md attributes/agy-device-root-pem > $D/root.pem.tmp 2>/dev/null && [[ -s $D/root.pem.tmp ]] && { mv $D/root.pem.tmp $D/root.pem; chown root:agy-credproxy $D/root.pem; chmod 0644 $D/root.pem; }
if [[ -s $D/device.crt ]] && openssl x509 -in $D/device.crt -noout -checkend $((10*86400)) >/dev/null 2>&1 \
   && openssl x509 -in $D/device.crt -noout -ext subjectAltName 2>/dev/null | grep -q "${SPIFFE}${INSTANCE}"; then
  echo "device certificate valid > 10 days - nothing to do"; exit 0
fi

umask 027
openssl ecparam -name prime256v1 -genkey -noout -out $D/device.key.new
openssl req -new -key $D/device.key.new -subj "/O=AGY POC/CN=${INSTANCE}" \
  -addext "subjectAltName=URI:${SPIFFE}${INSTANCE}" -out $D/device.csr
gcloud privateca certificates create --quiet --issuer-pool "$POOL" --issuer-location "$REGION" \
  --csr $D/device.csr --template "$TEMPLATE" --validity P30D --cert-output-file $D/device.crt.new >/dev/null
md attributes/agy-device-root-pem > $D/root.pem.new     # server trust anchor (gateway.agy.internal) delivered by MDM
mv $D/device.key.new $D/device.key; mv $D/device.crt.new $D/device.crt; mv $D/root.pem.new $D/root.pem
chown root:agy-credproxy $D/device.key $D/device.crt $D/root.pem; chmod 0640 $D/device.key; chmod 0644 $D/device.crt $D/root.pem
rm -f $D/device.csr
logger -t agy-mdm "device certificate enrolled san=${SPIFFE}${INSTANCE} notAfter=$(openssl x509 -in $D/device.crt -noout -enddate | cut -d= -f2) sha256=$(openssl x509 -in $D/device.crt -noout -fingerprint -sha256 | cut -d= -f2 | tr -d :)"
systemctl try-restart agy-credproxy.service || true
