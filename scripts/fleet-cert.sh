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

# fleet-cert.sh - issue a certificate-only device certificate from the FLEET CA pool (operator / MDM side).
#
#   scripts/fleet-cert.sh <device-id> --csr device.csr [--out DIR] [--days N]   # production: key made on the device
#   scripts/fleet-cert.sh <device-id> --test-key [--out DIR] [--days N]          # lab only: key generated here
#
# Writes <out>/<device-id>.crt and gateway-ca.pem (server trust anchor); with --test-key also <device-id>.key (0600).
# The device id must also be listed in fleet_devices (terraform/custom.auto.tfvars) with its user and group,
# otherwise the gateway rejects it (fleet_device_unregistered). Remove it from fleet_devices to revoke.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib.sh"
DEV="${1:-}"; shift || true
CSR=""; OUT="$ROOT/fleet-certs"; DAYS=30; TESTKEY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --csr) CSR="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    --test-key) TESTKEY=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ "$DEV" =~ ^[a-z0-9][a-z0-9._-]{1,62}$ ]] || { echo "usage: $0 <device-id> (--csr FILE | --test-key) [--out DIR] [--days N]" >&2; exit 2; }
[[ -n "$CSR" || $TESTKEY -eq 1 ]] || { echo "give --csr (recommended) or --test-key" >&2; exit 2; }
[[ "$DAYS" =~ ^[0-9]+$ && "$DAYS" -ge 1 && "$DAYS" -le 30 ]] || { echo "--days must be 1-30 (pool maximum)" >&2; exit 2; }
FL="$(tfo fleet)"; [[ -n "$FL" && "$FL" != "null" ]] || { echo "certificate-only devices are not enabled (device_auth_modes)" >&2; exit 1; }
j() { python3 -c 'import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])' "$FL" "$1"; }
POOL="$(j ca_pool)"; PREFIX="$(j spiffe_prefix)"
install -d -m 700 "$OUT"
if [[ $TESTKEY -eq 1 ]]; then
  echo "WARNING: lab key generated on this machine. In production the key is created on the device (TPM / Secure Enclave) and only the CSR is sent." >&2
  ( umask 077; openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/$DEV.key" )
  CSR="$OUT/$DEV.csr"
  openssl req -new -key "$OUT/$DEV.key" -subj "/O=AGY/CN=$DEV" -addext "subjectAltName=URI:${PREFIX}${DEV}" -out "$CSR"
fi
gcloud privateca certificates create --quiet --issuer-pool "${POOL##*/}" --issuer-location "$REGION" \
  --csr "$CSR" --validity "P${DAYS}D" --cert-output-file "$OUT/$DEV.crt" >/dev/null
python3 -c 'import json,sys; print(json.loads(sys.argv[1])["server_ca_pem"], end="")' "$FL" > "$OUT/gateway-ca.pem"
[[ $TESTKEY -eq 1 ]] && rm -f "$OUT/$DEV.csr"
echo "issued $OUT/$DEV.crt (SAN ${PREFIX}${DEV}, ${DAYS} days); server CA: $OUT/gateway-ca.pem"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if sys.argv[2] in d["devices"] else 1)' "$FL" "$DEV" \
  || echo "NOTE: $DEV is not in fleet_devices yet - add it (user + group) and run ./install.sh, or the gateway rejects it." >&2
