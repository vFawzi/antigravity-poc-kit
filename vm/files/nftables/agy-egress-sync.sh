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

# agy-egress-sync - resolve the per-group egress allowlist (FQDNs from instance metadata) into the nftables sets.
# Runs as root at boot (after nftables), on every policy apply and every minute; entries accumulate under a 1 h timeout, so rotating CDN / round-robin addresses are covered.
# Entries carry a 1 h timeout, so addresses that disappear from DNS age out automatically.
set -euo pipefail
MD="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
ALLOW="$(curl -fsS -H "Metadata-Flavor: Google" "$MD/agy-egress-allowlist" 2>/dev/null || echo '{}')"
nft list table inet agy_policy >/dev/null 2>&1 || { echo "agy_policy table missing - nothing to sync"; exit 0; }

declare -A SETS=([agy-dev]=allow_dev4 [agy-contractor]=allow_contractor4)
tx="$(mktemp)"; trap 'rm -f "$tx"' EXIT
total=0
for grp in "${!SETS[@]}"; do
  set="${SETS[$grp]}"
  mapfile -t fqdns < <(jq -r --arg g "$grp" '.[$g] // [] | .[]' <<<"$ALLOW" 2>/dev/null | grep -E '^[A-Za-z0-9.-]+$' || true)
  ips=()
  for h in "${fqdns[@]}"; do
    while read -r ip; do [[ "$ip" =~ ^[0-9.]+$ ]] && ips+=("$ip"); done < <(getent ahostsv4 "$h" | awk '{print $1}' | sort -u)
  done
  [[ ${#ips[@]} -eq 0 ]] && continue
  printf 'add element inet agy_policy %s { %s }\n' "$set" "$(printf '%s timeout 1h, ' "${ips[@]}" | sed 's/, $//')" >> "$tx"
  total=$((total + ${#ips[@]}))
done
[[ -s "$tx" ]] && nft -f "$tx"
logger -t agy-mdm "egress allowlist synced: ${total} addresses"
