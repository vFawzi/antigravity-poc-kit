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

# agy-evidence - collect OS-level evidence (run as admin: sudo agy-evidence)
set -uo pipefail
OUT="/var/tmp/agy-evidence-$(date +%Y%m%d-%H%M%S).txt"
{
  echo "=== host: $(hostname)  $(date -Is)"
  echo "=== antigravity cli: $(cat /opt/antigravity/cli/.version 2>/dev/null) sha512=$(cut -c1-24 /opt/antigravity/cli/.sha512 2>/dev/null)"
  echo; echo "=== AppArmor status";            aa-status 2>/dev/null | grep -E 'profiles are|antigravity' -A0
  echo; echo "=== AppArmor DENIED by antigravity-agent (auditd), grouped"
  grep 'apparmor="DENIED"' /var/log/audit/audit.log | grep 'profile="antigravity-agent"' \
    | grep -oE 'operation="[a-z_]+"|name="[^"]+"|comm="[^"]+"' | paste -d' ' - - - | sort | uniq -c | sort -rn | head -60
  echo; echo "=== nftables counters";          nft list table inet agy_policy
  echo; echo "=== nftables drops (last 100)";  journalctl -k --no-pager -o short-iso | grep -E 'AGY-[A-Z-]+BLOCK' | tail -100
  echo; echo "=== MDM policy mounts";          findmnt -rn -o TARGET,SOURCE,OPTIONS | grep antigravity-cli
  echo; echo "=== MDM events";                 journalctl -t agy-mdm --no-pager -o short-iso | tail -50
  echo; echo "=== agy launches";               journalctl -t agy-launch --no-pager -o short-iso | tail -50
  echo; echo "=== corp-tools.log (must be empty)"; cat /var/log/corp-tools.log
  echo; echo "=== hosts pins";                 grep 'agy-pin' /etc/hosts
} > "$OUT" 2>&1
echo "evidence written to $OUT"
