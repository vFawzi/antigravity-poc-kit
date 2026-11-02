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

# macos-e2e.sh - end-to-end test of poc/install-macos.sh on a disposable macOS machine (CI runner). TEST ONLY.
# Creates throwaway users and a test PKI, starts a mock mTLS gateway on 127.0.0.1:443, builds a kit, installs as
# root, then checks as the standard user: locks, tamper attempts, proxy persona check, launcher, hook (attack pack),
# drift repair, evidence, uninstall. Never run on a real user's Mac. Writes results to $OUT (default ./e2e-out).
set -uo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; OUT="${OUT:-$PWD/e2e-out}"; mkdir -p "$OUT"
W="$(mktemp -d)"; U=pocdev; PASS=0; FAILN=0
TPY="$(command -v python3.12 || command -v python3.11 || command -v python3)"   # tooling (kit, attack-pack runner)
res() { printf '%s|%s|%s\n' "$1" "$2" "$3" | tee -a "$OUT/e2e-results.txt"; [[ "$1" == PASS ]] && PASS=$((PASS+1)) || FAILN=$((FAILN+1)); }
asu() { sudo -u "$U" -H bash -c "cd /tmp && $1"; }   # run as the standard user
expect_denied() { if asu "$2" >/dev/null 2>&1; then res FAIL "$1" "allowed: $2"; else res PASS "$1" "denied"; fi; }

echo "== macOS $(sw_vers -productVersion) $(uname -m); python3: $(/usr/bin/python3 --version 2>&1)"
# 1. throwaway standard user (random password, never printed)
PW="$(openssl rand -base64 24)"
sudo sysadminctl -addUser "$U" -fullName "POC Dev" -password "$PW" >/dev/null 2>&1 || true
unset PW
sudo createhomedir -c -u "$U" >/dev/null 2>&1 || true
dseditgroup -o checkmember -m "$U" admin | grep -q '^yes' && { echo "test user must not be admin"; exit 1; }
# 2. test PKI: CA, gateway server cert, device cert with the fleet SPIFFE SAN
cd "$W"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=AGY test CA" -days 2 -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=gateway.agy.internal" -keyout srv.key -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:gateway.agy.internal\nextendedKeyUsage=serverAuth\n' > srv.ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile srv.ext -out srv.crt 2>/dev/null
mkdir -p certs
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/O=AGY/CN=mac-dev-01" -keyout certs/mac-dev-01.key -out dev.csr 2>/dev/null
printf 'subjectAltName=URI:spiffe://example.agy.internal/fleet/mac-dev-01\nextendedKeyUsage=clientAuth\n' > dev.ext
openssl x509 -req -in dev.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile dev.ext -out certs/mac-dev-01.crt 2>/dev/null
cp ca.pem certs/gateway-ca.pem
# 3. mock gateway (mTLS, test CA) on 127.0.0.1:443
sudo /usr/bin/python3 "$REPO/poc/ci/mock_gateway.py" --cert srv.crt --key srv.key --ca ca.pem --log "$OUT/mock-gateway.log" &
sleep 2
# 4. kit (gateway name pinned to 127.0.0.1 through the hosts entry)
printf 'device,owner,persona,os\nmac-dev-01,pocdev@example.com,dev,macos\n' > devices.csv
"$TPY" "$REPO/poc/poc_kit.py" kit devices.csv --certs certs --out kit --gateway-url https://gateway.agy.internal \
  --gateway-ip 127.0.0.1 --project example --region europe-west4 > /dev/null || { echo "kit build failed"; exit 1; }
cp "$REPO/poc/install-macos.sh" kit/mac-dev-01/
# 5. install
T0=$(date +%s)
sudo bash kit/mac-dev-01/install-macos.sh --install --user "$U" 2>&1 | tee "$OUT/install.log"
res "$([[ ${PIPESTATUS[0]} -eq 0 ]] && echo PASS || echo FAIL)" E01 "install exit code (took $(( $(date +%s) - T0 )) s)"
sudo cat "/Library/Application Support/AntigravityPOC/test.json" > "$OUT/test-after-install.json" 2>/dev/null
FAILS=$(/usr/bin/python3 -c 'import json,sys; print(",".join(r["id"] for r in json.load(open(sys.argv[1])) if r["status"]=="FAIL"))' "$OUT/test-after-install.json" 2>/dev/null)
[[ -z "$FAILS" ]] && res PASS E02 "self-test: no FAIL" || res FAIL E02 "self-test FAIL: $FAILS"
H="/Users/$U"
# 6. standard-user tamper attempts
expect_denied T01 "echo x >> '/Library/Application Support/Antigravity/admin_settings.json'"
expect_denied T02 "echo '{}' > $H/.gemini/antigravity-cli/settings.json"
expect_denied T03 "rm -f $H/.gemini/config/hooks.json"
expect_denied T04 "mv $H/.gemini $H/.gemini-x"
expect_denied T05 "mv $H/.gemini/config $H/.gemini/config-x"
expect_denied T06 "chflags noschg $H/.gemini/config/hooks.json"
expect_denied T07 "cat '/Library/Application Support/Antigravity/credproxy/device.key'"
expect_denied T08 "launchctl bootout system/com.google.agy.credproxy"
expect_denied T09 "echo x > /usr/local/libexec/agy-hook"
expect_denied T10 "echo '1.2.3.4 gateway.agy.internal' >> /etc/hosts"
expect_denied T11 "echo '{\"mcpServers\":{\"x\":{\"command\":\"nc\"}}}' > $H/.gemini/config/mcp_config.json"
# 7. proxy: persona allowed (through to the mock gateway), non-persona (the runner's admin user) refused
CODE=$(asu "curl -s -o /dev/null -w '%{http_code}' -m 20 http://127.0.0.1:8443/v1beta/models")
[[ "$CODE" == 200 ]] && res PASS P01 "persona through local proxy to the gateway (HTTP $CODE)" || res FAIL P01 "persona through proxy: HTTP $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 20 http://127.0.0.1:8443/v1beta/models)
[[ "$CODE" == 403 ]] && res PASS P02 "non-persona refused by the proxy (HTTP $CODE)" || res FAIL P02 "non-persona: HTTP $CODE (expected 403)"
grep -q '"client_cn": "mac-dev-01"' "$OUT/mock-gateway.log" 2>/dev/null && res PASS P03 "gateway saw the device certificate (mTLS)" || res FAIL P03 "device certificate not seen at the gateway"
# 8. launcher
OUTL=$(asu "/usr/local/bin/agy --version 2>&1"); res "$([[ $? -eq 0 ]] && echo PASS || echo FAIL)" L01 "persona runs the pinned CLI: ${OUTL:0:80}"
asu "/usr/local/bin/agy --dangerously-skip-permissions -p hi" >/dev/null 2>&1 && res FAIL L02 "review bypass allowed" || res PASS L02 "review-bypass flag refused"
/usr/local/bin/agy --version >/dev/null 2>&1 && res FAIL L03 "admin can run the agent" || res PASS L03 "agent refused for administrators"
# 9. hook: deterministic attack pack against the installed hook + policy (macOS system python)
"$TPY" "$REPO/poc/attack-pack/runner.py" run --mode deterministic --os macos --persona dev \
  --hook /usr/local/libexec/agy-hook --policy "/Library/Application Support/Antigravity/hooks/policy.json" --out "$OUT/ap-dev" > "$OUT/ap-dev.txt" 2>&1
"$TPY" "$REPO/poc/attack-pack/runner.py" run --mode deterministic --os macos --persona contractor \
  --hook /usr/local/libexec/agy-hook --policy "/Library/Application Support/Antigravity/hooks/policy.json" --out "$OUT/ap-contractor" > "$OUT/ap-contractor.txt" 2>&1
REP=$("$TPY" "$REPO/poc/attack-pack/runner.py" report --in "$OUT/ap-dev" "$OUT/ap-contractor" --out "$OUT/ap-report" 2>&1 | tail -1)
[[ "$REP" == *"critical blocked 100.0%"* && "$REP" == *"false blocks 0"* ]] && res PASS H01 "attack pack: $REP" || res FAIL H01 "attack pack: $REP"
# 9b. the installed hook under the macOS system Python (as the client runs it), as the persona
DEC=$(asu "printf '%s' '{\"toolCall\":{\"name\":\"read_file\",\"args\":{\"Path\":\"$H/.ssh/id_rsa\"}}}' | /usr/bin/python3 /usr/local/libexec/agy-hook PreToolUse 2>&1")
[[ "$DEC" == *deny* ]] && res PASS H02 "hook under /usr/bin/python3 denies ~/.ssh read as persona" || res FAIL H02 "hook decision: ${DEC:0:160}"
DEC=$(asu "printf '%s' '{\"toolCall\":{\"name\":\"run_command\",\"args\":{\"CommandLine\":\"ls\"}}}' | /usr/bin/python3 /usr/local/libexec/agy-hook PreToolUse 2>&1")
[[ "$DEC" != *deny* ]] && res PASS H03 "hook allows a normal command as persona" || res FAIL H03 "hook decision: ${DEC:0:160}"
# 10. drift repair re-locks a file
sudo chflags noschg "$H/.gemini/config/hooks.json"; sudo bash /usr/local/libexec/agy/install-macos.sh --repair >/dev/null 2>&1
[[ "$(stat -f %Sf "$H/.gemini/config/hooks.json")" == *schg* ]] && res PASS D01 "drift repair re-locked hooks.json" || res FAIL D01 "drift repair did not re-lock"
# 11. evidence + uninstall
sudo bash kit/mac-dev-01/install-macos.sh --collect > "$OUT/collect.log" 2>&1 && res PASS C01 "evidence archive" || res FAIL C01 "collect failed"
sudo bash kit/mac-dev-01/install-macos.sh --uninstall 2>&1 | tee "$OUT/uninstall.log"
grep -q "PASS  P00" "$OUT/uninstall.log" && res PASS U01 "uninstall leaves no AGY files, daemons or hosts entries" || res FAIL U01 "uninstall leftovers"
asu "echo ok > $H/.gemini/user-test.txt" && res PASS U02 "user owns ~/.gemini again" || res FAIL U02 "~/.gemini still locked"
sudo cp -R "/Library/Application Support/AntigravityPOC" "$OUT/state" 2>/dev/null; sudo chown -R "$(id -un)" "$OUT" 2>/dev/null
echo "== e2e: $PASS PASS, $FAILN FAIL"
[[ $FAILN -eq 0 ]]
