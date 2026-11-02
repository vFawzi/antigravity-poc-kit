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

# install-macos.sh - Antigravity pay-as-you-go POC: macOS endpoint script (run once by IT with sudo, from the kit).
#
#   sudo ./install-macos.sh --install [--user <short name>] [--offline] [--yes]   install + self-test
#                                        (no --user: the signed-in console user is proposed as device owner)
#   sudo ./install-macos.sh --test                                       PASS / FAIL per control
#   sudo ./install-macos.sh --collect                                    evidence archive
#   sudo ./install-macos.sh --uninstall                                  remove everything, then --test
#   (--repair is run by the policy LaunchDaemon every 5 minutes: re-applies the locked files and flags)
#
# Installs: pinned Antigravity CLI (sha512 from the official manifest), locked admin settings (gateway -> local
# credential proxy), corporate hook (stricter for contractors; noisy rules in audit during week 1), per-user locked
# settings / hooks / MCP config / browser allowlist (root-owned, system-immutable, immutable ~/.gemini so the folder
# can't be renamed away), credential proxy LaunchDaemon with the device certificate (key readable by root only),
# hosts entry for the gateway, drift-repair LaunchDaemon, self-test. Needs a working /usr/bin/python3 (Command Line
# Tools). Never touches other users' data; uninstall leaves the user's own files in ~/.gemini.
set -euo pipefail
R="${AGY_ROOT:-}"                      # test harness only: fake filesystem root (empty on a real Mac)
MODE="install"; OWNER=""; OFFLINE=0; YES=0
KIT="$(cd "$(dirname "$0")" && pwd)"
SUP="$R/Library/Application Support/Antigravity"
STATE="$R/Library/Application Support/AntigravityPOC"
LIBEXEC="$R/usr/local/libexec/agy"
HOOKBIN="$R/usr/local/libexec/agy-hook"
SHIM="$R/usr/local/bin/agy"
LD="$R/Library/LaunchDaemons"
PROXY_LABEL="com.google.agy.credproxy"; POLICY_LABEL="com.google.agy.policy"
HOSTS="$R/etc/hosts"; GW_MARK="# agy-poc-gw"; PIN_MARK="# agy-pin"
LOGDIR="$R/Library/Logs/Antigravity"
PY="${AGY_PYTHON:-/usr/bin/python3}"
GROUPS_=("agy-dev" "agy-contractor")

say()  { printf '[poc] %s\n' "$*"; }
fail() { printf '[poc] ERROR: %s\n' "$*" >&2; exit 1; }
usage() { sed -n '16,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install|-Install) MODE="install"; shift ;;
    --test|-Test) MODE="test"; shift ;;
    --collect|-Collect) MODE="collect"; shift ;;
    --uninstall|-Uninstall) MODE="uninstall"; shift ;;
    --repair) MODE="repair"; shift ;;
    --user|-User) OWNER="${2:-}"; shift 2 ;;
    --offline|-Offline) OFFLINE=1; shift ;;
    --yes|-y) YES=1; shift ;;
    --kit) KIT="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) fail "unknown option: $1 (see --help)" ;;
  esac
done

need_root() { [[ -n "$R" || "$(id -u)" -eq 0 ]] || fail "run with sudo (root)"; }
jget() {   # jget <json file> <python expression on d>
  "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); v=eval(sys.argv[2]); print("" if v is None else (json.dumps(v) if isinstance(v,(dict,list)) else v))' "$1" "$2"
}
lock()   { chflags schg "$@" 2>/dev/null || true; }
unlock() { chflags noschg,nouchg "$@" 2>/dev/null || true; }
user_home() { dscl . -read "/Users/$1" NFSHomeDirectory 2>/dev/null | awk '{print $2}' | sed "s#^#$R#"; }
is_admin() { dseditgroup -o checkmember -m "$1" admin 2>/dev/null | grep -q "^yes"; }
in_group() { dseditgroup -o checkmember -m "$1" "$2" 2>/dev/null | grep -q "^yes"; }
write_root_file() {   # write_root_file <path> <mode> <content-file>: root:wheel, then system-immutable
  local dst="$1" mode="$2" src="$3"
  mkdir -p "$(dirname "$dst")"
  [[ -e "$dst" ]] && unlock "$dst"
  cp "$src" "$dst"; chown root:wheel "$dst"; chmod "$mode" "$dst"; lock "$dst"
}
set_hosts() {   # set_hosts <ip> <name> <comma-separated pins>; empty args remove the entries
  local tmp; tmp="$(mktemp)"
  grep -v -e "$GW_MARK\$" -e "$PIN_MARK\$" "$HOSTS" > "$tmp" 2>/dev/null || true
  [[ -n "$1" ]] && printf '%s %s %s\n' "$1" "$2" "$GW_MARK" >> "$tmp"
  local h; for h in ${3//,/ }; do [[ "$h" =~ ^[A-Za-z0-9.-]+$ ]] && printf '0.0.0.0 %s %s\n' "$h" "$PIN_MARK" >> "$tmp"; done
  cat "$tmp" > "$HOSTS"; rm -f "$tmp"
  dscacheutil -flushcache 2>/dev/null || true; killall -HUP mDNSResponder 2>/dev/null || true
}

# ----------------------------------------------------------------------------- managed files (install + repair)
apply_machine() {   # admin settings, hook + policy, credproxy files (all root-owned)
  local cfg="$STATE/poc.json" b="$STATE/bundle" tmp; tmp="$(mktemp -d)"
  mkdir -p "$SUP" "$LIBEXEC" "$LOGDIR"; chown root:wheel "$SUP" "$LIBEXEC"; chmod 755 "$SUP" "$LIBEXEC"
  sed "s/@COST_CENTER@/poc-$(jget "$cfg" 'd["persona"]')/" "$b/policies/admin_settings.json" > "$tmp/admin.json"
  write_root_file "$SUP/admin_settings.json" 644 "$tmp/admin.json"
  # hook policy: the week-1 audit classes merged into the default section (the hook refuses critical classes)
  "$PY" - "$b/hooks/policy.json" "$tmp/policy.json" "$(jget "$cfg" '",".join(d["hook"].get("audit_classes", [])) if d["hook"].get("noisy") == "audit" else ""')" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
cls = [c for c in sys.argv[3].split(",") if c]
if cls:
    p.setdefault("default", {})["audit_classes"] = cls
json.dump(p, open(sys.argv[2], "w"), indent=2)
PY
  mkdir -p "$SUP/hooks"; chown root:wheel "$SUP/hooks"; chmod 755 "$SUP/hooks"
  write_root_file "$SUP/hooks/policy.json" 644 "$tmp/policy.json"
  write_root_file "$HOOKBIN" 755 "$b/hooks/agy-hook.py"
  write_root_file "$LIBEXEC/agy-credproxy.py" 755 "$b/credproxy/agy-credproxy.py"
  printf '%s\n' "$(jget "$cfg" 'd["gateway"]["url"]')" > "$tmp/gw"; write_root_file "$SUP/gateway_url" 644 "$tmp/gw"
  rm -rf "$tmp"
}

apply_user() {   # per-user locked files for the device owner
  local u="$1" persona grp home b="$STATE/bundle" ws tmp
  persona="$(jget "$STATE/poc.json" 'd["persona"]')"; grp="agy-$persona"
  home="$(user_home "$u")"; [[ -n "$home" && -d "$home" ]] || fail "home folder of $u not found"
  ws="${home#$R}/projects"
  tmp="$(mktemp -d)"
  # settings: the templates name the Linux persona paths - rewrite them to this user's own home and workspace
  sed -e "s#/data/projects/$persona#${ws}#g" -e "s#/home/$persona#${home#$R}#g" "$b/policies/$grp.settings.json" > "$tmp/settings.json"
  local hosts_extra; hosts_extra="$(jget "$STATE/poc.json" 'd.get("browser_allowlist", "")')"
  { echo "# managed by AGY - one host per line"; echo "localhost"; echo "127.0.0.1"; for h in ${hosts_extra//,/ }; do echo "$h"; done; } > "$tmp/browser.txt"
  # the folders the client writes to exist before ~/.gemini is made immutable (no new entries can be added there)
  [[ -d "$home/.gemini" ]] && unlock "$home/.gemini"
  mkdir -p "$home/.gemini/antigravity-cli/cache" "$home/.gemini/antigravity-cli/log" "$home/.gemini/config" \
           "$home/.gemini/antigravity" "$home/.gemini/tmp" "$home/projects"
  chown "$u" "$home/projects" "$home/.gemini/antigravity-cli/cache" "$home/.gemini/antigravity-cli/log" "$home/.gemini/tmp" 2>/dev/null || true
  write_root_file "$home/.gemini/antigravity-cli/settings.json" 644 "$tmp/settings.json"
  write_root_file "$home/.gemini/config/hooks.json" 644 "$b/hooks/hooks.json"
  write_root_file "$home/.gemini/config/mcp_config.json" 644 "$b/policies/$grp.mcp_config.json"
  write_root_file "$home/.gemini/antigravity/browserAllowlist.txt" 644 "$tmp/browser.txt"
  # onboarding state: the client can't persist it into read-only settings
  local ob="$home/.gemini/antigravity-cli/cache/onboarding.json"
  [[ -s "$ob" ]] || { echo '{"enterpriseOnboardingComplete": true}' > "$ob"; chown "$u" "$ob" 2>/dev/null || true; }
  # ~/.gemini itself: root-owned and system-immutable, so the user can't rename it away and recreate own files
  chown root:wheel "$home/.gemini"; chmod 755 "$home/.gemini"; lock "$home/.gemini"
  rm -rf "$tmp"
}

write_daemons() {
  mkdir -p "$LD"
  local tmp; tmp="$(mktemp -d)"
  cat > "$tmp/proxy.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$PROXY_LABEL</string>
  <key>ProgramArguments</key><array><string>$PY</string><string>${LIBEXEC#$R}/agy-credproxy.py</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>AGY_DEVICE_AUTH</key><string>cert</string>
    <key>AGY_CLIENT_CERT</key><string>${SUP#$R}/credproxy/device.crt</string>
    <key>AGY_CLIENT_KEY</key><string>${SUP#$R}/credproxy/device.key</string>
    <key>AGY_GATEWAY_CA</key><string>${SUP#$R}/credproxy/root.pem</string>
    <key>AGY_GATEWAY_URL_FILE</key><string>${SUP#$R}/gateway_url</string>
  </dict>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>${LOGDIR#$R}/credproxy.log</string>
  <key>StandardErrorPath</key><string>${LOGDIR#$R}/credproxy.log</string>
</dict></plist>
EOF
  cat > "$tmp/policy.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$POLICY_LABEL</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>${LIBEXEC#$R}/install-macos.sh</string><string>--repair</string></array>
  <key>RunAtLoad</key><true/><key>StartInterval</key><integer>300</integer>
  <key>StandardOutPath</key><string>${LOGDIR#$R}/policy.log</string>
  <key>StandardErrorPath</key><string>${LOGDIR#$R}/policy.log</string>
</dict></plist>
EOF
  write_root_file "$LD/$PROXY_LABEL.plist" 644 "$tmp/proxy.plist"; unlock "$LD/$PROXY_LABEL.plist"   # launchd reads it
  write_root_file "$LD/$POLICY_LABEL.plist" 644 "$tmp/policy.plist"; unlock "$LD/$POLICY_LABEL.plist"
  rm -rf "$tmp"
}

install_client() {   # pinned CLI from the official manifest: download URL under antigravity-public, sha512 checked
  local arch m url sha tgz tmp
  case "$(uname -m)" in arm64) arch=darwin_arm64 ;; x86_64) arch=darwin_amd64 ;; *) fail "unsupported CPU $(uname -m)" ;; esac
  tmp="$(mktemp -d)"
  if [[ -n "${AGY_CLI_TARBALL:-}" ]]; then cp "$AGY_CLI_TARBALL" "$tmp/cli.tgz"; sha="$(shasum -a 512 "$tmp/cli.tgz" | cut -d' ' -f1)"; url="local"; m='{"version":"test"}'
  else
    m="$(curl -fsSL --retry 3 "$(jget "$STATE/poc.json" 'd["client"].get("cli_manifest_url_macos") or "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/'"$arch"'.json"')")" \
      || fail "cannot read the CLI manifest"
    url="$("$PY" -c 'import json,sys; print(json.loads(sys.argv[1])["url"])' "$m")"; sha="$("$PY" -c 'import json,sys; print(json.loads(sys.argv[1])["sha512"])' "$m")"
    [[ "$url" == https://storage.googleapis.com/antigravity-public/* ]] || fail "CLI download URL outside antigravity-public: $url"
    curl -fsSL --retry 3 -o "$tmp/cli.tgz" "$url" || fail "CLI download failed"
    [[ "$(shasum -a 512 "$tmp/cli.tgz" | cut -d' ' -f1)" == "$sha" ]] || fail "CLI sha512 mismatch"
  fi
  mkdir -p "$tmp/x"; tar -xzf "$tmp/cli.tgz" -C "$tmp/x"
  local exe; exe="$(find "$tmp/x" -type f -perm -u+x \( -name 'agy' -o -name 'antigravity' -o -name 'cli*' \) | head -1)"
  [[ -n "$exe" ]] || fail "no CLI executable in the archive"
  mkdir -p "$LIBEXEC/cli"; rm -rf "$LIBEXEC/cli/"*; cp "$exe" "$LIBEXEC/cli/antigravity"; chown -R root:wheel "$LIBEXEC/cli"; chmod 755 "$LIBEXEC/cli/antigravity"
  xattr -dr com.apple.quarantine "$LIBEXEC/cli" 2>/dev/null || true
  "$PY" -c 'import json,sys; m=json.loads(sys.argv[1]); print(json.dumps({"version": m.get("version"), "sha512": sys.argv[2], "url": sys.argv[3]}))' "$m" "$sha" "$url" > "$STATE/cli.json"
  # launcher: personas only (not root / admins), no review-bypass modes, no self-update
  cat > "$tmp/shim" <<'EOF'
#!/bin/bash
# AGY launcher (managed): personas only, human review mandatory
u="$(id -un)"; g=" $(id -Gn) "
if [[ "$(id -u)" -eq 0 || "$g" == *" admin "* ]]; then echo "agy: not for administrators (policy)" >&2; logger -t agy-launch "BLOCKED user=$u reason=admin"; exit 126; fi
case "$g" in *" agy-dev "*|*" agy-contractor "*) ;; *) echo "agy: user $u is not in an AGY persona group (policy)" >&2; logger -t agy-launch "BLOCKED user=$u reason=unmanaged_group"; exit 126 ;; esac
for a in "$@"; do case "$a" in --dangerously-skip-permissions|--yolo|--mode=auto|--mode=accept-edits) echo "agy: $a is not allowed (human review is mandatory)" >&2; logger -t agy-launch "REVIEW_BYPASS_ATTEMPT user=$u arg=$a"; exit 126 ;; esac; done
prev=""; for a in "$@"; do if [[ "$prev" == "--mode" && ( "$a" == "auto" || "$a" == "accept-edits" ) ]]; then echo "agy: --mode $a is not allowed" >&2; exit 126; fi; prev="$a"; done
export AGY_CLI_DISABLE_AUTO_UPDATE=1
exec /usr/local/libexec/agy/cli/antigravity "$@"
EOF
  mkdir -p "$(dirname "$SHIM")"; write_root_file "$SHIM" 755 "$tmp/shim"
  rm -rf "$tmp"
}

# ----------------------------------------------------------------------------- modes
do_install() {
  need_root
  local t0 cfg os arch persona grp ip host
  t0="$(date +%s)"
  "$PY" -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null || fail "$PY not usable - install the Command Line Tools (xcode-select --install) or a signed Python 3.9+ (checklist D2)"
  cfg="$KIT/poc.json"; [[ -f "$cfg" ]] || fail "poc.json not found in $KIT"
  [[ "$(jget "$cfg" 'd["schema"]')" == "agy-poc-kit/1" ]] || fail "poc.json: unsupported schema"
  [[ "$(jget "$cfg" 'd["os"]')" == "macos" ]] || fail "this kit is for $(jget "$cfg" 'd["os"]'), not macOS"
  for f in device.crt device.key gateway-ca.pem bundle/hooks/agy-hook.py bundle/credproxy/agy-credproxy.py bundle/policies/admin_settings.json; do
    [[ -e "$KIT/$f" ]] || fail "kit file missing: $f"
  done
  os="$(sw_vers -productVersion)"; arch="$(uname -m)"
  say "device $(jget "$cfg" 'd["device_id"]') ($(jget "$cfg" 'd["persona"]')) - macOS $os $arch"
  [[ "${os%%.*}" -ge 14 ]] || fail "macOS 14 or later required (this Mac: $os)"
  if [[ -z "$OWNER" ]]; then
    # propose the user signed in at the console (the device owner signs in before IT runs the script)
    OWNER="$(stat -f %Su /dev/console 2>/dev/null || true)"
    [[ -n "$OWNER" && "$OWNER" != "root" && "$OWNER" != "loginwindow" && "$OWNER" != _* ]] \
      || fail "nobody is signed in at the console - let the owner sign in, or pass --user <short name>"
    if [[ $YES -eq 0 ]]; then
      local a; read -r -p "Device owner: $OWNER (kit owner: $(jget "$cfg" 'd["owner"]')) - correct? (y/n): " a
      [[ "$a" =~ ^(y|yes)$ ]] || fail "cancelled - pass --user <short name> to choose the owner"
    fi
    say "device owner: $OWNER (console user)"
  fi
  dscl . -read "/Users/$OWNER" UniqueID >/dev/null 2>&1 || fail "user $OWNER not found"
  is_admin "$OWNER" && fail "$OWNER is an administrator - POC users must be standard users (checklist D3)"
  persona="$(jget "$cfg" 'd["persona"]')"; grp="agy-$persona"
  ip="$(jget "$cfg" 'd["gateway"]["ip"]')"; host="$(jget "$cfg" 'd["gateway"]["hostname"]')"
  if [[ $OFFLINE -eq 1 ]]; then say "offline install: gateway reachability not checked (M11 fails until the Mac is on the VPN)"
  elif [[ -n "$ip" ]]; then nc -z -G 5 "$ip" 443 >/dev/null 2>&1 || fail "gateway $ip:443 not reachable - check the VPN (checklist B1-B4), or use --offline"; fi
  # kit -> state (bundle, config); the drift-repair daemon works from these copies
  mkdir -p "$STATE"; chown root:wheel "$STATE"; chmod 700 "$STATE"
  rm -rf "$STATE/bundle"; cp -R "$KIT/bundle" "$STATE/bundle"; cp "$cfg" "$STATE/poc.json"; chmod -R go-w "$STATE"
  mkdir -p "$LIBEXEC"; cp "$0" "$LIBEXEC/install-macos.sh"; chown root:wheel "$LIBEXEC/install-macos.sh"; chmod 755 "$LIBEXEC/install-macos.sh"
  # persona groups + owner
  local g; for g in "${GROUPS_[@]}"; do dscl . -read "/Groups/$g" >/dev/null 2>&1 || dseditgroup -o create -r "AGY $g" "$g"; done
  for g in "${GROUPS_[@]}"; do
    if [[ "$g" == "$grp" ]]; then in_group "$OWNER" "$g" || dseditgroup -o edit -a "$OWNER" -t user "$g"
    else in_group "$OWNER" "$g" && dseditgroup -o edit -d "$OWNER" -t user "$g"; fi
  done
  say "$OWNER -> $grp"
  # device certificate: root only
  mkdir -p "$SUP/credproxy"; chown root:wheel "$SUP/credproxy"; chmod 700 "$SUP/credproxy"
  local f; for f in device.crt device.key; do cp "$KIT/$f" "$SUP/credproxy/$f"; chown root:wheel "$SUP/credproxy/$f"; chmod 600 "$SUP/credproxy/$f"; done
  cp "$KIT/gateway-ca.pem" "$SUP/credproxy/root.pem"; chown root:wheel "$SUP/credproxy/root.pem"; chmod 644 "$SUP/credproxy/root.pem"
  say "device certificate installed (key readable by root only)"
  [[ "$(jget "$cfg" 'd["gateway"]["pin_hosts"]')" == "True" ]] && { set_hosts "$ip" "$host" "$(jget "$cfg" 'd.get("hosts_pin", "")')"; say "hosts: $ip $host (+ endpoint pins)"; }
  say "installing the pinned Antigravity CLI"; install_client
  apply_machine; apply_user "$OWNER"; write_daemons
  local l; for l in "$PROXY_LABEL" "$POLICY_LABEL"; do
    launchctl bootout "system/$l" >/dev/null 2>&1 || true
    launchctl bootstrap system "$LD/$l.plist" || say "launchctl bootstrap $l failed"
  done
  "$PY" -c 'import json,sys; print(json.dumps({"device": sys.argv[1], "persona": sys.argv[2], "user": sys.argv[3], "installed": sys.argv[4], "seconds": int(sys.argv[5]), "macos": sys.argv[6], "arch": sys.argv[7]}))' \
    "$(jget "$cfg" 'd["device_id"]')" "$persona" "$OWNER" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(( $(date +%s) - t0 ))" "$os" "$arch" > "$STATE/install.json"
  say "installed in $(( ($(date +%s) - t0) )) s (target < 10 min, no reboot); running the self-test"
  sleep 2; do_test
  say "Ask $OWNER to sign out and in once (group membership applies to new sessions)."
}

do_repair() {   # drift repair (policy LaunchDaemon): re-apply locked files and flags; never downloads anything
  [[ -f "$STATE/install.json" ]] || exit 0
  local u; u="$(jget "$STATE/install.json" 'd["user"]')"
  apply_machine; apply_user "$u"
  launchctl print "system/$PROXY_LABEL" >/dev/null 2>&1 || launchctl bootstrap system "$LD/$PROXY_LABEL.plist" 2>/dev/null || true
  logger -t agy-mdm "AGY policy re-applied for $u" 2>/dev/null || true
}

ROWS=()
row() { ROWS+=("$1|$2|$3|$4"); }
file_locked() {   # owner root, not group/other-writable, system-immutable
  local p="$1"; [[ -e "$p" ]] || { echo "missing"; return; }
  local o fl; o="$(stat -f %Su "$p" 2>/dev/null)"; fl="$(stat -f %Sf "$p" 2>/dev/null)"
  [[ "$o" == "root" && "$fl" == *schg* ]] && echo "ok" || echo "owner=$o flags=$fl"
}
do_test() {
  need_root; ROWS=()
  if [[ ! -f "$STATE/install.json" ]]; then
    local left=()
    [[ -e "$SUP/admin_settings.json" ]] && left+=("admin settings")
    [[ -e "$LD/$PROXY_LABEL.plist" || -e "$LD/$POLICY_LABEL.plist" ]] && left+=("LaunchDaemons")
    [[ -e "$SHIM" || -d "$LIBEXEC/cli" ]] && left+=("CLI")
    grep -q "$GW_MARK\$" "$HOSTS" 2>/dev/null && left+=("hosts entry")
    if [[ ${#left[@]} -gt 0 ]]; then row FAIL P00 "Not installed, but leftovers found" "${left[*]}"; else row PASS P00 "Not installed" "no AGY files, daemons or hosts entries"; fi
  else
    local u home persona grp r cfg="$STATE/poc.json"
    u="$(jget "$STATE/install.json" 'd["user"]')"; home="$(user_home "$u")"; persona="$(jget "$cfg" 'd["persona"]')"; grp="agy-$persona"
    r="$(file_locked "$SUP/admin_settings.json")"; local url; url="$(jget "$SUP/admin_settings.json" 'd["gateway"]["url"]' 2>/dev/null || true)"
    [[ "$r" == ok && "$url" == "http://127.0.0.1:8443" ]] && row PASS M01 "Admin settings locked, gateway via local proxy" "$url" || row FAIL M01 "Admin settings locked, gateway via local proxy" "$r url=$url"
    r="$(file_locked "$SUP/hooks/policy.json")"; local r2; r2="$(file_locked "$HOOKBIN")"
    [[ "$r" == ok && "$r2" == ok ]] && row PASS M02 "Corporate hook and policy installed, root-owned, immutable" "audit classes: $(jget "$SUP/hooks/policy.json" '",".join(d.get("default",{}).get("audit_classes",[]))' 2>/dev/null)" || row FAIL M02 "Corporate hook and policy installed, root-owned, immutable" "policy $r; hook $r2"
    local bad=() f; for f in .gemini/antigravity-cli/settings.json .gemini/config/hooks.json .gemini/config/mcp_config.json .gemini/antigravity/browserAllowlist.txt; do r="$(file_locked "$home/$f")"; [[ "$r" == ok ]] || bad+=("$f:$r"); done
    [[ "$(stat -f %Sf "$home/.gemini" 2>/dev/null)" == *schg* ]] || bad+=(".gemini not immutable")
    [[ ${#bad[@]} -eq 0 ]] && row PASS M03 "User's managed files locked (settings, hooks, MCP, browser allowlist; ~/.gemini immutable)" "$u" || row FAIL M03 "User's managed files locked (settings, hooks, MCP, browser allowlist; ~/.gemini immutable)" "${bad[*]}"
    local code; code="$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1:8443/v1beta/models 2>/dev/null || echo 000)"
    launchctl print "system/$PROXY_LABEL" >/dev/null 2>&1 && [[ "$code" == 403 ]] && row PASS M04 "Credential proxy running and refusing non-personas" "root got HTTP $code" || row FAIL M04 "Credential proxy running and refusing non-personas" "launchd=$(launchctl print "system/$PROXY_LABEL" >/dev/null 2>&1 && echo loaded || echo missing) http=$code"
    local km dm; km="$(stat -f '%Su:%Sg %Lp' "$SUP/credproxy/device.key" 2>/dev/null)"; dm="$(stat -f '%Lp' "$SUP/credproxy" 2>/dev/null)"
    [[ "$km" == "root:wheel 600" && "$dm" == 700 ]] && row PASS M05 "Device key readable by root only" "$km, folder $dm" || row FAIL M05 "Device key readable by root only" "key $km folder $dm"
    launchctl print "system/$POLICY_LABEL" >/dev/null 2>&1 && row PASS M06 "Drift repair daemon loaded (every 5 min)" "$POLICY_LABEL" || row FAIL M06 "Drift repair daemon loaded (every 5 min)" "not loaded"
    local hl; hl="$(grep "$GW_MARK\$" "$HOSTS" 2>/dev/null | head -1)"
    [[ -n "$hl" ]] && row PASS M07 "Gateway name resolves to the internal address" "$hl" || row FAIL M07 "Gateway name resolves to the internal address" "hosts entry missing"
    in_group "$u" "$grp" && ! is_admin "$u" && row PASS M08 "Device owner is a standard user in the persona group" "$u in $grp" || row FAIL M08 "Device owner is a standard user in the persona group" "$u in $grp: $(in_group "$u" "$grp" && echo yes || echo no); admin: $(is_admin "$u" && echo yes || echo no)"
    local v; v="$(jget "$STATE/cli.json" 'd["version"]' 2>/dev/null || true)"
    [[ -x "$LIBEXEC/cli/antigravity" && -x "$SHIM" ]] && row PASS M09 "Pinned Antigravity CLI and managed launcher" "version $v (sha512 verified)" || row FAIL M09 "Pinned Antigravity CLI and managed launcher" "missing"
    "$PY" -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null && row PASS M10 "Python for the hook and proxy" "$("$PY" --version 2>&1)" || row FAIL M10 "Python for the hook and proxy" "$PY not usable"
    local hs; hs="$("$PY" - "$(jget "$cfg" 'd["gateway"]["hostname"]')" "$SUP/credproxy" <<'PY' 2>&1 | tail -1
import socket, ssl, sys
host, d = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(cafile=d + "/root.pem"); ctx.load_cert_chain(d + "/device.crt", d + "/device.key")
with socket.create_connection((host, 443), timeout=30) as s, ctx.wrap_socket(s, server_hostname=host) as t:
    t.sendall(("GET /_gw/health HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
    print("OK " + t.version() + " " + t.recv(64).decode(errors="replace").splitlines()[0])
PY
)" || true
    [[ "$hs" == OK* ]] && row PASS M11 "Device certificate accepted by the gateway front door (mTLS)" "$hs" || row FAIL M11 "Device certificate accepted by the gateway front door (mTLS)" "$hs"
    local exp; exp="$(openssl x509 -enddate -noout -in "$SUP/credproxy/device.crt" 2>/dev/null | cut -d= -f2)"
    openssl x509 -checkend $((7*86400)) -noout -in "$SUP/credproxy/device.crt" >/dev/null 2>&1 && row PASS M12 "Device certificate valid" "until $exp" || row WARN M12 "Device certificate valid" "until $exp (< 7 days or unreadable)"
    local s; s="$(jget "$STATE/install.json" 'd["seconds"]')"
    [[ "$s" -lt 600 ]] && row PASS M13 "Install time under 10 minutes, no reboot" "${s}s" || row WARN M13 "Install time under 10 minutes, no reboot" "${s}s"
  fi
  local out="$STATE/test.json" p=0 w=0 fl=0 sk=0 line
  mkdir -p "$STATE"
  printf '%s\n' "${ROWS[@]}" | "$PY" -c 'import json,sys; print(json.dumps([dict(zip(["status","id","title","detail"], l.rstrip("\n").split("|",3))) for l in sys.stdin if l.strip()], indent=2))' > "$out"
  for line in "${ROWS[@]}"; do
    IFS='|' read -r st id ti de <<<"$line"; printf '%-5s %-4s %-78s %s\n' "$st" "$id" "$ti" "$de"
    case "$st" in PASS) p=$((p+1)) ;; WARN) w=$((w+1)) ;; FAIL) fl=$((fl+1)) ;; *) sk=$((sk+1)) ;; esac
  done
  say "$p PASS, $w WARN, $fl FAIL, $sk SKIP - ${out#$R}"
}

do_collect() {
  need_root
  local ts dev w; ts="$(date +%Y%m%d-%H%M%S)"; dev="$(jget "$STATE/poc.json" 'd["device_id"]' 2>/dev/null || hostname -s)"
  w="$(mktemp -d)/agy-collect-$dev-$ts"; mkdir -p "$w"
  log show --last 14d --style syslog --predicate 'eventMessage CONTAINS "agy-hook" OR eventMessage CONTAINS "agy-launch" OR eventMessage CONTAINS "agy-mdm" OR senderImagePath CONTAINS "logger"' > "$w/unified-log.txt" 2>/dev/null || true
  cp "$LOGDIR"/*.log "$w/" 2>/dev/null || true
  cp "$STATE"/*.json "$w/" 2>/dev/null || true
  cp "$SUP/hooks/policy.json" "$w/hook-policy.json" 2>/dev/null || true
  if [[ -f "$STATE/install.json" ]]; then local home; home="$(user_home "$(jget "$STATE/install.json" 'd["user"]')")"; mkdir -p "$w/cli-logs"; cp "$home/.gemini/antigravity-cli/log/"*.log "$w/cli-logs/" 2>/dev/null || true; fi
  do_test > "$w/test-output.txt" 2>&1 || true
  tar -czf "$STATE/collect-$dev-$ts.tar.gz" -C "$(dirname "$w")" "$(basename "$w")"; chmod 600 "$STATE/collect-$dev-$ts.tar.gz"
  rm -rf "$(dirname "$w")"
  say "evidence: ${STATE#$R}/collect-$dev-$ts.tar.gz (root only)"
}

do_uninstall() {
  need_root
  local l u="" home=""
  [[ -f "$STATE/install.json" ]] && u="$(jget "$STATE/install.json" 'd["user"]')"
  for l in "$POLICY_LABEL" "$PROXY_LABEL"; do launchctl bootout "system/$l" >/dev/null 2>&1 || true; rm -f "$LD/$l.plist"; done
  if [[ -n "$u" ]]; then
    home="$(user_home "$u")"
    if [[ -n "$home" && -d "$home/.gemini" ]]; then
      unlock "$home/.gemini"
      for f in .gemini/antigravity-cli/settings.json .gemini/config/hooks.json .gemini/config/mcp_config.json .gemini/antigravity/browserAllowlist.txt; do unlock "$home/$f"; rm -f "$home/$f"; done
      chown -R "$u" "$home/.gemini" 2>/dev/null || true
      say "$u: AGY locks lifted, managed files removed (own files in ~/.gemini kept)"
    fi
  fi
  unlock "$SUP" "$SUP/admin_settings.json" "$SUP/hooks/policy.json" "$SUP/gateway_url" "$HOOKBIN" "$SHIM" "$LIBEXEC/agy-credproxy.py"
  rm -rf "$SUP" "$LIBEXEC" "$HOOKBIN" "$SHIM"
  set_hosts "" "" ""
  local g; for g in "${GROUPS_[@]}"; do dscl . -read "/Groups/$g" >/dev/null 2>&1 && dseditgroup -o delete "$g" >/dev/null 2>&1 && say "group $g removed"; done
  mkdir -p "$LOGDIR/removed-$(date +%Y%m%d-%H%M%S)"; mv "$LOGDIR"/*.log "$LOGDIR"/removed-*/ 2>/dev/null || true
  rm -f "$STATE/install.json" "$STATE/poc.json" "$STATE/cli.json"; rm -rf "$STATE/bundle"
  say "uninstalled (kept: evidence in ${STATE#$R}, logs in ${LOGDIR#$R}, the user's own files)"
  do_test
}

case "$MODE" in
  install) do_install ;;
  test) do_test ;;
  collect) do_collect ;;
  uninstall) do_uninstall ;;
  repair) do_repair ;;
esac
