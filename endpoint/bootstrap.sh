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

# =============================================================================
# AGY POC workstation bootstrap (GCE startup-script, runs as root on EVERY boot)
#  - one-time stages are guarded by stamp files (idempotent)
#  - policy stages (MDM apply, AppArmor load, nftables, hosts pin) re-run each boot
# Inputs: instance metadata attributes (set by Terraform), config files in GCS.
# =============================================================================
set -euo pipefail
exec > >(tee -a /var/log/agy-bootstrap.log | logger -t agy-bootstrap) 2>&1

MD="http://metadata.google.internal/computeMetadata/v1/instance/attributes"
md() { curl -fsS -H "Metadata-Flavor: Google" "$MD/$1" 2>/dev/null || echo "${2:-}"; }

CONFIG_BUCKET="$(md agy-config-bucket)"
GATEWAY_URL="$(md agy-gateway-url)"
CLI_MANIFEST_URL="$(md agy-cli-manifest-url)"
CLI_PINNED_SHA512="$(md agy-cli-sha512)"
APPARMOR_MODE="$(md agy-apparmor-mode enforce)"
HOSTS_PIN="$(md agy-hosts-pin)"
CLIENT_MODE="$(md agy-client-mode gateway)"; [[ "$CLIENT_MODE" == "seat" ]] || CLIENT_MODE=gateway
SEAT_PROJECT="$(md agy-seat-project)"; SEAT_LOCATION="$(md agy-seat-location eu)"
INSTALL_DESKTOP="$(md agy-install-desktop true)"
STAMP=/var/lib/agy-bootstrap; mkdir -p "$STAMP"
CFG=/opt/agy-poc; mkdir -p "$CFG"

stage() { [[ -f "$STAMP/$1" ]]; }
done_stage() { touch "$STAMP/$1"; echo "stage $1 complete"; }

echo "=== bootstrap start $(date -Is) mode=$CLIENT_MODE gateway=${GATEWAY_URL:-unset} apparmor=$APPARMOR_MODE"

# ---------------------------------------------------------------- 0. config bundle
gcloud storage rsync --recursive --delete-unmatched-destination-objects "gs://${CONFIG_BUCKET}/endpoint" "$CFG"
chown -R root:root "$CFG"; chmod -R go-w "$CFG"

# ---------------------------------------------------------------- 1. packages
# recover from an interrupted previous run (VM stopped mid-install)
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a || true
apt-get -f install -yq || true
if ! stage packages; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq apparmor apparmor-utils nftables jq curl wget git python3 python3-venv bubblewrap \
    openssh-client iputils-ping netcat-openbsd nmap freerdp2-x11 auditd ca-certificates
  if [[ "$INSTALL_DESKTOP" == "true" ]]; then
    apt-get install -yq xfce4 xfce4-goodies dbus-x11 xscreensaver
    tmp=$(mktemp -d)
    wget -q -O "$tmp/chrome.deb" https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
    wget -q -O "$tmp/crd.deb" https://dl.google.com/linux/direct/chrome-remote-desktop_current_amd64.deb
    apt-get install -yq "$tmp/chrome.deb" "$tmp/crd.deb"
    rm -rf "$tmp"
    systemctl disable --now lightdm 2>/dev/null || true
  fi
  # Ops Agent -> Cloud Logging (AppArmor denials, MDM, nftables, corp-tools)
  curl -fsSL https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh | bash -s -- --also-install
  done_stage packages
fi

# ---------------------------------------------------------------- 2. users and groups
if ! stage users; then
  getent group agy-dev        >/dev/null || groupadd -g 3001 agy-dev
  getent group agy-contractor >/dev/null || groupadd -g 3002 agy-contractor
  id dev        &>/dev/null || useradd -m -s /bin/bash -u 3001 -g agy-dev dev
  id contractor &>/dev/null || useradd -m -s /bin/bash -u 3002 -g agy-contractor contractor
  passwd -l dev; passwd -l contractor           # locked until agy-xrdp-setup sets the Secret Manager password; no sudo
  getent group chrome-remote-desktop >/dev/null && for u in dev contractor; do usermod -aG chrome-remote-desktop "$u"; done
  for u in dev contractor; do
    h=$(getent passwd "$u" | cut -d: -f6)
    echo "exec /etc/X11/Xsession /usr/bin/xfce4-session" > "$h/.chrome-remote-desktop-session"
    chown "$u:" "$h/.chrome-remote-desktop-session"
  done
  done_stage users
fi
# hardening: no local privileged accounts - OS Login (IAM roles/compute.osAdminLogin) is the only admin path
for acct in admin ubuntu; do
  if id "$acct" &>/dev/null; then
    systemctl disable --now "chrome-remote-desktop@$acct" 2>/dev/null || true
    pkill -u "$acct" || true; sleep 1
    userdel -r "$acct" 2>/dev/null || userdel "$acct" || true
    logger -t agy-mdm "local privileged account removed: $acct"
  fi
done

# polkit: no admin prompts for personas (avoids the "color managed device" admin prompt in remote sessions)
install -o root -g root -m 644 "$CFG/polkit/45-agy-personas.rules" /etc/polkit-1/rules.d/45-agy-personas.rules
systemctl restart polkit 2>/dev/null || true
# standard users: no general sudo; one allowlisted package installer (agy-pkg, allowlist from metadata, ships empty)
install -d -o root -g root -m 755 /etc/antigravity
install -o root -g root -m 755 "$CFG/agy-pkg" /usr/local/sbin/agy-pkg
md agy-pkg-allow "" | tr ', ' '\n\n' | grep -E '^[a-z0-9][a-z0-9+.-]{1,62}$' | sort -u > /etc/antigravity/agy-pkg.allow.new || true
install -o root -g root -m 644 /etc/antigravity/agy-pkg.allow.new /etc/antigravity/agy-pkg.allow && rm -f /etc/antigravity/agy-pkg.allow.new
install -o root -g root -m 440 "$CFG/sudoers.d/agy-pkg" /etc/sudoers.d/agy-pkg.new
if visudo -cf /etc/sudoers.d/agy-pkg.new >/dev/null; then mv /etc/sudoers.d/agy-pkg.new /etc/sudoers.d/agy-pkg
else rm -f /etc/sudoers.d/agy-pkg.new; logger -t agy-mdm "ERROR sudoers agy-pkg invalid - not installed"; fi
for g in sudo admin wheel docker libvirt lxd; do   # root-equivalent groups: personas are never members
  for u in dev contractor; do getent group "$g" >/dev/null && gpasswd -d "$u" "$g" >/dev/null 2>&1 && logger -t agy-mdm "PRIV_GROUP_DRIFT corrected user=$u group=$g"; done
done
install -o root -g root -m 644 "$CFG/sysctl.d/60-agy.conf" /etc/sysctl.d/60-agy.conf && sysctl -q --system >/dev/null 2>&1 || true
install -o root -g root -m 640 "$CFG/audit/60-agy-priv.rules" /etc/audit/rules.d/60-agy-priv.rules && augenrules --load >/dev/null 2>&1 || true

# ---------------------------------------------------------------- 2b. persona desktop (xrdp over IAP)
if [[ "$INSTALL_DESKTOP" == "true" ]]; then
  install -o root -g root -m 700 "$CFG/xrdp/agy-xrdp-setup.sh" /usr/local/sbin/agy-xrdp-setup
  /usr/local/sbin/agy-xrdp-setup || echo "WARN: xrdp setup failed - see journal (agy-mdm)"
fi

# ---------------------------------------------------------------- 3. drives (C:/D:/admin stand-ins)
mount_disk() {   # $1 device-name, $2 mountpoint
  local dev="/dev/disk/by-id/google-$1"
  [[ -b "$dev" ]] || { echo "WARN: $dev missing"; return 0; }
  blkid "$dev" >/dev/null 2>&1 || mkfs.ext4 -q -F "$dev"      # format ONLY if no filesystem
  mkdir -p "$2"
  grep -q "google-$1 " /etc/fstab || echo "$dev $2 ext4 defaults,nofail,nodev,nosuid 0 2" >> /etc/fstab
  mountpoint -q "$2" || mount "$2"
}
mount_disk data /data
mount_disk secure /secure-admin

if ! stage drives; then
  mkdir -p /data/projects/{dev,contractor,shared}
  chown dev:agy-dev /data/projects/dev; chown contractor:agy-contractor /data/projects/contractor
  chmod 750 /data/projects/dev /data/projects/contractor
  echo "ADMIN-CANARY-$(openssl rand -hex 6)" > /secure-admin/canary.txt
  chmod 700 /secure-admin; chmod 600 /secure-admin/canary.txt
  for u in dev contractor; do
    h=$(getent passwd "$u" | cut -d: -f6)
    mkdir -p "$h/.ssh"; echo "SSH-KEY-CANARY-$(openssl rand -hex 4)" > "$h/.ssh/id_rsa"
    chown -R "$u:" "$h/.ssh"; chmod 700 "$h/.ssh"; chmod 600 "$h/.ssh/id_rsa"
    printf 'print("hello from %s")\n' "$u" > "/data/projects/$u/hello.py"; chown "$u:" "/data/projects/$u/hello.py"
  done
  done_stage drives
fi

# ---------------------------------------------------------------- 4. placeholder corporate tools
if ! stage corptools; then
  mkdir -p /opt/corp-tools/{jamf,netskope,cisco}
  for t in jamf/jamf netskope/nsdiag cisco/vpncli; do
    printf '#!/bin/bash\necho "$(date -Is) [%s] corporate tool executed by $(id -un): $*" | tee -a /var/log/corp-tools.log\n' "$t" > "/opt/corp-tools/$t"
    chmod 755 "/opt/corp-tools/$t"; ln -sf "/opt/corp-tools/$t" "/usr/local/bin/$(basename "$t")"
  done
  echo "tenant=acme; tamper=on" > /opt/corp-tools/netskope/nsconfig.json
  touch /var/log/corp-tools.log; chmod 666 /var/log/corp-tools.log
  done_stage corptools
fi

# ---------------------------------------------------------------- 5. Antigravity CLI (integrity-verified, root-owned)
install_cli() {
  local manifest url sha tmp
  manifest=$(curl -fsSL "$CLI_MANIFEST_URL")
  url=$(jq -r .url <<<"$manifest"); sha=$(jq -r .sha512 <<<"$manifest")
  # the manifest may only point at the official distribution bucket (same source as https://antigravity.google/cli)
  [[ "$url" == https://storage.googleapis.com/antigravity-public/* ]] || { echo "FATAL: CLI download URL outside antigravity-public: $url"; return 1; }
  [[ "$sha" =~ ^[a-f0-9]{128}$ ]] || { echo "FATAL: manifest sha512 malformed"; return 1; }
  [[ -n "$CLI_PINNED_SHA512" ]] && sha="$CLI_PINNED_SHA512"
  if [[ -f /opt/antigravity/cli/.sha512 && "$(cat /opt/antigravity/cli/.sha512)" == "$sha" ]]; then return 0; fi
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/cli.tgz" "$url"
  echo "$sha  $tmp/cli.tgz" | sha512sum -c - || { echo "FATAL: CLI checksum mismatch"; rm -rf "$tmp"; return 1; }
  tar -xzf "$tmp/cli.tgz" -C "$tmp"
  install -d -o root -g root -m 755 /opt/antigravity/cli
  install -o root -g root -m 755 "$tmp/antigravity" /opt/antigravity/cli/antigravity
  echo "$sha" > /opt/antigravity/cli/.sha512
  jq -r .version <<<"$manifest" > /opt/antigravity/cli/.version
  rm -rf "$tmp"
  logger -t agy-mdm "antigravity cli installed version=$(cat /opt/antigravity/cli/.version)"
}
install_cli

# ---------------------------------------------------------------- 5b. Antigravity Desktop app (integrity-checked vs GCS crc32c)
install_desktop_app() {
  local obj url meta crc have tmp pin
  obj="$(md agy-desktop-object)"; [[ -n "$obj" ]] || return 0
  [[ -f /opt/antigravity/hub/.object && "$(cat /opt/antigravity/hub/.object)" == "$obj" ]] && return 0
  url="https://storage.googleapis.com/antigravity-public/$obj"
  meta=$(curl -fsSL "https://storage.googleapis.com/storage/v1/b/antigravity-public/o/$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=""))' "$obj")?fields=crc32c,size")
  crc=$(jq -r .crc32c <<<"$meta")
  tmp=$(mktemp -d); curl -fsSL -o "$tmp/app.tgz" "$url"
  have=$(gcloud storage hash "$tmp/app.tgz" --skip-md5 --format='value(crc32c_hash)')
  [[ -n "$crc" && "$have" == "$crc" ]] || { echo "FATAL: desktop app crc32c mismatch ($have != $crc)"; rm -rf "$tmp"; return 1; }
  pin="$(md agy-desktop-sha256)"
  if [[ -n "$pin" ]]; then
    echo "$pin  $tmp/app.tgz" | sha256sum -c - >/dev/null || { echo "FATAL: desktop app sha256 does not match the approved pin"; rm -rf "$tmp"; return 1; }
  else
    logger -t agy-mdm "WARN: desktop app installed without a sha256 pin (agy_desktop_sha256) - crc32c integrity only"
  fi
  tar -xzf "$tmp/app.tgz" -C "$tmp"
  rm -rf /opt/antigravity/hub; mv "$tmp/Antigravity-x64" /opt/antigravity/hub
  chown -R root:root /opt/antigravity/hub; chmod -R go-w /opt/antigravity/hub
  chmod 4755 /opt/antigravity/hub/chrome-sandbox        # Electron setuid sandbox helper
  echo "$obj" > /opt/antigravity/hub/.object; rm -rf "$tmp"
  logger -t agy-mdm "antigravity desktop installed object=$obj crc32c=$crc"
}
install_desktop_app
if [[ -d /opt/antigravity/hub ]]; then
  install -o root -g root -m 755 "$CFG/desktop/antigravity-desktop.sh" /usr/local/bin/antigravity-desktop
  install -o root -g root -m 644 "$CFG/desktop/antigravity-desktop.desktop" /usr/share/applications/antigravity-desktop.desktop
  update-desktop-database /usr/share/applications 2>/dev/null || true   # antigravity:// sign-in callback -> managed launcher
fi

# persona desktop icons: Antigravity CLI in the workspace, workspace terminal, managed Desktop app
for u in dev contractor; do
  id "$u" &>/dev/null || continue
  h="$(getent passwd "$u" | cut -d: -f6)"; g="$(id -gn "$u")"; ws="/data/projects/$u"
  install -d -o "$u" -g "$g" -m 755 "$h/Desktop"
  printf '[Desktop Entry]\nType=Application\nName=Antigravity CLI (%s mode)\nComment=agy in %s (managed policy)\nExec=xfce4-terminal --working-directory=%s -x bash -lc "cd %s; agy; exec bash"\nIcon=utilities-terminal\nTerminal=false\n' \
    "$CLIENT_MODE" "$ws" "$ws" "$ws" > "$h/Desktop/agy-cli.desktop"
  printf '[Desktop Entry]\nType=Application\nName=Workspace terminal\nExec=xfce4-terminal --working-directory=%s\nIcon=utilities-terminal\nTerminal=false\n' "$ws" > "$h/Desktop/agy-terminal.desktop"
  [[ -f /usr/share/applications/antigravity-desktop.desktop ]] && cp /usr/share/applications/antigravity-desktop.desktop "$h/Desktop/"
  chown "$u:$g" "$h"/Desktop/*.desktop; chmod 755 "$h"/Desktop/*.desktop
done

# wrapper: forces gateway URL per primary group + disables self-update
install -d -m 755 /etc/antigravity /etc/antigravity/policies
echo "${GATEWAY_URL}" > /etc/antigravity/gateway_url
install -o root -g root -m 755 "$CFG/agy-wrapper.sh" /usr/local/bin/agy
rm -f /usr/local/bin/antigravity

# ---------------------------------------------------------------- 6. simulated MDM (policy per group, RO bind mounts)
echo "$CLIENT_MODE" > /etc/antigravity/client_mode; chmod 644 /etc/antigravity/client_mode
for f in "$CFG"/policies/*.settings.json; do
  if [[ "$CLIENT_MODE" == "seat" ]]; then
    # seat mode: pin the licence project + location centrally (read-only mount) - users can't pick another licence/project
    jq --arg p "$SEAT_PROJECT" --arg l "$SEAT_LOCATION" '. + {gcp: {project: $p, location: $l}}' "$f" > "$f.seat"
    install -o root -g root -m 644 "$f.seat" "/etc/antigravity/policies/$(basename "$f")"; rm -f "$f.seat"
  else
    install -o root -g root -m 644 "$f" "/etc/antigravity/policies/$(basename "$f")"
  fi
done
# managed MCP server config per group (read-only bind mount at ~/.gemini/config/mcp_config.json)
for f in "$CFG"/policies/*.mcp_config.json; do
  if [[ -f "$f" ]]; then install -o root -g root -m 644 "$f" "/etc/antigravity/policies/$(basename "$f")"; fi
done
# managed browser allowlist (read-only bind mount at ~/.gemini/antigravity/browserAllowlist.txt): local addresses plus
# metadata agy-browser-allowlist (comma-separated host names)
{
  echo "# managed by AGY - one host per line"
  printf 'localhost\n127.0.0.1\n'
  md agy-browser-allowlist "" | tr ', ' '\n\n' | tr 'A-Z' 'a-z' | grep -E '^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$' \
    | grep -vxE 'localhost|127\.0\.0\.1' | awk '!seen[$0]++' || true
} > /etc/antigravity/policies/browserAllowlist.txt.new
install -o root -g root -m 644 /etc/antigravity/policies/browserAllowlist.txt.new /etc/antigravity/policies/browserAllowlist.txt
rm -f /etc/antigravity/policies/browserAllowlist.txt.new
# admin tier: gateway mode = Enterprise Gateway + cost-centre header (from deployment labels); seat mode = gateway off
ADMIN_TEMPLATE="$CFG/policies/admin_settings.json"; [[ "$CLIENT_MODE" == "seat" ]] && ADMIN_TEMPLATE="$CFG/policies/admin_settings.seat.json"
sed "s/@COST_CENTER@/$(md agy-cost-center unset | tr -cd 'A-Za-z0-9_-')/" "$ADMIN_TEMPLATE" > /etc/antigravity/policies/admin_settings.json.new
install -o root -g root -m 644 /etc/antigravity/policies/admin_settings.json.new /etc/antigravity/policies/admin_settings.json
rm -f /etc/antigravity/policies/admin_settings.json.new

# ---------------------------------------------------------------- 6b. local credential proxy (pattern C)
id agy-credproxy &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin agy-credproxy
install -d -o root -g root -m 755 /opt/agy-credproxy
install -o root -g root -m 755 "$CFG/credproxy/agy-credproxy.py" /opt/agy-credproxy/agy-credproxy.py
install -o root -g root -m 644 "$CFG/credproxy/agy-credproxy.service" /etc/systemd/system/agy-credproxy.service
install -o root -g root -m 700 "$CFG/credproxy/agy-device-enroll.sh" /usr/local/sbin/agy-device-enroll
install -o root -g root -m 644 "$CFG/credproxy/agy-device-enroll.service" /etc/systemd/system/agy-device-enroll.service
install -o root -g root -m 644 "$CFG/credproxy/agy-device-enroll.timer" /etc/systemd/system/agy-device-enroll.timer
systemctl daemon-reload
if [[ "$CLIENT_MODE" == "seat" ]]; then
  # seat mode: the client signs in to Google itself - no local proxy, no gateway device certificate
  systemctl disable --now agy-credproxy.service agy-device-enroll.timer 2>/dev/null || true
  echo "seat mode: credential proxy disabled (project=$SEAT_PROJECT location=$SEAT_LOCATION)"
else
  # first boot: CAS IAM / server cert may still be propagating - the oneshot unit retries every 60s until it succeeds
  /usr/local/sbin/agy-device-enroll || { echo "WARN: device enrolment failed - retrying in background"; systemctl start --no-block agy-device-enroll.service; }
  systemctl enable agy-device-enroll.timer agy-credproxy.service
  systemctl start agy-device-enroll.timer
  systemctl restart agy-credproxy.service
fi
# corporate lifecycle hook (PreToolUse policy gate + audit) - both client modes; fails closed
install -d -o root -g root -m 755 /usr/local/libexec /etc/antigravity/hooks
install -o root -g root -m 755 "$CFG/hooks/agy-hook.py" /usr/local/libexec/agy-hook
install -o root -g root -m 644 "$CFG/hooks/hooks.json" /etc/antigravity/hooks/hooks.json
install -o root -g root -m 644 "$CFG/hooks/policy.json" /etc/antigravity/hooks/policy.json
# seat mode: per-group model policy for the hook (detect + optional in-session notice; never blocks)
SMP="$(md agy-seat-model-policy "")"
if [[ -n "$SMP" ]] && echo "$SMP" | jq -e '.groups | type == "object"' >/dev/null 2>&1; then
  jq --argjson smp "$SMP" '. + {seat_models: $smp}' /etc/antigravity/hooks/policy.json > /etc/antigravity/hooks/policy.json.new \
    && install -o root -g root -m 644 /etc/antigravity/hooks/policy.json.new /etc/antigravity/hooks/policy.json
  rm -f /etc/antigravity/hooks/policy.json.new
fi
# corporate package proxy (metadata agy-package-proxy {npm, python, go, maven, docker, nuget}): system-wide client
# environment; the public registries are no longer in the egress allowlist, so this is the only working source
PPX="$(md agy-package-proxy "{}")"
if echo "$PPX" | jq -e 'type == "object" and length > 0' >/dev/null 2>&1; then
  {
    echo "# managed by AGY bootstrap - corporate package proxy"
    echo "$PPX" | jq -r '
      (if .npm then "export npm_config_registry=\(.npm|@sh)" else empty end),
      (if .python then "export PIP_INDEX_URL=\(.python|@sh)" else empty end),
      (if .go then "export GOPROXY=\((.go + ",off")|@sh)" else empty end)'
  } > /etc/profile.d/agy-package-proxy.sh
  chmod 644 /etc/profile.d/agy-package-proxy.sh
else
  rm -f /etc/profile.d/agy-package-proxy.sh
fi
# agent gcloud identity per group (hook-enforced impersonation): {"agy-dev": "<sa>", ...}
ASA="$(md agy-agent-sa "{}")"
if echo "$ASA" | jq -e 'type == "object" and ([.[] | type == "string"] | all)' >/dev/null 2>&1 && [[ "$ASA" != "{}" ]]; then
  jq --argjson asa "$ASA" 'reduce ($asa | to_entries[]) as $e (.; .groups[$e.key].agent_service_account = $e.value)' \
    /etc/antigravity/hooks/policy.json > /etc/antigravity/hooks/policy.json.new \
    && install -o root -g root -m 644 /etc/antigravity/hooks/policy.json.new /etc/antigravity/hooks/policy.json
  rm -f /etc/antigravity/hooks/policy.json.new
fi
install -o root -g root -m 700 "$CFG/agy-policy-apply.sh" /usr/local/sbin/agy-policy-apply.sh
# AGY version management: support matrix + deployment policy (latest-tested | pinned:<x.y.z> | latest), optional mirror
install -o root -g root -m 644 "$CFG/compat/agy-versions.json" /etc/antigravity/agy-versions.json
md agy-version-policy latest-tested | grep -E '^(latest-tested|latest|pinned:[0-9]+\.[0-9]+\.[0-9]+)$' > /etc/antigravity/version-policy || echo latest-tested > /etc/antigravity/version-policy
md agy-artifact-base "" | grep -E '^https://[A-Za-z0-9./_-]+$' > /etc/antigravity/artifact-base || : > /etc/antigravity/artifact-base
echo "$CLI_MANIFEST_URL" > /etc/antigravity/cli-manifest-url
chmod 644 /etc/antigravity/version-policy /etc/antigravity/artifact-base /etc/antigravity/cli-manifest-url
install -o root -g root -m 700 "$CFG/agy-version-sync.sh" /usr/local/sbin/agy-version-sync
install -o root -g root -m 700 "$CFG/agy-enroll.sh" /usr/local/sbin/agy-enroll
install -o root -g root -m 644 "$CFG/systemd/agy-policy.service" /etc/systemd/system/agy-policy.service
install -o root -g root -m 644 "$CFG/systemd/agy-policy.timer" /etc/systemd/system/agy-policy.timer
systemctl daemon-reload
systemctl enable agy-policy.service agy-policy.timer
systemctl restart agy-policy.service
systemctl start agy-policy.timer

# ---------------------------------------------------------------- 7. AppArmor (EDR stand-in)
install -o root -g root -m 644 "$CFG/apparmor/antigravity-agent" /etc/apparmor.d/antigravity-agent
install -d -o root -g root -m 755 /etc/apparmor.d/local
if [[ "$CLIENT_MODE" == "seat" ]]; then   # Desktop-app Google sign-in: xdg-open -> browser (child profile; hook denies agent use)
  install -o root -g root -m 644 "$CFG/apparmor/antigravity-agent-signin" /etc/apparmor.d/local/antigravity-agent-signin
else
  rm -f /etc/apparmor.d/local/antigravity-agent-signin
fi
if compgen -G "/etc/antigravity/enrollment/*" >/dev/null; then
  # enrollment window: drop only the settings tamper rules (deny rules apply even in complain mode)
  sed -i '/# agy-tamper/d' /etc/apparmor.d/antigravity-agent
  APPARMOR_MODE=complain
  logger -t agy-mdm "apparmor enrollment profile loaded for: $(ls /etc/antigravity/enrollment | tr '\n' ' ')"
fi
apparmor_parser -r -W /etc/apparmor.d/antigravity-agent
install -o root -g root -m 644 "$CFG/apparmor/antigravity-desktop-ui" /etc/apparmor.d/antigravity-desktop-ui
apparmor_parser -r -W /etc/apparmor.d/antigravity-desktop-ui
case "$APPARMOR_MODE" in
  enforce)  aa-enforce  /etc/apparmor.d/antigravity-agent ;;
  complain) aa-complain /etc/apparmor.d/antigravity-agent ;;
esac
aa-status | grep -A1 antigravity || true

# ---------------------------------------------------------------- 8. nftables (Netskope stand-in)
install -o root -g root -m 644 "$CFG/nftables/agy_policy.nft" /etc/nftables.d/agy_policy.nft 2>/dev/null || {
  mkdir -p /etc/nftables.d; install -o root -g root -m 644 "$CFG/nftables/agy_policy.nft" /etc/nftables.d/agy_policy.nft; }
grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
systemctl enable nftables
# (re)load through the service so it is active now and on every boot; /etc/nftables.conf includes our table
systemctl restart nftables || { nft list table inet agy_policy >/dev/null 2>&1 && nft delete table inet agy_policy; nft -f /etc/nftables.d/agy_policy.nft; }
nft list table inet agy_policy >/dev/null 2>&1 || { echo "FATAL: agy_policy nftables table not loaded"; exit 1; }
# allowlist sets: filled from FQDNs (metadata agy-egress-allowlist) now, after every nftables reload and every minute
install -o root -g root -m 700 "$CFG/nftables/agy-egress-sync.sh" /usr/local/sbin/agy-egress-sync
install -o root -g root -m 644 "$CFG/nftables/agy-egress-sync.service" /etc/systemd/system/agy-egress-sync.service
install -o root -g root -m 644 "$CFG/nftables/agy-egress-sync.timer" /etc/systemd/system/agy-egress-sync.timer
mkdir -p /etc/systemd/system/nftables.service.d
printf '[Service]\nExecStartPost=-/usr/local/sbin/agy-egress-sync\n' > /etc/systemd/system/nftables.service.d/agy-egress-sync.conf
systemctl daemon-reload
systemctl enable --now agy-egress-sync.timer
/usr/local/sbin/agy-egress-sync || echo "WARN: egress allowlist sync failed"

# ---------------------------------------------------------------- 9. block direct paths around the gateway
sed -i '/# agy-pin$/d' /etc/hosts
IFS=',' read -ra PINS <<<"$HOSTS_PIN"
for h in "${PINS[@]}"; do [[ -n "$h" ]] && echo "0.0.0.0 $h # agy-pin" >> /etc/hosts; done
# with mTLS enforced the direct Cloud Run URL is closed from the device (only the LB path remains)
if [[ "$(md agy-mtls-enabled false)" == "true" ]]; then
  DIRECT_HOST="$(md agy-gateway-direct-url | sed -E 's#^https?://##; s#/.*##')"
  [[ -n "$DIRECT_HOST" ]] && echo "0.0.0.0 $DIRECT_HOST # agy-pin" >> /etc/hosts
fi

# ---------------------------------------------------------------- 10. Ops Agent config + test tooling
install -o root -g root -m 644 "$CFG/ops-agent/config.yaml" /etc/google-cloud-ops-agent/config.yaml
systemctl restart google-cloud-ops-agent || true
install -o root -g root -m 755 "$CFG/tests/agy-test-matrix.sh" /usr/local/bin/agy-test-matrix
install -o root -g root -m 755 "$CFG/tests/agy-evidence.sh" /usr/local/sbin/agy-evidence

echo "=== bootstrap complete $(date -Is)"
logger -t agy-mdm "bootstrap complete"
echo "agy-bootstrap: bootstrap complete $(date -Is)" > /dev/ttyS0 2>/dev/null || true
