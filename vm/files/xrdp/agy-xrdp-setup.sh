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

# agy-xrdp-setup - persona desktop over RDP (xrdp + xorgxrdp), reachable only through IAP.
# Runs as root on every boot (called by the bootstrap); idempotent. Never prints passwords.
#  * TLS-only listener, drive/printer redirection off, clipboard per policy (agy-rdp-clipboard)
#  * only members of agy-rdp (dev, contractor) may log in: sesman TerminalServerUsers + PAM rule
#  * persona passwords come from Secret Manager (VM SA has secretAccessor on those secrets only;
#    managed users cannot reach the metadata server - nftables), personas stay without SSH / sudo
set -euo pipefail
MD="http://metadata.google.internal/computeMetadata/v1"
md() { curl -fsS -H "Metadata-Flavor: Google" "$MD/instance/attributes/$1" 2>/dev/null || echo "${2:-}"; }
ACCESS="$(md agy-desktop-access none)"
CLIP="$(md agy-rdp-clipboard true)"
SECRETS="$(md agy-desktop-secrets)"
PROJECT="$(curl -fsS -H "Metadata-Flavor: Google" "$MD/project/project-id")"
CFG=/opt/agy-poc/xrdp
PERSONAS=(dev contractor)

# personas never log in over SSH (OS Login admins are unaffected); no password auth at all
install -d -m 755 /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-agy-personas.conf <<'EOF'
# managed by agy-xrdp-setup: personas use the RDP desktop only
DenyUsers dev contractor
PasswordAuthentication no
KbdInteractiveAuthentication no
EOF
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

if [[ "$ACCESS" != "xrdp" ]]; then
  systemctl disable --now xrdp xrdp-sesman 2>/dev/null || true
  for u in "${PERSONAS[@]}"; do passwd -l "$u" >/dev/null 2>&1 || true; done
  echo "xrdp: disabled (desktop_access=$ACCESS), persona passwords locked"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive
# one desktop per persona: a Chrome Remote Desktop session left enabled from an earlier access mode starts a second
# XFCE session at boot, and the xrdp session then shows only the wallpaper (XFCE is single-instance per user)
for u in "${PERSONAS[@]}"; do
  if systemctl is-enabled --quiet "chrome-remote-desktop@$u" 2>/dev/null; then
    systemctl disable --now "chrome-remote-desktop@$u" 2>/dev/null || true
    logger -t agy-mdm "xrdp: disabled chrome-remote-desktop@$u (single desktop session per persona)"
  fi
done
dpkg -s xrdp xorgxrdp >/dev/null 2>&1 || apt-get install -yq xrdp xorgxrdp ssl-cert
[[ -s /etc/ssl/private/ssl-cert-snakeoil.key ]] || make-ssl-cert generate-default-snakeoil --force-overwrite
usermod -aG ssl-cert xrdp 2>/dev/null || true

# ---- listener + channel policy
cliprdr=false; [[ "$CLIP" == "true" ]] && cliprdr=true
sed "s/@CLIPRDR@/${cliprdr}/" "$CFG/xrdp.ini" > /etc/xrdp/xrdp.ini.new
install -o root -g root -m 644 /etc/xrdp/xrdp.ini.new /etc/xrdp/xrdp.ini; rm -f /etc/xrdp/xrdp.ini.new

# ---- session manager: group gate, no root, idle/disconnect limits
S=/etc/xrdp/sesman.ini
set_ini() { sed -i -E "s|^;?\s*$1\s*=.*|$1=$2|" "$S"; grep -q "^$1=" "$S" || echo "WARN: $1 not found in sesman.ini"; }
set_ini AllowRootLogin false
set_ini TerminalServerUsers agy-rdp
set_ini AlwaysGroupCheck true
set_ini MaxLoginRetry 3
set_ini KillDisconnected true
set_ini DisconnectedTimeLimit 28800
set_ini IdleTimeLimit 1800
set_ini EnableFuseMount false || true

getent group agy-rdp >/dev/null || groupadd agy-rdp
P=/etc/pam.d/xrdp-sesman
grep -q 'pam_succeed_if.so user ingroup agy-rdp' "$P" \
  || sed -i '1i auth required pam_succeed_if.so user ingroup agy-rdp quiet_success' "$P"

# ---- personas: group, XFCE session, password from Secret Manager
for u in "${PERSONAS[@]}"; do
  id "$u" &>/dev/null || continue
  usermod -aG agy-rdp "$u"
  h="$(getent passwd "$u" | cut -d: -f6)"
  echo "xfce4-session" > "$h/.xsession"; chown "$u:" "$h/.xsession"; chmod 644 "$h/.xsession"
done

set +x
IFS=',' read -ra PAIRS <<<"$SECRETS"
for pair in "${PAIRS[@]}"; do
  u="${pair%%=*}"; s="${pair#*=}"
  [[ -n "$u" && -n "$s" ]] && id "$u" &>/dev/null || continue
  pw=""
  for i in 1 2 3 4 5 6; do   # IAM propagation on first boot
    pw="$(gcloud secrets versions access latest --secret "$s" --project "$PROJECT" 2>/dev/null)" && [[ -n "$pw" ]] && break
    sleep 20
  done
  if [[ -n "$pw" ]]; then
    printf '%s:%s\n' "$u" "$pw" | chpasswd
    logger -t agy-mdm "desktop password set for $u from secret $s"
  else
    passwd -l "$u" >/dev/null; logger -t agy-mdm "WARN: desktop secret $s unreadable - $u locked"
  fi
  unset pw
done

systemctl enable xrdp xrdp-sesman >/dev/null 2>&1
systemctl restart xrdp-sesman xrdp
logger -t agy-mdm "xrdp ready (tls, clipboard=$cliprdr, rdpdr=off, group=agy-rdp)"
echo "xrdp: ready (clipboard=$cliprdr)"
