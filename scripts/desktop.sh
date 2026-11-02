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

# Open a persona desktop (xrdp) through an IAP TCP tunnel.
#   scripts/desktop.sh <dev|contractor> [local-port]        (VM=windows: the Windows workstation)
# Needs: roles/iap.tunnelResourceAccessor on the VM + secretAccessor on the persona secret (operators get both).
# The password is copied to the clipboard when possible, otherwise printed once; it is never written to disk.
source "$(dirname "$0")/lib.sh"
PERSONA="${1:?usage: $0 <dev|contractor> [local-port]}"; PORT="${2:-13389}"
[[ "$PERSONA" =~ ^(dev|contractor)$ ]] || die "persona must be dev or contractor"
if [[ "${TARGET_OS:-linux}" == "windows" ]]; then
  VM="$(tfo windows_workstation_name)"; SESSION="Windows (NLA; clipboard per policy; drives/printers not redirected)"
  SECRET="$(tfo windows_desktop_secrets | python3 -c "import json,sys; print(json.load(sys.stdin).get('$PERSONA',''))" 2>/dev/null)"
else
  VM="$(tfo workstation_name)"; SESSION="XFCE (clipboard per policy; drives/printers not redirected)"
  SECRET="$(tfo desktop_secrets | python3 -c "import json,sys; print(json.load(sys.stdin).get('$PERSONA',''))" 2>/dev/null)"
fi
[[ -n "$VM" ]] || die "no ${TARGET_OS:-linux} workstation in state - run ./install.sh"
[[ -n "$SECRET" ]] || die "no desktop secret for $PERSONA (desktop_access=none?)"

[[ "$(gcloud compute instances describe "$VM" --zone "$ZONE" --format='value(status)')" == "RUNNING" ]] \
  || { log "starting $VM"; gcloud compute instances start "$VM" --zone "$ZONE" --quiet; sleep 30; }

PW="$(gcloud secrets versions access latest --secret "$SECRET")"
copied=""
if command -v pbcopy >/dev/null; then printf '%s' "$PW" | pbcopy && copied=1
elif command -v wl-copy >/dev/null && [[ -n "${WAYLAND_DISPLAY:-}" ]]; then printf '%s' "$PW" | wl-copy && copied=1
elif command -v xclip >/dev/null && [[ -n "${DISPLAY:-}" ]]; then printf '%s' "$PW" | xclip -selection clipboard && copied=1
fi

log "IAP tunnel ${VM}:3389 -> localhost:${PORT} (Ctrl-C to close)"
gcloud compute start-iap-tunnel "$VM" 3389 --local-host-port="localhost:${PORT}" --zone "$ZONE" >/dev/null 2>&1 &
TUN=$!; trap 'kill $TUN 2>/dev/null' EXIT
for _ in $(seq 1 20); do (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break; sleep 1; done

cat <<EOF

  RDP target : localhost:${PORT}
  User       : ${PERSONA}
  Password   : $([[ -n "$copied" ]] && echo "copied to clipboard" || echo "$PW")
  Session    : ${SESSION}

EOF
unset PW
if command -v remmina >/dev/null && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  remmina -c "rdp://${PERSONA}@localhost:${PORT}" >/dev/null 2>&1 &
elif command -v xfreerdp >/dev/null && [[ -n "${DISPLAY:-}" ]]; then
  log "launch: xfreerdp /v:localhost:${PORT} /u:${PERSONA} /sec:tls /cert:tofu /dynamic-resolution"
elif [[ "$(uname)" == "Darwin" ]]; then
  log "macOS: open 'Windows App' (Microsoft Remote Desktop) -> add PC 'localhost:${PORT}', user '${PERSONA}'"
else
  log "connect any RDP client to localhost:${PORT} (Cloud Shell has no GUI: run this from your workstation)"
fi
wait "$TUN"
