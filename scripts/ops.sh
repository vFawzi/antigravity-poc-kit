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

# Day-2 helpers: stop | start | ssh | bootstrap | evidence | logs | status | rotate-desktop-passwords
source "$(dirname "$0")/lib.sh"
if [[ "${TARGET_OS:-linux}" == "windows" ]]; then VM="$(tfo windows_workstation_name)"; else VM="$(tfo workstation_name)"; fi
[[ -n "$VM" ]] || die "no ${TARGET_OS:-linux} workstation in state - run ./install.sh"
case "${1:-status}" in
  stop)      gcloud compute instances stop "$VM" --zone "$ZONE" ;;
  start)     gcloud compute instances start "$VM" --zone "$ZONE" ;;
  ssh)       gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap ;;
  bootstrap) gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --command "sudo google_metadata_script_runner startup && sudo tail -5 /var/log/agy-bootstrap.log" ;;
  evidence)  gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --command "sudo agy-evidence && sudo bash -c 'cat \$(ls -t /var/tmp/agy-evidence-*.txt | head -1)'" ;;
  logs)      gcloud logging read 'jsonPayload.component="agy-gateway" AND jsonPayload.event=("PROMPT_BLOCKED" OR "ROUTED" OR "RESPONSE_FLAGGED" OR "MODEL_DENIED" OR "PROMPT_FLAGGED" OR "STOLEN_TOKEN_SUSPECTED" OR "PERIMETER_DRYRUN_VIOLATION" OR "CONTAINMENT_DRYRUN" OR "CONTAINMENT_APPLIED" OR "CONTAINMENT_FAILED" OR "CONTAINMENT_SKIPPED" OR "MODEL_OFF_POLICY")' \
               --freshness 1h --limit 50 --format 'table(timestamp, jsonPayload.event, jsonPayload.group, jsonPayload.user, jsonPayload.category, jsonPayload.requested, jsonPayload.routed, jsonPayload.incident, jsonPayload.risk)' ;;
  status)    gcloud compute instances describe "$VM" --zone "$ZONE" --format 'value(name,status)'; echo "gateway: $(tfo gateway_url)" ;;
  rotate-desktop-passwords)
    log "new random persona passwords -> Secret Manager (new versions), then re-applied on the VM"
    tf apply -input=false -auto-approve -var "gateway_image=$(current_image)" \
      -replace='module.workstation[0].random_password.persona["dev"]' -replace='module.workstation[0].random_password.persona["contractor"]'
    gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet --command "sudo /usr/local/sbin/agy-xrdp-setup" ;;
  signin-window)
    # Seat mode: time-boxed HTTPS to Google's published front-end ranges for the persona's browser sign-in
    # (the sign-in pages rotate addresses faster than the DNS-based allowlist). Audited; elements expire on their own.
    mins="${MINUTES:-15}"; [[ "$mins" =~ ^[0-9]+$ && "$mins" -ge 1 && "$mins" -le 60 ]] || die "MINUTES must be 1-60"
    # Google-owned ranges minus Google Cloud customer ranges (no customer-hosted GCP addresses -> no exfil target)
    ranges="$(python3 scripts/google_ranges.py)"
    [[ -n "$ranges" ]] || die "could not fetch https://www.gstatic.com/ipranges/goog.json"
    log "sign-in window: Google front-end ranges open for ${mins} min (persona groups, TCP 443 only)"
    if [[ "${TARGET_OS:-linux}" == "windows" ]]; then
      # Windows: the egress sync task merges the ranges until the expiry (C:\ProgramData\Antigravity\signin-window.json)
      tmp="$(mktemp)"; python3 -c 'import json,sys,time; print(json.dumps({"until": int(time.time()) + int(sys.argv[1]) * 60, "ranges": sys.argv[2].split(",")}))' "$mins" "$ranges" > "$tmp"
      gcloud compute scp "$tmp" "$VM:C:\ProgramData\Antigravity\signin-window.json" --zone "$ZONE" --tunnel-through-iap --quiet; rm -f "$tmp"
      gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet --command \
        "powershell -NoProfile -Command \"Write-EventLog -LogName Application -Source agy-mdm -EventId 1001 -EntryType Warning -Message 'SIGNIN-WINDOW opened ${mins}m by operator'; & C:\ProgramData\Antigravity\bundle\files\controls\Sync-AGYEgress.ps1\""
      exit 0
    fi
    gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet --command \
      "sudo nft add element inet agy_policy signin_window4 '{ ${ranges//,/ timeout ${mins}m, } timeout ${mins}m }' && logger -t agy-mdm 'SIGNIN-WINDOW opened ${mins}m by operator $(gcloud config get-value account 2>/dev/null)'" ;;
  *) die "usage: $0 stop|start|ssh|bootstrap|evidence|logs|status|rotate-desktop-passwords|signin-window" ;;
esac
