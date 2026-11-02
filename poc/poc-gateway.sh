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

# poc-gateway.sh - pay-as-you-go POC: gateway + device kits in one command.
#
#   poc/poc-gateway.sh                 ask 6 questions (+ optional network question 7), deploy the gateway, issue one
#                                      certificate per device, write kits
#   poc/poc-gateway.sh --yes           re-run with the saved answers (poc/.state/answers.env), no prompts
#   poc/poc-gateway.sh --reissue       also re-issue every device certificate (otherwise only missing / < 7 days left)
#   poc/poc-gateway.sh --status        gateway IP and port, network, budgets and device certificates
#   poc/poc-gateway.sh --destroy       remove the POC cloud resources, then (on confirmation) the kits and keys
#   HOOK_NOISY=enforce poc/poc-gateway.sh --yes   kits with the noisy hook rules enforced (after week 1); re-run the
#                                       endpoint script with the new kit on each device
#
# Deploys the fixed POC composition through the standard installer (profile gateway): gateway with Model Armor and
# Sensitive Data Protection, persona model tiers, mTLS device certificates (internal load balancer, reached over the
# customer VPN), logging + BigQuery views, CMEK, EU location, labels, cost per persona and per-persona budget alerts.
# Writes poc-kit/<device>/ (endpoint script, poc.json, device certificate and key) and poc-kit/<device>.tar.gz.
# Never changes the global gcloud configuration (always --project).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # works from any current folder
POC="$ROOT/poc"
STATE="$POC/.state"
ANSWERS="$STATE/answers.env"
CONF="$STATE/install.conf"
CERTS="$STATE/certs"
MODEL_PRICES="${MODEL_PRICES:-$POC/model-prices.json}"   # indicative list prices for the usage cost estimate
[[ -f "$MODEL_PRICES" ]] || MODEL_PRICES=""
KIT="$ROOT/poc-kit"
TFVARS="$ROOT/terraform/poc.auto.tfvars"
YES=0; MODE="install"; REISSUE=0; CERT_DAYS="${CERT_DAYS:-30}"

log()  { printf '\033[1;34m[poc]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[poc]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[poc] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '16,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) YES=1; shift ;;
    --reissue) REISSUE=1; shift ;;
    --status) MODE="status"; shift ;;
    --destroy) MODE="destroy"; shift ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done
# the installer's pinned Terraform (install.sh puts it in .tools/bin; Cloud Shell may have none or another version)
use_installer_tf() { [[ -x "$ROOT/.tools/bin/terraform" && ":$PATH:" != *":$ROOT/.tools/bin:"* ]] && export PATH="$ROOT/.tools/bin:$PATH"; return 0; }
need_tf() { use_installer_tf; command -v terraform >/dev/null 2>&1 || die "terraform not found (run the install first, or poc/poc-gateway.sh --yes)"; }
use_installer_tf
command -v gcloud >/dev/null || die "gcloud not found"
command -v python3 >/dev/null || die "python3 not found"
command -v openssl >/dev/null || die "openssl not found"
install -d -m 700 "$STATE" "$CERTS"

# ----------------------------------------------------------------------------- questions (no secrets saved)
unset PROJECT_ID REGION ADMIN_EMAIL BUDGET_DEV BUDGET_CONTRACTOR DEVICES_CSV BILLING_ACCOUNT INTERNAL_DNS_DOMAIN COST_CENTER \
      NETWORK_MODE SHARED_VPC_HOST_PROJECT SHARED_VPC_NETWORK SHARED_VPC_SUBNET GATEWAY_ILB_IP ILB_GLOBAL_ACCESS
# shellcheck disable=SC1090
[[ -f "$ANSWERS" ]] && source "$ANSWERS"
ask() {   # ask VAR "question" "default" "regex"
  local var="$1" q="$2" def="$3" re="$4" cur="${!1:-}" ans
  [[ -n "$cur" ]] && def="$cur"
  if [[ $YES -eq 1 ]]; then
    [[ "$def" =~ $re ]] || die "$var='$def' missing or invalid in $ANSWERS"
    printf -v "$var" '%s' "$def"; return
  fi
  while true; do
    read -r -p "$(printf '\033[1m%s\033[0m%s: ' "$q" "${def:+ [$def]}")" ans || die "no answer (stdin closed) for: $q"
    ans="${ans:-$def}"
    [[ "$ans" =~ $re ]] && break
    warn "invalid value"
  done
  printf -v "$var" '%s' "$ans"
}
questions() {
  local email_re='^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$' amount_re='^[1-9][0-9]{0,6}$'
  ask PROJECT_ID "1/6 GCP project ID for the POC" "" '^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
  ask REGION "2/6 Region (EU residency)" "europe-west4" '^europe-[a-z]+[0-9]+$'
  ask ADMIN_EMAIL "3/6 Admin e-mail (operator, budget and security alerts; a group address is best)" \
      "$(gcloud config get-value account 2>/dev/null || true)" "$email_re"
  ask BUDGET_DEV "4/6 Monthly budget alert for developers (billing account currency)" "2000" "$amount_re"
  ask BUDGET_CONTRACTOR "5/6 Monthly budget alert for contractors (billing account currency)" "1000" "$amount_re"
  ask DEVICES_CSV "6/6 Path to devices.csv (device,owner,persona,os)" "$POC/devices.csv" '^.+$'
  DEVICES_CSV="$(cd "$(dirname "$DEVICES_CSV")" && pwd)/$(basename "$DEVICES_CSV")"
  INTERNAL_DNS_DOMAIN="${INTERNAL_DNS_DOMAIN:-agy.internal}"
  COST_CENTER="${COST_CENTER:-security}"
  python3 "$POC/poc_kit.py" validate "$DEVICES_CSV" || die "fix $DEVICES_CSV and re-run"
  network_question
  gcloud services enable cloudbilling.googleapis.com --project "$PROJECT_ID" --quiet >/dev/null \
    || die "cannot enable the Cloud Billing API on $PROJECT_ID"
  local ba
  ba="$(gcloud billing projects describe "$PROJECT_ID" --billing-project "$PROJECT_ID" --format='value(billingAccountName)' 2>/dev/null || true)"
  BILLING_ACCOUNT="${ba#billingAccounts/}"
  [[ -n "$BILLING_ACCOUNT" ]] || die "$PROJECT_ID has no billing account linked (or you cannot read it)"
  umask 077
  cat > "$ANSWERS" <<EOF
# poc-gateway.sh answers - $(date -u +%Y-%m-%dT%H:%M:%SZ). No secrets.
PROJECT_ID="$PROJECT_ID"
REGION="$REGION"
ADMIN_EMAIL="$ADMIN_EMAIL"
BUDGET_DEV="$BUDGET_DEV"
BUDGET_CONTRACTOR="$BUDGET_CONTRACTOR"
DEVICES_CSV="$DEVICES_CSV"
BILLING_ACCOUNT="$BILLING_ACCOUNT"
INTERNAL_DNS_DOMAIN="$INTERNAL_DNS_DOMAIN"
COST_CENTER="$COST_CENTER"
NETWORK_MODE="$NETWORK_MODE"
SHARED_VPC_HOST_PROJECT="$SHARED_VPC_HOST_PROJECT"
SHARED_VPC_NETWORK="$SHARED_VPC_NETWORK"
SHARED_VPC_SUBNET="$SHARED_VPC_SUBNET"
GATEWAY_ILB_IP="$GATEWAY_ILB_IP"
ILB_GLOBAL_ACCESS="$ILB_GLOBAL_ACCESS"
EOF
}

# ----------------------------------------------------------------------------- question 7: network (optional)
# [1] new VPC in this project (default = today's behaviour) or [2] an existing Shared VPC subnet of the network team.
# Nothing in the host project is created or changed; the network team shares the subnet, provides the proxy-only
# subnet and grants the installer Compute Network User on the subnet.
PROJ_RE='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'; NAME_RE='^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$'
IP_RE='^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$'
parse_subnet_url() {   # .../projects/<host>/regions/<region>/subnetworks/<name> -> "<host> <region> <name>"
  [[ "$1" =~ projects/([a-z][a-z0-9-]+)/regions/([a-z0-9-]+)/subnetworks/([a-z0-9-]+)$ ]] || return 1
  printf '%s %s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
}
detect_host_project() {   # Shared VPC host of the service project ("" when not attached / not readable)
  gcloud compute shared-vpc get-host-project "$PROJECT_ID" --format='value(name)' 2>/dev/null | head -1 || true
}
usable_subnets() {   # "<subnet url>\t<network name>\t<cidr>" per subnet this identity may use in $REGION of host project $1
  # listUsable must be asked on the HOST project (on the service project it returns nothing); JSON, not value(): the
  # value() projection shortens the resource URLs
  gcloud compute networks subnets list-usable --project "$1" --format=json 2>/dev/null | python3 -c '
import json, sys
region = sys.argv[1]
try:
    rows = json.load(sys.stdin) or []
except ValueError:
    rows = []
for r in rows:
    url = str(r.get("subnetwork", ""))
    if f"/regions/{region}/subnetworks/" in url and r.get("purpose", "PRIVATE") in ("PRIVATE", ""):
        print(url + "\t" + str(r.get("network", "")).rsplit("/", 1)[-1] + "\t" + str(r.get("ipCidrRange", "")))
' "$REGION" || true
}
pick_shared_subnet() {   # numbered list of the subnets this identity may use in $REGION of the host project; sets 7b/7c defaults
  local rows=() line url net cidr h r n i=0 pick
  while IFS=$'\t' read -r url net cidr; do
    [[ -n "$url" ]] && rows+=("$url"$'\t'"$net"$'\t'"$cidr")
  done < <(usable_subnets "$SHARED_VPC_HOST_PROJECT")
  if [[ ${#rows[@]} -eq 0 ]]; then
    warn "no subnet of $SHARED_VPC_HOST_PROJECT usable by $(gcloud config get-value account 2>/dev/null) in $REGION is visible (not shared yet, or no Compute Network User on it) - type the values your network team gave you"
    return 0
  fi
  echo "   Subnets you may use in $REGION (host project $SHARED_VPC_HOST_PROJECT):"
  for line in "${rows[@]}"; do
    i=$((i + 1)); IFS=$'\t' read -r url net cidr <<<"$line"
    read -r h r n <<<"$(parse_subnet_url "$url")"
    printf '   [%d] network %s  subnet %s  %s\n' "$i" "$net" "$n" "$cidr"
  done
  echo "   m = type the values instead"
  while true; do
    read -r -p "$(printf '\033[1m%s\033[0m: ' "   7c Subnet: number [1]")" pick \
      || die "no answer (stdin closed) for the subnet choice"
    pick="${pick:-1}"   # Enter = the first (often the only) subnet
    if [[ "$pick" =~ ^[mM]$ ]]; then   # typed values: offer the network when the list shows exactly one
      local nets; nets="$(for line in "${rows[@]}"; do IFS=$'\t' read -r url net cidr <<<"$line"; echo "$net"; done | sort -u)"
      [[ -z "$SHARED_VPC_NETWORK" && $(wc -l <<<"$nets") -eq 1 ]] && SHARED_VPC_NETWORK="$nets"
      return 0
    fi
    [[ "$pick" =~ ^[0-9]+$ && $pick -ge 1 && $pick -le ${#rows[@]} ]] && break
    warn "invalid value"
  done
  IFS=$'\t' read -r url net cidr <<<"${rows[$((pick - 1))]}"
  read -r h r n <<<"$(parse_subnet_url "$url")"
  SHARED_VPC_NETWORK="$net"; SHARED_VPC_SUBNET="$n"
  log "selected: network $net, subnet $n ($cidr) - confirm or change below"
}
network_question() {
  NETWORK_MODE="${NETWORK_MODE:-create}"; ILB_GLOBAL_ACCESS="${ILB_GLOBAL_ACCESS:-false}"
  SHARED_VPC_HOST_PROJECT="${SHARED_VPC_HOST_PROJECT:-}"; SHARED_VPC_NETWORK="${SHARED_VPC_NETWORK:-}"
  SHARED_VPC_SUBNET="${SHARED_VPC_SUBNET:-}"; GATEWAY_ILB_IP="${GATEWAY_ILB_IP:-}"
  [[ "$NETWORK_MODE" =~ ^(create|shared)$ ]] || die "NETWORK_MODE='$NETWORK_MODE' invalid in $ANSWERS (create or shared)"
  [[ "$ILB_GLOBAL_ACCESS" =~ ^(true|false)$ ]] || die "ILB_GLOBAL_ACCESS='$ILB_GLOBAL_ACCESS' invalid in $ANSWERS (true or false)"
  NET_CHOICE="$([[ "$NETWORK_MODE" == "shared" ]] && echo 2 || echo 1)"
  if [[ $YES -eq 0 ]]; then
    echo "7 (optional) Network for the gateway"
    echo "   [1] new VPC in this project (default, today's behaviour)"
    echo "   [2] existing Shared VPC (your network team shares a subnet with this project)"
  fi
  ask NET_CHOICE "7 Network [1/2]" "1" '^[12]$'
  if [[ "$NET_CHOICE" == "1" ]]; then NETWORK_MODE="create"; return 0; fi
  NETWORK_MODE="shared"
  if [[ $YES -eq 0 && -z "$SHARED_VPC_HOST_PROJECT" ]]; then   # 7a default: the host this project is attached to
    SHARED_VPC_HOST_PROJECT="$(detect_host_project)"
    [[ -n "$SHARED_VPC_HOST_PROJECT" ]] && log "this project is attached to Shared VPC host project $SHARED_VPC_HOST_PROJECT"
  fi
  ask SHARED_VPC_HOST_PROJECT "   7a Host project ID" "" "$PROJ_RE"
  [[ "$SHARED_VPC_HOST_PROJECT" != "$PROJECT_ID" ]] || die "the host project must be the Shared VPC host project, not $PROJECT_ID"
  [[ $YES -eq 1 ]] || pick_shared_subnet
  ask SHARED_VPC_NETWORK "   7b Shared VPC network name" "" "$NAME_RE"
  ask SHARED_VPC_SUBNET "   7c Subnet name (in $REGION)" "" "$NAME_RE"
  GW_IP_ANSWER="${GATEWAY_ILB_IP:-auto}"
  ask GW_IP_ANSWER "   7e Gateway IP (auto = any free IP in the subnet, or a specific free IP)" "auto" "^auto\$|$IP_RE"
  GATEWAY_ILB_IP="$([[ "$GW_IP_ANSWER" == "auto" ]] && echo "" || echo "$GW_IP_ANSWER")"
  GA_ANSWER="$([[ "$ILB_GLOBAL_ACCESS" == "true" ]] && echo y || echo n)"
  ask GA_ANSWER "   7f Does your on-prem connection (VPN/Interconnect) end in another region than $REGION? [y/N]" "n" '^[yYnN]$'
  ILB_GLOBAL_ACCESS="$([[ "$GA_ANSWER" =~ ^[yY]$ ]] && echo true || echo false)"
}
network_line() {   # "shared (host / network / subnet)" or "create (new VPC in this project)"
  local ga; ga="$([[ "${ILB_GLOBAL_ACCESS:-false}" == "true" ]] && echo ", global access on" || true)"
  if [[ "${NETWORK_MODE:-create}" == "shared" ]]; then
    printf 'shared (%s / %s / %s)%s' "$SHARED_VPC_HOST_PROJECT" "$SHARED_VPC_NETWORK" "$SHARED_VPC_SUBNET" "$ga"
  else
    printf 'create (new VPC in this project)%s' "$ga"
  fi
}

# The fixed POC composition = installer profile gateway + these answers (see compositions/poc-gateway.yaml)
write_install_conf() {
  local prev_ack=""
  [[ -f "$CONF" ]] && prev_ack="$(sed -n 's/^COST_ACK="\(.*\)"$/\1/p' "$CONF")"
  COST_ACK="${COST_ACK:-$prev_ack}"   # a cost acknowledgement given once is kept for --yes re-runs
  umask 077
  cat > "$CONF" <<EOF
# GENERATED by poc/poc-gateway.sh - fixed POC composition. No secrets.
PROFILE="gateway"
PROJECT_ID="$PROJECT_ID"
REGION="$REGION"
ZONE="${REGION}-a"
OPERATORS="user:$ADMIN_EMAIL"
SECOPS_EMAIL="$ADMIN_EMAIL"
COST_CENTER="$COST_CENTER"
INTERNAL_DNS_DOMAIN="$INTERNAL_DNS_DOMAIN"
LOG_LOCK_DAYS="0"
GROUPS_MODE="none"
PROMPT_LOGGING="hash"
FLEET_ISSUERS=""
CLIENT_MODE="gateway"
AGY_POC="1"
COST_ACK="${COST_ACK:-}"
EOF
}

cost_ack() {
  grep -q '^COST_ACK="yes"' "$CONF" 2>/dev/null && return 0
  cat <<'EOF'

 Estimated cost of the POC gateway (list prices, indicative):
   - Internal load balancer + Private CA (3 DevOps-tier CAs) ... ~EUR 60-80/month
   - Cloud Run, KMS, Model Armor, logging, NAT ................. ~EUR 15-30/month at POC volumes
   - Vertex AI Gemini calls .................................... pay per token (budget alerts per persona)
EOF
  [[ $YES -eq 1 ]] && die "costs not acknowledged yet: run once without --yes"
  local a; read -r -p "Proceed and accept these costs? (yes/no): " a
  [[ "$a" == "yes" ]] || die "aborted"
  sed -i.bak 's/^COST_ACK=.*/COST_ACK="yes"/' "$CONF" && rm -f "$CONF.bak"
}

tfo() {   # terraform output (string or JSON); "" when that output does not exist yet; errors are shown, never swallowed
  command -v terraform >/dev/null 2>&1 || die "terraform not found (run the install first, or poc/poc-gateway.sh --yes)"
  local out errf rc=0
  errf="$(mktemp)"
  out="$(terraform -chdir="$ROOT/terraform" output -json "$1" 2>"$errf")" || rc=$?
  if [[ $rc -ne 0 ]]; then
    if grep -qi "output .* not found" "$errf"; then rm -f "$errf"; echo ""; return 0; fi   # not created (yet)
    warn "cannot read state (terraform output $1): $(LC_ALL=C tr -s ' \n' ' ' <"$errf" | cut -c1-600)"
    rm -f "$errf"; return 1
  fi
  rm -f "$errf"
  python3 -c 'import json,sys; v=json.loads(sys.argv[1]); print(v if isinstance(v,str) else json.dumps(v))' "$out" \
    || { warn "unreadable terraform output $1"; return 1; }
}
tfo_required() {   # tfo_required NAME "what is missing" -> value, or stop with the reason
  local v; v="$(tfo "$1")" || die "cannot read state: terraform output $1 failed (error above)"
  [[ -n "$v" ]] || die "$2"
  printf '%s\n' "$v"
}

needs_cert() {   # missing, or fewer than 7 days left
  local crt="$CERTS/$1.crt"
  [[ $REISSUE -eq 1 || ! -s "$crt" || ! -s "$CERTS/$1.key" ]] && return 0
  ! openssl x509 -checkend $((7 * 86400)) -noout -in "$crt" >/dev/null
}

shred_keys() {
  local f
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    if command -v shred >/dev/null; then shred -u "$f"; else rm -P "$f" 2>/dev/null || rm -f "$f"; fi
  done
}

devices() {   # device ids from devices.csv (validated)
  python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import poc_kit, pathlib
for d in poc_kit.read_devices(pathlib.Path(sys.argv[2])): print(d.device)' "$POC" "$DEVICES_CSV"
}

# ----------------------------------------------------------------------------- modes
do_install() {
  questions
  write_install_conf
  cost_ack
  log "devices.csv -> device registry + budgets (terraform/poc.auto.tfvars)"
  python3 "$POC/poc_kit.py" tfvars "$DEVICES_CSV" --billing-account "$BILLING_ACCOUNT" \
    --budget "dev=$BUDGET_DEV" --budget "contractor=$BUDGET_CONTRACTOR" \
    ${MODEL_PRICES:+--prices "$MODEL_PRICES"} --out "$TFVARS" \
    --network-mode "$NETWORK_MODE" --shared-vpc-host-project "$SHARED_VPC_HOST_PROJECT" \
    --shared-vpc-network "$SHARED_VPC_NETWORK" --shared-vpc-subnet "$SHARED_VPC_SUBNET" \
    --gateway-ilb-ip "$GATEWAY_ILB_IP" --ilb-global-access "$ILB_GLOBAL_ACCESS"
  log "network: $(network_line)"
  log "deploying the POC gateway (standard installer, profile gateway)"
  "$ROOT/install.sh" --config "$CONF" --yes
  need_tf   # the installer may just have installed its pinned Terraform into .tools/bin
  local url ip
  url="$(tfo_required gateway_mtls_url "no gateway URL in the Terraform outputs - check the installer log (install-report.md)")"
  ip="$(tfo_required gateway_ilb_ip "no gateway IP in the Terraform outputs - check the installer log (install-report.md)")"
  log "device certificates (fleet CA, ${CERT_DAYS} days; persona comes from the registry, not the certificate)"
  local dev issued=0
  while read -r dev; do
    if needs_cert "$dev"; then
      "$ROOT/scripts/fleet-cert.sh" "$dev" --test-key --out "$CERTS" --days "$CERT_DAYS" >/dev/null
      issued=$((issued + 1))
    fi
  done < <(devices)
  log "  $issued certificate(s) issued"
  for dev in $(devices); do
    [[ -s "$CERTS/$dev.key" ]] || die "$dev: key missing in $CERTS (run with --reissue)"
  done
  log "writing device kits to ${KIT#$ROOT/}/"
  tfo device_settings_by_mode > "$STATE/device-settings.json" || die "cannot read the device settings from the Terraform state"
  python3 "$POC/poc_kit.py" kit "$DEVICES_CSV" --certs "$CERTS" --out "$KIT" --gateway-url "$url" \
    --gateway-ip "$ip" --project "$PROJECT_ID" --region "$REGION" --device-settings "$STATE/device-settings.json" \
    --hook-noisy "${HOOK_NOISY:-audit}"
  cat <<EOF

 POC gateway ready: $url (internal IP $ip, TCP 443; reach it over the VPN; the kits pin the name)
 Network: $(network_line)
 Device kits: ${KIT#$ROOT/}/<device>.tar.gz  - they contain the device private key:
   hand them to IT over a secure channel, delete them after installation (poc/poc-gateway.sh --status shows expiry).
 Next: on each laptop, as admin/root, run the endpoint script from its kit (-Install, then -Test).
EOF
}

do_status() {
  [[ -f "$ANSWERS" ]] || die "no POC deployed from this checkout ($ANSWERS missing)"
  need_tf
  local gw_url gw_ip
  gw_url="$(tfo gateway_mtls_url)" || die "cannot read state (see the error above)"
  gw_ip="$(tfo gateway_ilb_ip)" || die "cannot read state (see the error above)"
  printf '\n%-22s %s\n' "project" "$PROJECT_ID ($REGION)"
  printf '%-22s %s\n' "gateway" "${gw_url:-not deployed} -> ${gw_ip:+$gw_ip, TCP port 443}"
  printf '%-22s %s\n' "network" "$(network_line)"
  local svc; svc="$(gcloud run services list --project "$PROJECT_ID" --region "$REGION" \
    --filter='metadata.name~gateway' --format='value(metadata.name,status.conditions[0].status)' 2>/dev/null | head -1)"
  printf '%-22s %s\n' "gateway service" "${svc:-not found}"
  printf '%-22s %s\n' "registered devices" "$(tfo fleet | python3 -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}") or {}; print(", ".join(d.get("devices", [])) or "-")')"
  echo; echo "budgets (billing account $BILLING_ACCOUNT):"
  local pnum; pnum="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)' 2>/dev/null || true)"
  gcloud billing budgets list --billing-account "$BILLING_ACCOUNT" --billing-project "$PROJECT_ID" \
    --filter="displayName~^agy- AND budgetFilter.projects:projects/${pnum:-0}" --format='table(displayName,amount.specifiedAmount.units:label=AMOUNT,amount.specifiedAmount.currencyCode:label=CUR,thresholdRules.thresholdPercent.list():label=ALERTS)' 2>/dev/null || warn "cannot list budgets"
  echo; echo "device kits (device | persona | os | owner | certificate):"
  python3 "$POC/poc_kit.py" status "$DEVICES_CSV" --out "$KIT"
}

do_destroy() {
  [[ -f "$CONF" ]] || die "no POC deployed from this checkout ($CONF missing)"
  warn "This removes the POC cloud resources of $PROJECT_ID (installer --destroy asks for its own confirmation)."
  "$ROOT/install.sh" --config "$CONF" --destroy
  local a; read -r -p "Also delete the device kits and keys (${KIT#$ROOT/}/, poc/.state/certs)? (yes/no): " a
  if [[ "$a" == "yes" ]]; then
    shred_keys "$CERTS"/*.key "$KIT"/*/device.key
    rm -rf "$KIT" "$CERTS" "$TFVARS"
    log "kits, keys and the device registry file removed"
  fi
}

case "$MODE" in
  install) do_install ;;
  status)  do_status ;;
  destroy) do_destroy ;;
esac
