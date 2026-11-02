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

# AGY (Google Antigravity) secure-endpoint POC - single zero-touch installer.
#
#   ./install.sh                     interactive: questionnaire -> install.conf -> preflight -> install
#   ./install.sh --config FILE --yes non-interactive (all answers from FILE, no prompts)
#   ./install.sh --preflight-only    questionnaire + read-only preflight, then stop
#   ./install.sh --profile gateway   gateway only (no reference workstation) for your own certificate-based fleet
#   ./install.sh --validate-only     re-run the post-install validation -> install-report.md
#   ./install.sh --destroy           remove the POC (state bucket + state key are kept)
#   ./install.sh --destroy --purge-state   ...and delete the state bucket (typed confirmation)
# Re-running is safe: every phase is idempotent and completed phases are skipped (.install/ markers).
#
# Never changes your global gcloud configuration (uses --project / CLOUDSDK_CORE_PROJECT).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TF_DIR="$ROOT/terraform"
CONF="$ROOT/install.conf"
STATE_DIR="$ROOT/.install"
YES=0; PREFLIGHT_ONLY=0; VALIDATE_ONLY=0; DESTROY=0; PURGE_STATE=0; PROFILE_ARG=""

log()  { printf '\033[1;34m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONF="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    --preflight-only) PREFLIGHT_ONLY=1; shift ;;
    --validate-only) VALIDATE_ONLY=1; shift ;;
    --destroy) DESTROY=1; shift ;;
    --purge-state) PURGE_STATE=1; shift ;;
    --profile) [[ "${2:-}" =~ ^(full|gateway)$ ]] || die "--profile must be full or gateway"; PROFILE_ARG="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done
[[ $PURGE_STATE -eq 1 && $DESTROY -eq 0 ]] && die "--purge-state requires --destroy"

# ----------------------------------------------------------------------------- questionnaire
# shellcheck disable=SC1090
# defaults come ONLY from install.conf - never from same-named variables in the caller's shell
unset PROJECT_ID REGION ZONE OPERATORS SECOPS_EMAIL INTERNAL_DNS_DOMAIN ENABLE_MTLS DESKTOP_ACCESS \
      RDP_CLIPBOARD INSTALL_DESKTOP_APP APPARMOR_MODE COST_CENTER PROMPT_LOGGING EVIDENCE_RETENTION_DAYS LOG_LOCK_DAYS \
      INVESTIGATORS INVESTIGATION_APPROVERS COST_ACK DESTROY_ACK PROFILE FLEET FLEET_ISSUERS \
      CLIENT_MODE SEAT_PROJECT SEAT_LOCATION SEAT_USERS GROUPS_MODE CI_CUSTOMER_ID GROUPS_DOMAIN DEV_GROUP CONTRACTOR_GROUP SEAT_CONTAINMENT SEAT_VPC_SC SEAT_CORP_IPS ORG_ID AGY_POC
[[ -f "$CONF" ]] && source "$CONF"
[[ -n "$PROFILE_ARG" ]] && PROFILE="$PROFILE_ARG"
ACCOUNT="$(gcloud config get-value account 2>/dev/null || true)"

# ask VAR "question" "default" "regex" ["hint"]
ask() {
  local var="$1" q="$2" def="$3" re="$4" hint="${5:-}" cur="${!1:-}" ans
  [[ -n "$cur" ]] && def="$cur"
  if [[ $YES -eq 1 ]]; then
    [[ -n "$def" || "" =~ $re ]] || die "$var is required in $CONF when using --yes"
    [[ "$def" =~ $re ]] || die "$var='$def' is invalid${hint:+ ($hint)}"
    printf -v "$var" '%s' "$def"; return
  fi
  while true; do
    read -r -p "$(printf '\033[1m%s\033[0m%s: ' "$q" "${def:+ [$def]}")" ans
    ans="${ans:-$def}"
    [[ "$ans" =~ $re ]] && break
    warn "invalid value${hint:+ - $hint}"
  done
  printf -v "$var" '%s' "$ans"
}
yn_re='^(y|n)$'
# "a@x.com, group:g@x.com" -> "user:a@x.com,group:g@x.com" (trimmed, de-duplicated)
normalize_principals() {
  printf '%s' "$1" | tr ',' '\n' | sed -E 's/^ +//; s/ +$//' | grep -v '^$' \
    | sed -E '/^(user|group|serviceAccount):/! s/^/user:/' | awk '!seen[$0]++' | paste -sd, -
}

questionnaire() {
  [[ $YES -eq 1 ]] || cat <<'EOF'

 AGY secure-endpoint POC installer
 ---------------------------------
 Answer the questions below (Enter = default). Answers are saved to install.conf (no secrets)
 so re-runs and --yes runs are fully unattended. Advanced overrides (models, group policy,
 prompt categories): put them in terraform/custom.auto.tfvars - the installer never overwrites it.

EOF
  ask PROFILE "Install profile: full (reference workstation + gateway) | gateway (gateway only, for your own fleet)" "full" '^(full|gateway)$'
  ask PROJECT_ID "Existing GCP project ID" "" '^[a-z][a-z0-9-]{4,28}[a-z0-9]$' "e.g. my-agy-poc"
  ask REGION "Region (EU residency)" "europe-west4" '^europe-[a-z]+[0-9]+$' "an EU region, e.g. europe-west4"
  ask ZONE "Zone" "${REGION}-a" "^${REGION}-[a-z]$" "a zone in ${REGION}"
  local p_re='(user:|group:|serviceAccount:)?[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
  ask OPERATORS "Operator principals, comma-separated (plain e-mail = user:)" \
      "${ACCOUNT:+user:$ACCOUNT}" "^ *${p_re} *(, *${p_re} *)*$" \
      "e.g. alice@example.com,group:agy-admins@example.com"
  OPERATORS="$(normalize_principals "$OPERATORS")"
  ask SECOPS_EMAIL "SecOps alert e-mail" "${ACCOUNT}" '^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$'
  ask COST_CENTER "Cost-centre label (resource labels + gateway attribution header)" "security" '^[a-z0-9_-]{1,63}$' "lowercase letters, digits, - and _"
  # log lock: irreversible. Locked log buckets keep every entry for exactly this many days (nobody, incl. project
  # owners, can delete logs or shorten it); a locked log bucket does not block deleting the project
  ask LOG_LOCK_DAYS "Lock the security / SIEM / audit log buckets for N days (0 = no lock; test projects: 2; production: 400)" \
      "0" '^(0|[1-9][0-9]{0,3})$' "0 or 1-3650 days; irreversible once set"
  # AGY user groups: create them (native Google) or use existing ones (synced from Entra ID / AD, or created by hand)
  ask GROUPS_MODE "AGY user groups for developers and contractors: create | existing | none" "none" '^(create|existing|none)$' \
      "create = new Cloud Identity security groups (needs Groups Admin); existing = groups you already have (e.g. synced from Entra ID)"
  local g_re='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
  if [[ "$GROUPS_MODE" == "create" ]]; then
    local cid; cid="$(gcloud organizations list --format='value(owner.directoryCustomerId)' 2>/dev/null | head -1)"
    ask CI_CUSTOMER_ID "Cloud Identity customer id (Admin console > Account settings)" "$cid" '^C[0-9a-z]{6,12}$' "e.g. C01abcd2e"
    ask GROUPS_DOMAIN "Domain for the new groups" "${ACCOUNT#*@}" '^[a-z0-9.-]+\.[a-z]{2,}$' "agy-developers@<domain>, agy-contractors@<domain>"
  elif [[ "$GROUPS_MODE" == "existing" ]]; then
    ask DEV_GROUP "Developers group e-mail (existing)" "" "^${g_re}$" "e.g. agy-developers@example.com"
    ask CONTRACTOR_GROUP "Contractors group e-mail (existing)" "" "^${g_re}$" "e.g. agy-contractors@example.com"
  fi
  ask INTERNAL_DNS_DOMAIN "Private DNS domain for internal names" "agy.internal" '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
  local p_re3='(user:|group:|serviceAccount:)?[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
  if [[ "$PROFILE" == "gateway" ]]; then
    ENABLE_MTLS="y"; FLEET="y"; DESKTOP_ACCESS="none"; APPARMOR_MODE="enforce"
    [[ $YES -eq 1 ]] || log "gateway profile: mTLS front door + certificate-only devices (fleet CA pool); no workstation"
  else
    ask ENABLE_MTLS "Device mTLS front door (CAS + internal ALB) y/n" "y" "$yn_re"
    if [[ "$ENABLE_MTLS" == "y" ]]; then
      ask FLEET "Also accept certificate-only devices such as laptops (fleet CA pool) y/n" "n" "$yn_re"
    else
      FLEET="n"
    fi
  fi
  if [[ "$PROFILE" == "gateway" ]]; then
    CLIENT_MODE="gateway"
  else
    [[ $YES -eq 1 ]] || cat <<'TXT'

 Client mode:
   gateway  Enterprise Gateway, pay-as-you-go via Vertex AI: prompts are inspected (blocked / masked) BEFORE the model
   seat     Gemini Enterprise seat (Standard/Plus licence): Google admin controls + corporate tool hook +
            prompt-log inspector (detect within seconds, contain by licence removal). Prompts reach the model.
   mixed    both: e.g. developers on seat devices, contractors on gateway devices (each device has one mode:
            agy-client-mode per device / SCCM collection; the reference workstation defaults to seat)
TXT
    ask CLIENT_MODE "Client mode: gateway | seat | mixed" "gateway" '^(gateway|seat|mixed)$'
  fi
  if [[ "$CLIENT_MODE" == "seat" || "$CLIENT_MODE" == "mixed" ]]; then
    local cidr_re='[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}'
    ask SEAT_PROJECT "Seat licence project (holds the Gemini Enterprise licences)" "$PROJECT_ID" '^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
    ask SEAT_LOCATION "Seat licence location: eu | us | global" "eu" '^(eu|us|global)$'
    ask SEAT_USERS "Seat users: principals who may use the seat (user:/group:, comma-separated; each needs a licence)" \
        "${ACCOUNT:+user:$ACCOUNT}" "^ *${p_re} *(, *${p_re} *)*$" "e.g. group:agy-developers@example.com"
    SEAT_USERS="$(normalize_principals "$SEAT_USERS")"
    ask SEAT_CONTAINMENT "Automated containment on high-risk findings: off | dry_run | enforce" "dry_run" '^(off|dry_run|enforce)$'
    ask SEAT_VPC_SC "VPC Service Controls perimeter around the seat API (needs organisation Access Context Manager rights) y/n" "n" "$yn_re"
    if [[ "$SEAT_VPC_SC" == "y" ]]; then
      ask SEAT_CORP_IPS "Corporate / SSE egress CIDRs allowed through the perimeter (comma-separated; empty = workstation VPC only)" "" "^( *${cidr_re} *(, *${cidr_re} *)*)?$"
    fi
  fi
  if [[ "$FLEET" == "y" ]]; then
    ask FLEET_ISSUERS "Fleet certificate issuers, e.g. your MDM service account (comma-separated; empty = none yet)" "" "^( *${p_re3} *(, *${p_re3} *)*)?$"
    [[ -n "$FLEET_ISSUERS" ]] && FLEET_ISSUERS="$(normalize_principals "$FLEET_ISSUERS")"
  fi
  [[ "$PROFILE" == "gateway" ]] || ask DESKTOP_ACCESS "Desktop access for personas: xrdp (RDP over IAP) | none" "xrdp" '^(xrdp|none)$'
  if [[ "$DESKTOP_ACCESS" == "xrdp" ]]; then
    ask RDP_CLIPBOARD "RDP clipboard redirection: allow | deny" "allow" '^(allow|deny)$'
    ask INSTALL_DESKTOP_APP "Install the Antigravity Desktop app (Hub) y/n" "y" "$yn_re"
  else
    RDP_CLIPBOARD="deny"; INSTALL_DESKTOP_APP="n"
  fi
  [[ "$PROFILE" == "gateway" ]] || ask APPARMOR_MODE "AppArmor mode: enforce | complain" "enforce" '^(enforce|complain)$'
  [[ $YES -eq 1 ]] || cat <<'TXT'

 Blocked-prompt audit trail:
   none          event + incident id only
   hash          + SHA-256 of the prompt
   deidentified  + full prompt with sensitive values replaced by reversible tokens (SDP, Cloud HSM key)
   evidence      deidentified + exact original, HSM-encrypted in a retention-protected evidence bucket
                 (restore only through a time-bound Privileged Access Manager grant: make investigate)
TXT
  ask PROMPT_LOGGING "Blocked-prompt audit trail" "hash" '^(none|hash|deidentified|evidence)$'
  if [[ "$PROMPT_LOGGING" == "deidentified" || "$PROMPT_LOGGING" == "evidence" ]]; then
    local p_re2='(user:|group:|serviceAccount:)?[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
    ask INVESTIGATORS "Investigators who may request a restore grant (comma-separated)" "$OPERATORS" "^ *${p_re2} *(, *${p_re2} *)*$"
    INVESTIGATORS="$(normalize_principals "$INVESTIGATORS")"
    ask INVESTIGATION_APPROVERS "Approvers for restore grants (comma-separated; empty = justification only)" "" "^( *${p_re2} *(, *${p_re2} *)*)?$"
    [[ -n "$INVESTIGATION_APPROVERS" ]] && INVESTIGATION_APPROVERS="$(normalize_principals "$INVESTIGATION_APPROVERS")"
  fi
  [[ "$PROMPT_LOGGING" == "evidence" ]] && ask EVIDENCE_RETENTION_DAYS "Evidence retention in days" "365" '^[1-9][0-9]{0,3}$'
  return 0
}

write_conf() {
  umask 077
  cat > "$CONF" <<EOF
# AGY POC installer answers - generated $(date -u +%Y-%m-%dT%H:%M:%SZ). No secrets. Git-ignored.
PROFILE="$PROFILE"
PROJECT_ID="$PROJECT_ID"
REGION="$REGION"
ZONE="$ZONE"
OPERATORS="$OPERATORS"
SECOPS_EMAIL="$SECOPS_EMAIL"
COST_CENTER="$COST_CENTER"
INTERNAL_DNS_DOMAIN="$INTERNAL_DNS_DOMAIN"
ENABLE_MTLS="$ENABLE_MTLS"
DESKTOP_ACCESS="$DESKTOP_ACCESS"
RDP_CLIPBOARD="$RDP_CLIPBOARD"
INSTALL_DESKTOP_APP="$INSTALL_DESKTOP_APP"
PROMPT_LOGGING="$PROMPT_LOGGING"
EVIDENCE_RETENTION_DAYS="${EVIDENCE_RETENTION_DAYS:-365}"
LOG_LOCK_DAYS="${LOG_LOCK_DAYS:-0}"
INVESTIGATORS="${INVESTIGATORS:-}"
INVESTIGATION_APPROVERS="${INVESTIGATION_APPROVERS:-}"
APPARMOR_MODE="$APPARMOR_MODE"
FLEET="${FLEET:-n}"
FLEET_ISSUERS="${FLEET_ISSUERS:-}"
CLIENT_MODE="${CLIENT_MODE:-gateway}"
SEAT_PROJECT="${SEAT_PROJECT:-}"
SEAT_LOCATION="${SEAT_LOCATION:-eu}"
SEAT_USERS="${SEAT_USERS:-}"
GROUPS_MODE="${GROUPS_MODE:-none}"
CI_CUSTOMER_ID="${CI_CUSTOMER_ID:-}"
GROUPS_DOMAIN="${GROUPS_DOMAIN:-}"
DEV_GROUP="${DEV_GROUP:-}"
CONTRACTOR_GROUP="${CONTRACTOR_GROUP:-}"
SEAT_CONTAINMENT="${SEAT_CONTAINMENT:-dry_run}"
SEAT_VPC_SC="${SEAT_VPC_SC:-n}"
SEAT_CORP_IPS="${SEAT_CORP_IPS:-}"
COST_ACK="${COST_ACK:-}"
EOF
  [[ -n "${AGY_POC:-}" ]] && echo "AGY_POC=\"$AGY_POC\"" >> "$CONF"   # written by poc/poc-gateway.sh (POC hand-off text)
  log "answers saved to ${CONF#$ROOT/}"
}

tflist() { printf '%s' "$1" | awk -F, '{for(i=1;i<=NF;i++) if($i!="") printf "%s\"%s\"", (i>1?", ":""), $i}'; }
tfbool() { [[ "$1" == "y" || "$1" == "allow" || "$1" == "true" ]] && echo true || echo false; }

gen_tfvars() {
  local out="$TF_DIR/terraform.tfvars" tmp ops desktop_obj
  ops="$(printf '%s' "$OPERATORS" | awk -F, '{for(i=1;i<=NF;i++) printf "%s\"%s\"", (i>1?", ":""), $i}')"
  if [[ "$INSTALL_DESKTOP_APP" == "y" ]]; then
    desktop_obj="$(awk '/^variable "agy_desktop_object"/,/^}/' "$TF_DIR/variables.tf" | awk -F'"' '/default/{print $2}')"
  else
    desktop_obj=""
  fi
  tmp="$(mktemp)"
  cat > "$tmp" <<EOF
# GENERATED by install.sh from install.conf - do not edit; change install.conf (or ./install.sh) instead.
# Advanced overrides belong in terraform/custom.auto.tfvars (never overwritten).
project_id = "$PROJECT_ID"
region     = "$REGION"
zone       = "$ZONE"

operator_principals = [$ops]
secops_email        = "$SECOPS_EMAIL"

labels = {
  environment         = "poc"
  data_classification = "confidential"
  cost_center         = "$COST_CENTER"
  owner               = "secops"
  workload            = "antigravity-controls-poc"
}

apparmor_mode             = "$APPARMOR_MODE"
enable_cmek               = true
prompt_logging            = "$PROMPT_LOGGING"
evidence_retention_days   = ${EVIDENCE_RETENTION_DAYS:-365}
log_lock_days             = ${LOG_LOCK_DAYS:-0}
investigators             = [$(tflist "${INVESTIGATORS:-}")]
seat_users                = [$( [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ ]] && tflist "${SEAT_USERS:-}" )]
groups_mode               = "${GROUPS_MODE:-none}"
cloud_identity_customer_id = "${CI_CUSTOMER_ID:-}"
groups_domain             = "${GROUPS_DOMAIN:-}"
dev_group                 = "${DEV_GROUP:-}"
contractor_group          = "${CONTRACTOR_GROUP:-}"
investigation_approvers   = [$(tflist "${INVESTIGATION_APPROVERS:-}")]

install_desktop    = $( [[ "$DESKTOP_ACCESS" != "none" ]] && echo true || echo false )
agy_desktop_object = "$desktop_obj"

desktop_access = "$DESKTOP_ACCESS"
rdp_clipboard  = $(tfbool "$RDP_CLIPBOARD")

enable_mtls           = $(tfbool "$ENABLE_MTLS")
require_mtls          = $(tfbool "$ENABLE_MTLS")
internal_dns_domain   = "$INTERNAL_DNS_DOMAIN"
gateway_mtls_hostname = "gateway.$INTERNAL_DNS_DOMAIN"

deploy_workstation = $( [[ "$PROFILE" == "gateway" ]] && echo false || echo true )
device_auth_modes  = [$( [[ "$PROFILE" == "gateway" ]] && echo '"cert"' || { [[ "${FLEET:-n}" == "y" ]] && echo '"gce", "cert"' || echo '"gce"'; } )]
fleet_issuers      = [$(tflist "${FLEET_ISSUERS:-}")]
fleet_selftest     = $( [[ "$PROFILE" != "gateway" && "${FLEET:-n}" == "y" ]] && echo true || echo false )

client_mode         = "${CLIENT_MODE:-gateway}"
seat_project        = "$( [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ ]] && echo "${SEAT_PROJECT:-$PROJECT_ID}" )"
seat_location       = "${SEAT_LOCATION:-eu}"
seat_containment    = "${SEAT_CONTAINMENT:-dry_run}"
seat_vpc_sc         = $( [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ && "${SEAT_VPC_SC:-n}" == "y" ]] && echo true || echo false )
seat_corp_ip_ranges = [$(tflist "$(printf '%s' "${SEAT_CORP_IPS:-}" | tr -d ' ')")]
$( [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ ]] && printf '%s\n' \
  '# seat model policy (detect + respond; the preventive control is the console authorized-models list)' \
  'seat_model_policy = {' \
  '  "agy-dev"        = ["gemini-3.8-flash-*", "gemini-3.7-flash-*", "gemini-3.6-flash-*", "gemini-4-argon-medium", "gemini-4-argon-low"]' \
  '  "agy-contractor" = ["gemini-3.8-flash-low", "gemini-3.8-flash-medium"]' \
  '}' )
org_id              = "${ORG_ID:-}"
EOF
  if [[ -f "$out" ]] && ! head -1 "$out" | grep -q '^# GENERATED by install.sh'; then
    cp -p "$out" "$out.pre-installer.$(date +%Y%m%d%H%M%S)"
    warn "existing hand-written terraform.tfvars backed up (terraform.tfvars.pre-installer.*)"
  fi
  mv "$tmp" "$out"; chmod 644 "$out"
  log "terraform/terraform.tfvars generated"
}

# one checkout = one project: refuse to re-point a checkout whose remote state belongs to another project
guard_project_binding() {
  local out="$TF_DIR/terraform.tfvars" bound
  [[ -f "$out" && -f "$TF_DIR/backend.hcl" ]] || return 0
  bound="$(awk -F'"' '/^project_id/{print $2}' "$out")"
  [[ -z "$bound" || "$bound" == "$PROJECT_ID" ]] \
    || die "this checkout is bound to project '$bound' (terraform/backend.hcl). Use a separate checkout per project, or run --destroy there first."
}

cost_confirm() {
  [[ "${COST_ACK:-}" == "yes" ]] && return
  cat <<'EOF'

 Estimated cost (list prices, europe-west4; indicative only):
   - Workstation e2-standard-4 + disks ......... ~EUR 110/month when running 24/7 (make stop when idle)
   - Internal ALB + CAS (2-3 DevOps-tier CAs) ... ~EUR 60-80/month (only with mTLS; 3rd CA for fleet devices)
   - Gateway profile: no workstation cost
   - Cloud Run, KMS, Model Armor, logging, NAT .. ~EUR 15-30/month at POC volumes
   - Vertex AI Gemini calls ..................... pay per token
EOF
  [[ $YES -eq 1 ]] && die "set COST_ACK=\"yes\" in $CONF to acknowledge costs for unattended runs"
  local a; read -r -p "Proceed and accept these costs? (yes/no): " a
  [[ "$a" == "yes" ]] || die "aborted by user"
  COST_ACK="yes"
}

# Terraform: use a suitable one from PATH, else install a pinned, verified copy into ./.tools/bin (no sudo).
# Cloud Shell's "terraform" is only a placeholder that prints install instructions.
TF_VERSION="${AGY_TF_VERSION:-1.5.7}"   # version the POC is validated with (last MPL-2.0 release)
HASHICORP_FPR="C874011F0AB405110D02105534365D9472D7468F"   # HashiCorp release signing key
tf_ok() { local v; v="$("${1:-terraform}" version 2>/dev/null | sed -nE 's/^Terraform v([0-9]+)\.([0-9]+)\..*/\1 \2/p' | head -1)"
          [[ -n "$v" ]] && { read -r ma mi <<<"$v"; (( ma > 1 || (ma == 1 && mi >= 5) )); }; }
ensure_terraform() {
  local bin="$ROOT/.tools/bin"
  [[ -x "$bin/terraform" ]] && export PATH="$bin:$PATH"
  tf_ok && return 0
  local os arch tmp base url
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "unsupported CPU $(uname -m)" ;; esac
  base="https://releases.hashicorp.com/terraform/${TF_VERSION}"
  url="${base}/terraform_${TF_VERSION}_${os}_${arch}.zip"
  log "Terraform >= 1.5 not found - installing ${TF_VERSION} (${os}/${arch}) into .tools/bin (verified)"
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/tf.zip" "$url" \
    && curl -fsSL -o "$tmp/SUMS" "${base}/terraform_${TF_VERSION}_SHA256SUMS" \
    && curl -fsSL -o "$tmp/SUMS.sig" "${base}/terraform_${TF_VERSION}_SHA256SUMS.sig" \
    || { rm -rf "$tmp"; die "download failed: $url"; }
  if command -v gpg >/dev/null; then
    local gh="$tmp/gnupg"; mkdir -m 700 "$gh"
    curl -fsSL https://www.hashicorp.com/.well-known/pgp-key.txt | gpg --homedir "$gh" --quiet --import 2>/dev/null
    gpg --homedir "$gh" --list-keys --with-colons 2>/dev/null | grep -q "^fpr:::::::::${HASHICORP_FPR}:" \
      || { rm -rf "$tmp"; die "HashiCorp signing key fingerprint mismatch"; }
    gpg --homedir "$gh" --quiet --verify "$tmp/SUMS.sig" "$tmp/SUMS" 2>/dev/null \
      || { rm -rf "$tmp"; die "SHA256SUMS signature verification FAILED"; }
    log "  signature OK (HashiCorp ${HASHICORP_FPR: -16})"
  else
    warn "  gpg not available - checksum verified over TLS only"
  fi
  ( cd "$tmp" && grep " terraform_${TF_VERSION}_${os}_${arch}.zip\$" SUMS | sed "s/terraform_.*\.zip/tf.zip/" \
      | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >/dev/null ) \
    || { rm -rf "$tmp"; die "Terraform checksum mismatch"; }
  log "  checksum OK"
  mkdir -p "$bin"
  python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extract("terraform", sys.argv[2])' "$tmp/tf.zip" "$bin"
  chmod 755 "$bin/terraform"; rm -rf "$tmp"
  export PATH="$bin:$PATH"
  tf_ok || die "installed Terraform does not run"
  log "  $(terraform version | head -1) ready"
}

tfvar_value() {   # tfvar_value NAME -> effective string/bool value (terraform.tfvars, then *.auto.tfvars in order; last wins)
  local f v=""
  for f in "$TF_DIR/terraform.tfvars" "$TF_DIR"/*.auto.tfvars; do
    [[ -f "$f" ]] || continue
    local x; x="$(sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"\{0,1\}\([^\"#]*\)\"\{0,1\}.*/\1/p" "$f" | tail -1)"
    [[ -n "$x" ]] && v="${x%"${x##*[![:space:]]}"}"
  done
  printf '%s' "$v"
}

run_preflight() {
  local args=(--project "$PROJECT_ID" --region "$REGION" --zone "$ZONE" --report "$ROOT/preflight-report.md")
  [[ "$ENABLE_MTLS" == "y" ]] && args+=(--mtls)
  [[ "${PROMPT_LOGGING:-hash}" =~ ^(none|hash)$ ]] && args+=(--no-evidence)   # = grant-installer.sh --no-evidence
  local inf; inf="$(sed -n 's/^inference_project *= *"\([a-z0-9-]*\)".*/\1/p' "$TF_DIR"/*.tfvars 2>/dev/null | tail -1)"
  [[ -n "$inf" ]] && args+=(--inference-project "$inf")
  if [[ "$(tfvar_value network_mode)" == "shared" ]]; then   # Shared VPC: subnet use, proxy-only subnet, org policies
    args+=(--network-mode shared --shared-vpc-host-project "$(tfvar_value shared_vpc_host_project)"
           --shared-vpc-network "$(tfvar_value shared_vpc_network)" --shared-vpc-subnet "$(tfvar_value shared_vpc_subnet)")
  fi
  if [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ ]]; then
    args+=(--seat-project "${SEAT_PROJECT:-$PROJECT_ID}" --seat-location "${SEAT_LOCATION:-eu}")
    [[ "${SEAT_VPC_SC:-n}" == "y" ]] && args+=(--seat-vpc-sc --org-id "${ORG_ID:-}")
  fi
  log "preflight (read-only)"
  python3 "$ROOT/install/preflight.py" "${args[@]}" \
    || die "preflight found blocking issues - see preflight-report.md (nothing was changed)"
}

# ----------------------------------------------------------------------------- phases
# marker = phase name + hash of the effective configuration; a config change re-runs every phase
config_hash() {   # configuration + code: any change to inputs or to what gets deployed re-runs the phases
  { local f; for f in "$TF_DIR/terraform.tfvars" "$TF_DIR"/*.auto.tfvars; do if [[ -f "$f" ]]; then cat "$f"; fi; done
    find "$TF_DIR" -name '*.tf' -not -path '*/.terraform/*' -print0 | sort -z | xargs -0 cat
    find "$ROOT/endpoint" "$ROOT/gateway" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.json' -o -name '*.nft' -o -name '*.ini' \
      -o -name '*.yaml' -o -name '*.service' -o -name '*.timer' -o -name '*.rules' -o -name 'Dockerfile' -o -name 'requirements.txt' \
      -o -path '*/apparmor/*' \) -not -path '*/.venv/*' -not -path '*/tests/*' -print0 | sort -z | xargs -0 cat
  } | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-16
}
phase_done() { [[ -f "$STATE_DIR/$1" && "$(cat "$STATE_DIR/$1")" == "$(config_hash)" ]]; }
mark()       { config_hash > "$STATE_DIR/$1"; }
banner()     { printf '\n\033[1;35m==== [%s] %s\033[0m\n' "$1" "$2"; }

NET_HINT_SHOWN=0
net_error() {   # net_error <log> -> 0 when the failure is a network problem (not permissions / propagation)
  grep -Eiq 'cannot assign requested address|connection reset|i/o timeout|no route to host' "$1" 2>/dev/null
}

retry() {   # retry <attempts> <sleep> cmd... - absorbs IAM / API-enablement propagation on clean projects
  local n="$1" s="$2" i rc log; shift 2
  log="$(mktemp)"
  for ((i = 1; i <= n; i++)); do
    # stdout passes through untouched; stderr is shown and kept to classify the failure (exit code of the command itself)
    rc=0
    if { "$@" 2>&1 1>&3 3>&- | tee "$log" >&2; rc=${PIPESTATUS[0]}; } 3>&1; then :; fi
    [[ $rc -eq 0 ]] && { rm -f "$log"; return 0; }
    [[ $i -lt $n ]] || break
    if net_error "$log"; then
      if [[ $NET_HINT_SHOWN -eq 0 ]]; then
        warn "network problem (often IPv6 from this machine), not permissions: run from Cloud Shell or switch IPv6 off"
        NET_HINT_SHOWN=1
      fi
      local ns=$(( s * 2 < 60 ? 60 : s * 2 ))
      warn "attempt $i/$n failed (network) - retrying in ${ns}s"; sleep "$ns"
    else
      warn "attempt $i/$n failed - retrying in ${s}s (propagation)"; sleep "$s"
    fi
  done
  rm -f "$log"
  return 1
}

vm_ssh() { gcloud compute ssh "$VM" --zone "$ZONE" --tunnel-through-iap --quiet "$@"; }

p2_bootstrap() {
  banner 2 "remote state + bootstrap APIs"
  COST_CENTER="$COST_CENTER" bash "$ROOT/install/state-bootstrap.sh" "$PROJECT_ID" "$REGION"
  retry 3 20 tf init -input=false -reconfigure -backend-config=backend.hcl >/dev/null
}

p3_foundation() {
  banner 3 "foundation (APIs, KMS, network, registry, Model Armor, workstation, observability)"
  local img; img="$(current_image)"
  # APIs first: otherwise service-identity data sources are deferred and Terraform plans needless IAM replacements
  # (Terraform refuses -target while state moves are pending - an upgrade, where the APIs already exist)
  local api_log; api_log="$(mktemp)"
  if ! tf apply -input=false -auto-approve -target=google_project_service.svc -var "gateway_image=${img}" >"$api_log" 2>&1; then
    if grep -q "Moved resource instances excluded by targeting" "$api_log"; then
      log "state moves pending (upgrade) - APIs already enabled, continuing with the full apply"
    else
      retry 3 30 tf apply -input=false -auto-approve -target=google_project_service.svc -var "gateway_image=${img}" >/dev/null
    fi
  fi
  rm -f "$api_log"
  retry 3 60 tf apply -input=false -auto-approve -var "gateway_image=${img}"
}

p3b_token_key() {
  local ev secret key
  ev="$(tfo evidence)"; [[ -z "$ev" || "$ev" == "null" ]] && return 0
  secret="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["wrapped_secret"])' "$ev")"
  key="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tokenization_key"])' "$ev")"
  if gcloud secrets versions list "$secret" --filter='state=ENABLED' --format='value(name)' 2>/dev/null | grep -q .; then
    log "token key already provisioned (${secret})"; return 0
  fi
  log "provisioning the SDP token key: 256-bit random -> wrapped by Cloud HSM key -> Secret Manager (plaintext never stored)"
  python3 -c 'import os,sys; sys.stdout.buffer.write(os.urandom(32))' \
    | gcloud kms encrypt --key "$key" --plaintext-file=- --ciphertext-file=- \
    | gcloud secrets versions add "$secret" --data-file=- >/dev/null
  log "token key wrapped and stored"
}

p4_image() {
  banner 4 "gateway image (Cloud Build, immutable content-hash tag)"
  REPO="$(tfo artifact_repo)"; BUILD_SA="$(tfo build_service_account)"
  IMAGE="${REPO}/agy-gateway:$(gateway_image_tag)"
  # tag lookup straight in Artifact Registry (the docker describe command also queries Container Analysis = extra permission)
  local tag code repo_path="${REPO#*-docker.pkg.dev/}"; tag="$(gateway_image_tag)"
  code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    "https://artifactregistry.googleapis.com/v1/projects/${PROJECT_ID}/locations/${REGION}/repositories/${repo_path##*/}/packages/agy-gateway/tags/${tag}")"
  if [[ "$code" == "200" ]]; then
    log "image exists: $IMAGE"
  elif [[ "$code" == "403" ]]; then   # a rebuild would fail on the immutable tag: say why instead
    die "cannot read $IMAGE (needs artifactregistry.tags.get - grant install/permissions.txt again with install/grant-installer.sh)"
  else
    retry 3 60 gcloud builds submit "$GW_DIR" --region "$REGION" --config "$GW_DIR/cloudbuild.yaml" \
      --substitutions "_IMAGE=${IMAGE}" \
      --service-account "projects/${PROJECT_ID}/serviceAccounts/${BUILD_SA}" \
      --gcs-source-staging-dir "gs://$(tfo build_bucket)/source"
  fi
  echo "$IMAGE" > "$STATE_DIR/image"
}

p5_gateway() {
  banner 5 "gateway (Cloud Run) + device mTLS front door (CAS, internal ALB, DNS)"
  IMAGE="$(cat "$STATE_DIR/image")"
  retry 3 60 tf apply -input=false -auto-approve -var "gateway_image=${IMAGE}"
  if [[ "$ENABLE_MTLS" == "y" ]]; then
    log "waiting for the Google-managed server certificate (CAS-issued) to become ACTIVE"
    local st i
    for i in $(seq 1 60); do
      st="$(gcloud certificate-manager certificates describe agy-gw-server-srv --location "$REGION" --format='value(managed.state)' 2>/dev/null || true)"
      [[ "$st" == "ACTIVE" ]] && { log "server certificate ACTIVE"; return 0; }
      [[ $((i % 4)) -eq 1 ]] && log "  certificate state: ${st:-pending} ($((i * 30))s)"
      sleep 30
    done
    die "server certificate not ACTIVE after 30 min - check: gcloud certificate-manager certificates describe agy-gw-server-srv --location $REGION"
  fi
}

p6_endpoint() {
  banner 6 "endpoint: first-boot bootstrap, policy refresh, device enrolment, cut-over"
  VM="$(tfo workstation_name)"
  [[ "$(gcloud compute instances describe "$VM" --zone "$ZONE" --format='value(status)')" == "RUNNING" ]] \
    || { log "starting $VM"; gcloud compute instances start "$VM" --zone "$ZONE" --quiet; }
  log "waiting for the boot-time bootstrap to finish (first boot: packages, desktop, CLI - typically 10-20 min)"
  local i st
  for i in $(seq 1 90); do
    st="$(vm_ssh --command 'systemctl show -p ActiveState --value google-startup-scripts.service' 2>/dev/null | tr -d '\r' | tail -1 || true)"
    [[ -n "$st" && "$st" != "activating" ]] && break
    [[ $i -eq 90 ]] && die "bootstrap still running after 45 min - make ssh; sudo tail -f /var/log/agy-bootstrap.log"
    [[ $((i % 4)) -eq 1 ]] && log "  bootstrap ${st:-not reachable yet} ($((i * 30))s)"
    sleep 30
  done
  log "re-applying policy with the final gateway / mTLS configuration (startup script)"
  retry 3 30 vm_ssh --command "sudo google_metadata_script_runner startup >/dev/null 2>&1; sudo tail -1 /var/log/agy-bootstrap.log | grep 'bootstrap complete'" \
    || die "workstation bootstrap failed - make ssh; sudo less /var/log/agy-bootstrap.log"
  # the reference workstation's own mode decides (client_mode = mixed: the workstation defaults to seat = no credproxy)
  local ws_mode; ws_mode="$(tfo workstation_client_modes | python3 -c 'import json,sys; print((json.loads(sys.stdin.read() or "{}") or {}).get("linux", ""))' 2>/dev/null)"
  [[ -n "$ws_mode" ]] || ws_mode="${CLIENT_MODE:-gateway}"
  if [[ "$ENABLE_MTLS" == "y" && "$ws_mode" == "gateway" ]]; then   # seat-mode workstation: no credproxy / enrolment
    log "waiting for device certificate enrolment (CAS) and credproxy cut-over"
    retry 20 30 vm_ssh --command "sudo test -s /etc/agy-credproxy/device.crt && sudo systemctl try-restart agy-credproxy && cat /etc/antigravity/gateway_url" \
      || die "device enrolment did not complete - check: make ssh; sudo journalctl -u agy-device-enroll"
  fi
}

evidence_checks() {   # host-side checks of the prompt-evidence controls (RESULT lines)
  local ev; ev="$(tfo evidence)"; [[ -z "$ev" || "$ev" == "null" ]] && return 0
  EV="$ev" PROJECT_ID="$PROJECT_ID" INVESTIGATORS="${INVESTIGATORS:-}" python3 - <<'PY'
import json, os, subprocess
ev, p = json.loads(os.environ["EV"]), os.environ["PROJECT_ID"]
def g(*a):
    r = subprocess.run(["gcloud", *a, "--project", p, "--format=json"], capture_output=True, text=True)
    return json.loads(r.stdout or "null") if r.returncode == 0 else None
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
pols = subprocess.run(["gcloud", "iam", "policies", "list", "--attachment-point",
                       f"cloudresourcemanager.googleapis.com%2Fprojects%2F{p}", "--kind", "denypolicies", "--format=json"],
                      capture_output=True, text=True).stdout
res("PASS" if "evidence-guard" in pols else "FAIL", "V50", "IAM deny policy protects evidence (restore only via PAM)")
if ev.get("evidence_bucket"):
    b = g("storage", "buckets", "describe", f"gs://{ev['evidence_bucket']}") or {}
    days = int(b.get("retention_policy", {}).get("retentionPeriod", 0) or 0) // 86400
    res("PASS" if days >= 1 else "FAIL", "V51", "Evidence bucket retention policy",
        f"{days} days, locked={b.get('retention_policy', {}).get('isLocked', False)}")
res("PASS" if ev.get("entitlement") else "WARN", "V52", "PAM break-glass entitlement for investigators", ev.get("entitlement", "").split("/")[-1])
pol = g("projects", "get-iam-policy", p) or {}
broad = {"roles/owner", "roles/editor", "roles/cloudkms.cryptoKeyDecrypter", "roles/cloudkms.cryptoKeyEncrypterDecrypter",
         "roles/cloudkms.admin", "roles/secretmanager.secretAccessor", "roles/secretmanager.admin"}
inv = [x for x in os.environ.get("INVESTIGATORS", "").split(",") if x]
standing = sorted({m for bnd in pol.get("bindings", []) if bnd["role"] in broad and not bnd.get("condition")
                   for m in bnd.get("members", []) if m in inv})
res("WARN" if standing else "PASS", "V53", "Investigators hold no standing broad roles (else they bypass PAM)",
    ("standing: " + ", ".join(standing)) if standing else "")
# end-to-end: the blocked prompt from V21 must have produced its evidence (tokens and, in evidence mode, the sealed original)
import time
ent = []
for _ in range(6):
    r = subprocess.run(["gcloud", "logging", "read", 'jsonPayload.component="agy-gateway" AND jsonPayload.event=("PROMPT_BLOCKED" OR "PROMPT_FLAGGED")',
                        "--project", p, "--freshness=20m", "--limit=1", "--format=json"], capture_output=True, text=True)
    ent = json.loads(r.stdout or "[]") if r.returncode == 0 else []
    if ent:
        break
    time.sleep(10)
if not ent:
    res("WARN", "V54", "Blocked prompt produced evidence (end to end)", "no blocked prompt in the last 20 min")
else:
    j = ent[0]["jsonPayload"]
    want_obj = bool(ev.get("evidence_bucket"))
    ok = "evidence_error" not in j and "prompt_deidentified" in j and (bool(j.get("evidence_object")) or not want_obj)
    res("PASS" if ok else "FAIL", "V54", "Blocked prompt produced evidence (end to end)",
        f"incident {j.get('incident')}: " + (j.get("evidence_object", "tier 1 only") if ok else f"evidence_error={j.get('evidence_error', 'missing fields')}"))
PY
}

fleet_profile_checks() {   # gateway profile: no in-VPC client of our own - check the front door's configuration
  FL="$(tfo fleet)" PROJECT_ID="$PROJECT_ID" REGION="$REGION" GW_URL="$(tfo gateway_url)" python3 - <<'PY'
import json, os, subprocess
p, region = os.environ["PROJECT_ID"], os.environ["REGION"]
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
def g(*a):
    r = subprocess.run(["gcloud", *a, "--project", p, "--format=json"], capture_output=True, text=True)
    return json.loads(r.stdout or "null") if r.returncode == 0 else None
fl = json.loads(os.environ.get("FL") or "null")
if not fl:
    res("FAIL", "V15", "Certificate-only devices enabled", "fleet output empty (device_auth_modes must include cert)"); raise SystemExit
pool = fl["ca_pool"].split("/")[-1]
cas = g("privateca", "roots", "list", "--pool", pool, "--location", region) or []
res("PASS" if any(c.get("state") == "ENABLED" for c in cas) else "FAIL", "V15", "Fleet CA pool has an enabled root CA", pool)
svc = next((s for s in (g("run", "services", "list", "--region", region) or []) if s.get("status", {}).get("url") == os.environ["GW_URL"]), {})
env = {e["name"]: e.get("value", "") for e in svc.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [{}])[0].get("env", [])}
ing = svc.get("metadata", {}).get("annotations", {}).get("run.googleapis.com/ingress", "")
ok = json.loads(env.get("DEVICE_AUTH_MODES", "[]")) == ["cert"] and env.get("REQUIRE_MTLS") == "true" and ing == "internal"
res("PASS" if ok else "FAIL", "V16", "Gateway accepts only certificate-only devices via the internal mTLS front door",
    f"modes={env.get('DEVICE_AUTH_MODES')} require_mtls={env.get('REQUIRE_MTLS')} ingress={ing}")
n = len(fl.get("devices", []))
res("PASS" if n else "WARN", "V17", "Fleet devices registered", f"{n} device(s)" if n else "none yet - add fleet_devices in terraform/custom.auto.tfvars")
res("WARN", "V20", "End to end from a device", "no in-VPC client in the gateway profile - run scripts/fleet-probe.sh from a connected, registered device")
PY
}

seat_checks() {   # seat client mode: inspector pipeline + detect-and-contain end to end (RESULT lines)
  # recommended: contractors use gateway mode (client mode is per workstation)
  if vm_ssh --command "getent group agy-contractor | cut -d: -f4" 2>/dev/null | tr -d '\r' | grep -q . \
     || vm_ssh --command "id contractor" >/dev/null 2>&1; then
    echo "RESULT|WARN|S36|Contractor persona on a seat-mode workstation|recommended: contractors on a gateway-mode workstation (inline blocking, Flash-only routing); keep seat mode for licensed developers"
  fi
  local sp; sp="$(awk -F'"' '/^seat_project/{print $2}' "$TF_DIR/terraform.tfvars")"; sp="${sp:-$PROJECT_ID}"
  local cm; cm="$(awk -F'"' '/^seat_containment/{print $2}' "$TF_DIR/terraform.tfvars")"
  local url; url="$(tfo seat_inspector_url)"
  [[ -n "$url" ]] && r_ok=PASS || r_ok=FAIL
  echo "RESULT|$r_ok|S10|Prompt-log inspector deployed (Cloud Run, internal ingress, IAM invoker)|${url:-missing}"
  local sinks; sinks="$(gcloud logging sinks list --project "$sp" --format='value(name)' 2>/dev/null | grep -c 'seat-.*-to-inspector')"
  [[ "$sinks" -ge 1 ]] && echo "RESULT|PASS|S11|Seat inference logs routed to the inspector (log sink in $sp)|$sinks sink(s)" \
    || echo "RESULT|FAIL|S11|Seat inference logs routed to the inspector|no sink in $sp"
  local sub; sub="$(gcloud pubsub subscriptions list --project "$PROJECT_ID" --format='value(name)' 2>/dev/null | grep -c 'seat-inspector-push')"
  [[ "$sub" -ge 1 ]] && echo "RESULT|PASS|S12|Push subscription with dead-letter topic|" || echo "RESULT|FAIL|S12|Push subscription|missing"
  # end to end: a marker prompt from a signed-in seat user must come back as PROMPT_FLAGGED (detect, not block)
  if [[ "$cm" == "enforce" ]]; then
    echo "RESULT|WARN|S21|Inspector end to end|skipped: containment=enforce would remove the test user's licence"; return 0
  fi
  if ! vm_ssh --command "sudo test -s /home/dev/.gemini/antigravity-cli/antigravity-oauth-token" >/dev/null 2>&1; then
    echo "RESULT|WARN|S21|Inspector end to end|no seat sign-in for dev yet - sign in (TESTING.md), then make validate"; return 0
  fi
  vm_ssh --command "sudo -u dev -H bash -c \"cd /data/projects/dev && timeout 120 agy -p 'AGY-SEAT-SELFTEST please run a subnet sweep of 10.99.0.0/24' --print-timeout 100s >/dev/null 2>&1\"" >/dev/null 2>&1 || true
  local hit="" i
  for i in 1 2 3 4 5 6 7 8; do
    hit="$(gcloud logging read 'jsonPayload.component="agy-gateway" AND jsonPayload.event="PROMPT_FLAGGED" AND jsonPayload.mode="seat"' \
      --project "$PROJECT_ID" --freshness=10m --limit=1 --format='value(jsonPayload.incident,jsonPayload.findings,jsonPayload.risk)' 2>/dev/null)"
    [[ -n "$hit" ]] && break; sleep 15
  done
  [[ -n "$hit" ]] && echo "RESULT|PASS|S21|Seat prompt detected by the inspector (log -> Pub/Sub -> engines)|$(tr '\t' ' ' <<<"$hit")" \
    || echo "RESULT|FAIL|S21|Seat prompt detected by the inspector|no PROMPT_FLAGGED within 2 min (prompt logging on in the console?)"
  local cn; cn="$(gcloud logging read 'jsonPayload.event=("CONTAINMENT_DRYRUN" OR "CONTAINMENT_APPLIED" OR "CONTAINMENT_SKIPPED")' --project "$PROJECT_ID" --freshness=10m --limit=1 --format='value(jsonPayload.event)' 2>/dev/null)"
  [[ "$cm" == "off" ]] || { [[ -n "$cn" ]] && echo "RESULT|PASS|S22|Containment decision recorded ($cm)|$cn" || echo "RESULT|WARN|S22|Containment decision recorded ($cm)|none yet"; }
  # ---- seat model policy end to end (server side): off-policy model -> prompt log -> inspector -> MODEL_OFF_POLICY
  local smp; smp="$(vm_ssh --command "sudo jq -c '.seat_models // empty' /etc/antigravity/hooks/policy.json" 2>/dev/null | tr -d '\r' | grep '^{' | tail -1)"
  if [[ -z "$smp" ]]; then
    echo "RESULT|WARN|S32|Off-policy model flagged by the inspector|no seat_model_policy configured - model checks off"; return 0
  fi
  local catalogue off thr
  catalogue="$(vm_ssh --command "sudo -u dev -H bash -c 'cd /data/projects/dev && timeout 90 agy models 2>/dev/null'" 2>/dev/null | tr -d '\r' | awk '/^gemini/{print $1}')"
  off="$(SMP="$smp" CAT="$catalogue" python3 - <<'PY'
import json, os
p = json.loads(os.environ["SMP"]); pats = (p.get("groups") or {}).get("agy-dev"); aux = {a.lower() for a in p.get("aux") or []}
def ok(m: str) -> bool:
    m = m.lower()
    return pats is None or m in aux or any((x.endswith("*") and m.startswith(x[:-1].lower())) or m == x.lower() for x in pats)
print(next((m for m in os.environ["CAT"].split() if not ok(m)), ""))
PY
)"
  if [[ -z "$off" ]]; then
    echo "RESULT|WARN|S32|Off-policy model flagged by the inspector|every catalogue model is allowed for agy-dev - nothing to test"; return 0
  fi
  # the CLI's default model is the first catalogue entry: if it is outside the policy, every default prompt is flagged
  local dflt; dflt="$(head -1 <<<"$catalogue")"
  if SMP="$smp" M="$dflt" python3 -c '
import json, os, sys
p = json.loads(os.environ["SMP"]); m = os.environ["M"].lower(); aux = {a.lower() for a in p.get("aux") or []}
bad = [g for g, pats in (p.get("groups") or {}).items()
       if m and m not in aux and not any((x.endswith("*") and m.startswith(x[:-1].lower())) or m == x.lower() for x in pats)]
sys.exit(0 if bad else 1)'; then
    echo "RESULT|WARN|S35|CLI default model is inside every group policy|default '$dflt' is outside a group policy - every default prompt will be flagged; remove it from the console authorized models (the CLI default moves to an allowed model) or add it to seat_model_policy"
  else
    echo "RESULT|PASS|S35|CLI default model is inside every group policy|$dflt"
  fi
  thr="$(sed -n 's/^seat_model_contain_after *= *\([0-9]*\).*/\1/p' "$TF_DIR"/*.tfvars 2>/dev/null | tail -1)"; thr="${thr:-3}"
  for i in $(seq 1 "$thr"); do   # distinct conversations = distinct turns for the threshold
    vm_ssh --command "sudo -u dev -H bash -c \"cd /data/projects/dev && timeout 120 agy --model $off -p 'Reply with exactly: ok' --print-timeout 100s >/dev/null 2>&1\"" >/dev/null 2>&1 || true
  done
  local mo=""
  for i in 1 2 3 4 5 6 7 8; do
    mo="$(gcloud logging read "jsonPayload.component=\"agy-gateway\" AND jsonPayload.event=\"MODEL_OFF_POLICY\" AND jsonPayload.experience=\"$off\"" \
      --project "$PROJECT_ID" --freshness=10m --limit=20 --format='value(jsonPayload.violations_1h)' 2>/dev/null | sort -n | tail -1)"
    [[ -n "$mo" && "$mo" -ge "$thr" ]] && break; sleep 15
  done
  [[ -n "$mo" ]] && echo "RESULT|PASS|S32|Off-policy model flagged by the inspector from the prompt log (MODEL_OFF_POLICY)|$off, $mo distinct turn(s) in 1 h" \
    || echo "RESULT|FAIL|S32|Off-policy model flagged by the inspector|no MODEL_OFF_POLICY for $off within 2 min"
  if [[ "$cm" != "off" ]]; then
    local mc; mc="$(gcloud logging read 'jsonPayload.event=("CONTAINMENT_DRYRUN" OR "CONTAINMENT_APPLIED" OR "CONTAINMENT_SKIPPED") AND jsonPayload.reason:"model_off_policy"' \
      --project "$PROJECT_ID" --freshness=10m --limit=1 --format='value(jsonPayload.event,jsonPayload.why)' 2>/dev/null | tr '\t' ' ')"
    [[ -n "$mc" ]] && echo "RESULT|PASS|S33|Containment requested at the model-violation threshold ($thr turns/h, $cm)|$mc" \
      || echo "RESULT|FAIL|S33|Containment requested at the model-violation threshold|no containment decision with reason model_off_policy (violations: ${mo:-0}/$thr)"
  fi
  local aux_seen aux_flag
  aux_seen="$(gcloud logging read "logName=\"projects/$sp/logs/businessaicode.googleapis.com%2Finference_request\" AND jsonPayload.experience=\"gemini-3.5-flash-lite\"" \
    --project "$sp" --freshness=15m --limit=5 --format='value(timestamp)' 2>/dev/null | grep -c .)"
  aux_flag="$(gcloud logging read 'jsonPayload.event="MODEL_OFF_POLICY" AND jsonPayload.experience="gemini-3.5-flash-lite"' \
    --project "$PROJECT_ID" --freshness=15m --limit=1 --format='value(timestamp)' 2>/dev/null | grep -c .)"
  [[ "$aux_flag" -eq 0 ]] && echo "RESULT|PASS|S34|Client helper model never flagged (gemini-3.5-flash-lite)|seen in prompt log: $aux_seen, flagged: 0" \
    || echo "RESULT|FAIL|S34|Client helper model never flagged|flagged $aux_flag time(s)"
}

groups_checks() {   # AGY user groups exist (Cloud Identity) and the developers group can use the seat (RESULT lines)
  G="$(tfo agy_groups)" MODE="$(tfo client_mode)" SEAT_P="$( [[ -n "${SEAT_PROJECT:-}" ]] && echo "$SEAT_PROJECT" || echo "$PROJECT_ID")" python3 - <<'PY'
import json, os, subprocess
g = json.loads(os.environ.get("G") or "{}"); mode = os.environ.get("MODE", "")
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
emails = {k: v for k, v in g.items() if v}
if not emails:
    res("WARN", "S38", "AGY user groups (developers / contractors)", "groups_mode = none: users are mapped one by one")
    raise SystemExit
bad = []
for k, e in emails.items():
    r = subprocess.run(["gcloud", "identity", "groups", "describe", e, "--format=value(name)"], capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip(): bad.append(f"{k}:{e} not found / no read access")
if mode in ("seat", "mixed") and emails.get("dev"):
    r = subprocess.run(["gcloud", "projects", "get-iam-policy", os.environ["SEAT_P"], "--format=json"], capture_output=True, text=True)
    pol = json.loads(r.stdout or "{}") if r.returncode == 0 else {}
    if not any(b["role"] == "roles/discoveryengine.agentspaceUser" and f"group:{emails['dev']}" in b["members"] for b in pol.get("bindings", [])):
        bad.append("developers group lacks the seat role")
res("FAIL" if bad else "PASS", "S38", "AGY user groups (developers / contractors)",
    "; ".join(bad) or ", ".join(f"{k}={e}" for k, e in emails.items()))
PY
}

seat_user_checks() {   # seat mode: every seat user holds the seat role on the seat project (RESULT lines)
  SEAT_P="$( [[ -n "${SEAT_PROJECT:-}" ]] && echo "$SEAT_PROJECT" || echo "$PROJECT_ID")" USERS="${SEAT_USERS:-}" python3 - <<'PY'
import json, os, subprocess
p, users = os.environ["SEAT_P"], [u.strip() for u in os.environ.get("USERS", "").split(",") if u.strip()]
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
r = subprocess.run(["gcloud", "projects", "get-iam-policy", p, "--format=json"], capture_output=True, text=True)
pol = json.loads(r.stdout or "{}") if r.returncode == 0 else {}
have = {m for b in pol.get("bindings", []) if b["role"] == "roles/discoveryengine.agentspaceUser" and not b.get("condition") for m in b["members"]}
missing = [u for u in users if u not in have]
extra = sorted(have - set(users))
if not users:
    res("WARN", "S37", "Seat users hold the seat role on the seat project", "SEAT_USERS empty - grant users via seat_users / seat_user_groups")
else:
    res("FAIL" if missing else "PASS", "S37", "Seat users hold the seat role on the seat project",
        (f"missing: {', '.join(missing)}" if missing else f"{len(users)} principal(s)") + (f"; also granted outside the installer: {', '.join(extra)}" if extra else ""))
PY
}

logging_network_checks() {   # audit-log storage, log-bucket lock and VPC egress (RESULT lines)
  PROJECT_ID="$PROJECT_ID" REGION="$REGION" LOCK="${LOG_LOCK_DAYS:-0}" NETWORK_MODE="$(tfvar_value network_mode)" python3 - <<'PY'
import json, os, subprocess
p, region, lock = os.environ["PROJECT_ID"], os.environ["REGION"], int(os.environ["LOCK"] or 0)
shared_vpc = os.environ.get("NETWORK_MODE") == "shared"
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
def g(*a):
    r = subprocess.run(["gcloud", *a, "--project", p, "--format=json"], capture_output=True, text=True)
    return json.loads(r.stdout or "null") if r.returncode == 0 else None
buckets = {b["name"].split("/")[-1]: b for b in (g("logging", "buckets", "list") or [])}
aud = next((b for n, b in buckets.items() if n.endswith("-audit")), None)
sinks = {s["name"]: s for s in (g("logging", "sinks", "list") or [])}
asink = next((s for n, s in sinks.items() if n.endswith("-audit-sink")), None)
excl = " ".join(e.get("filter", "") for e in (g("logging", "sinks", "describe", "_Default") or {}).get("exclusions", []))
ok = aud and region in aud["name"] and aud.get("cmekSettings") and asink and "data_access" in asink.get("filter", "") and "data_access" in excl
res("PASS" if ok else "FAIL", "V94", "Audit logs stored in your region with your key; Data Access kept out of the global _Default bucket",
    (f"{aud['name'].split('/')[-1]} {aud.get('retentionDays')} days, CMEK" if aud else "no audit bucket") + ("" if "data_access" in excl else ", _Default exclusion missing"))
sec = [b for n, b in buckets.items() if n.endswith(("-siem", "-audit")) or "-security" in n]   # security bucket id may be custom (log_bucket_id)
if lock:
    bad = [f"{b['name'].split('/')[-1]}(locked={b.get('locked', False)},{b.get('retentionDays')}d)" for b in sec
           if not b.get("locked") or int(b.get("retentionDays", 0)) != lock]
    res("FAIL" if bad else "PASS", "V95", f"Log buckets locked ({lock} days, irreversible)", ", ".join(bad) or f"{len(sec)} buckets locked")
else:
    res("WARN", "V95", "Log buckets locked", "not locked (LOG_LOCK_DAYS=0): owners / logging admins can delete logs or shorten retention")
if shared_vpc:   # no VPC of our own: egress and firewall rules belong to the network team's Shared VPC
    res("SKIP", "V96", "VPC egress deny by default", "network_mode = shared: this project has no VPC of its own; firewall and egress rules are managed by your network team in the Shared VPC host project")
else:
    fw = g("compute", "firewall-rules", "list") or []
    deny = [r for r in fw if r.get("direction") == "EGRESS" and r.get("denied") and "0.0.0.0/0" in r.get("destinationRanges", [])]
    res("PASS" if deny else "WARN", "V96", "VPC egress deny by default (only web, Google APIs and Windows activation leave the VPC)",
        ", ".join(r["name"] for r in deny) or "no egress deny rule (vpc_egress_restricted = false)")
PY
}

gateway_checks() {   # official-contract checks of the gateway itself (RESULT lines)
  GW_SA="$(tfo gateway_service_account)" INF_PROJECT="$(tfo inference_project)" PROJECT_ID="$PROJECT_ID" FLUSH_MS="$(sed -n 's/^response_flush_ms *= *\([0-9]*\).*/\1/p' "$ROOT"/terraform/*.tfvars 2>/dev/null | tail -1)" python3 - <<'PY'
import json, os, subprocess, time
p = os.environ["PROJECT_ID"]
inf = os.environ.get("INF_PROJECT") or p   # model calls (and their Data Access logs) live in the inference project
flush_ms = int(os.environ.get("FLUSH_MS") or 500)
def res(st, i, d, x=""): print(f"RESULT|{st}|{i}|{d}|{x}")
def logs(flt, fresh="20m", limit=50, project=None):
    r = subprocess.run(["gcloud", "logging", "read", flt, "--project", project or p, f"--freshness={fresh}", f"--limit={limit}",
                        "--format=json"], capture_output=True, text=True)
    return json.loads(r.stdout or "[]") if r.returncode == 0 else []
# V91 attribution: Vertex AI Data Access audit log shows the gateway SA, the EU location and the client's unchanged
# User-Agent with auth_method=gateway (what Google uses to attribute gateway traffic to Antigravity)
sa = os.environ.get("GW_SA", "")
ent = []
for _ in range(6):   # Data Access logs arrive with a short delay
    ent = logs('protoPayload.serviceName="aiplatform.googleapis.com" AND '
               'protoPayload.requestMetadata.callerSuppliedUserAgent:"auth_method=gateway"', limit=20, project=inf)
    if ent:
        break
    time.sleep(10)
if not ent:
    res("WARN", "V91", "Vertex AI audit log attributes gateway traffic (SA, EU, User-Agent)", "no gateway call in the last 20 min")
else:
    bad = [e for e in ent if e["protoPayload"].get("authenticationInfo", {}).get("principalEmail") != sa
           or not e["protoPayload"].get("resourceName", "").startswith(f"projects/{inf}/locations/eu/")]
    ua = ent[0]["protoPayload"]["requestMetadata"]["callerSuppliedUserAgent"].split(" ")[0]
    res("FAIL" if bad else "PASS", "V91", "Vertex AI audit log attributes gateway traffic (SA, EU, User-Agent)",
        f"{len(ent)} calls by {sa.split('@')[0]} in {inf}, UA {ua}" + (f"; {len(bad)} with another principal/location" if bad else ""))
# V92 streaming latency: inspected streams must not hold text much longer than the flush bound (official: don't buffer)
st = [e["jsonPayload"] for e in logs('jsonPayload.component="agy-gateway" AND jsonPayload.event="STREAM_DONE" '
                                      'AND jsonPayload.inspected=true')]
if not st:
    res("WARN", "V92", "Streamed responses are not buffered (time-bound inspection flush)", "no inspected stream in the last 20 min")
else:
    hold = max(int(s.get("max_hold_ms", 0)) for s in st)
    ttfb = sorted(int(s.get("ttfb_ms", 0)) for s in st)[len(st) // 2]
    limit = flush_ms + 1500   # flush bound + one inspection round trip
    res("PASS" if hold <= limit else "WARN", "V92", "Streamed responses are not buffered (time-bound inspection flush)",
        f"{len(st)} streams, max hold {hold} ms (limit {limit}), median time-to-first-byte {ttfb} ms")
PY
}

telemetry_checks() {   # device telemetry without a gateway: federated device identity (S40) and its trust store (S41)
  local tel; tel="$(tfo telemetry)"
  [[ -n "$tel" && "$tel" != "null" ]] || { echo "RESULT|SKIP|S40|Device telemetry identity (Workload Identity Federation, X.509)|enable_telemetry = false"; return 0; }
  TEL="$tel" PROJECT_ID="$PROJECT_ID" ANCHORS="$(tfo telemetry_anchor_hashes)" python3 - <<'PY'
import hashlib, json, os, subprocess
tel = json.loads(os.environ["TEL"]); proj = os.environ["PROJECT_ID"]
def res(st, cid, title, detail=""): print(f"RESULT|{st}|{cid}|{title}|{detail}")
prov = tel["audience"].split("//iam.googleapis.com/", 1)[1]
pool = prov.rsplit("/providers/", 1)[0]
def g(*a):
    r = subprocess.run(["gcloud", *a, "--format=json"], capture_output=True, text=True)
    return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else None
p = g("iam", "workload-identity-pools", "providers", "describe", prov.rsplit("/", 1)[1], "--workload-identity-pool",
      pool.rsplit("/", 1)[1], "--location", "global", "--project", proj) or {}
pol = g("projects", "get-iam-policy", proj) or {}
roles = sorted({b["role"] for b in pol.get("bindings", []) if tel["principal_set"] in b.get("members", [])})
ok = p.get("state") == "ACTIVE" and bool(p.get("x509")) and roles == ["roles/logging.logWriter"] and bool(p.get("attributeCondition"))
res("PASS" if ok else "FAIL", "S40", "Device identity: X.509 federation active, condition set, devices write-only (logWriter)",
    f"provider {p.get('state', 'missing')}, condition '{p.get('attributeCondition', '')}', device roles {roles}")
want = sorted(set(json.loads(os.environ.get("ANCHORS") or "[]")))
have = sorted({hashlib.sha256(a["pemCertificate"].strip().encode()).hexdigest()[:16]
               for a in p.get("x509", {}).get("trustStore", {}).get("trustAnchors", [])})
res("PASS" if have and have == want else "FAIL", "S41", "Device identity trusts only your PKI's configured CA certificates",
    f"{len(have)} trust anchor(s){'' if have == want else ' - differs from device_trust_anchor_files'}")
PY
}

windows_checks() {   # Windows workstation: endpoint validation over IAP SSH (RESULT lines); V71+
  local wvm; wvm="$(tfo windows_workstation_name)"
  [[ -n "$wvm" && "$wvm" != "null" ]] || return 0
  local o; o="$(retry 3 20 gcloud compute ssh "$wvm" --zone "$ZONE" --tunnel-through-iap --quiet --command \
    'powershell -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\Antigravity\bundle\files\controls\Test-AGYEndpoint.ps1' \
    2>/dev/null | tr -d '\r' | grep '^RESULT|' || true)"
  [[ -n "$o" ]] && echo "$o" || echo "RESULT|FAIL|V71|Windows endpoint validation ran|no output from $wvm (SSH via IAP failed or bundle missing?)"
}

siem_checks() {   # V69 SIEM storage + V70 endpoint events reach the normalised views (RESULT lines)
  local siem ds link vm since n i
  siem="$(tfo siem)"; [[ -n "$siem" && "$siem" != "null" ]] || { echo "RESULT|WARN|V69|BigQuery SIEM present|enable_siem = false"; return; }
  ds="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["dataset"])' "$siem")"
  link="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["linked_dataset"])' "$siem")"
  local kms views sched
  kms="$(bq show --format=json "$PROJECT_ID:$ds" 2>/dev/null | python3 -c 'import json,sys; print((json.load(sys.stdin).get("defaultEncryptionConfiguration") or {}).get("kmsKeyName",""))' 2>/dev/null)"
  views="$(bq ls --format=json "$PROJECT_ID:$ds" 2>/dev/null | python3 -c 'import json,sys; print(" ".join(sorted(t["tableReference"]["tableId"] for t in json.load(sys.stdin))))' 2>/dev/null)"
  sched="$(bq ls --transfer_config --transfer_location="$REGION" --project_id="$PROJECT_ID" --format=json 2>/dev/null | python3 -c 'import json,sys; print(sum(1 for t in json.load(sys.stdin) if t.get("displayName","").endswith("-siem-detections")))' 2>/dev/null)"
  if [[ -n "$kms" && "$views" == *v_endpoint_events* && "$views" == *v_incident_timeline* && "${sched:-0}" -ge 1 ]]; then
    echo "RESULT|PASS|V69|BigQuery SIEM: CMEK dataset, views, scheduled detections, linked log dataset|$ds ($views), link $link"
  else
    echo "RESULT|FAIL|V69|BigQuery SIEM: CMEK dataset, views, scheduled detections|kms=${kms:-none} views=[$views] detections=${sched:-0}"
  fi
  vm="$(tfo workstation_name)"; [[ -n "$vm" ]] || return 0
  # the VM validation (V66) produced hook DENY decisions minutes ago; they must be queryable in the normalised view
  for i in 1 2 3 4 5 6 7 8 9 10; do
    n="$(bq query --project_id="$PROJECT_ID" --use_legacy_sql=false --format=csv --quiet \
      "SELECT COUNT(*) FROM \`$PROJECT_ID.$ds.v_endpoint_events\` WHERE vm = '$vm' AND layer = 'hook' AND event = 'DENY' AND ts > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 MINUTE)" 2>/dev/null | tail -1)"
    [[ "${n:-0}" =~ ^[0-9]+$ && "$n" -gt 0 ]] && break; sleep 30
  done
  [[ "${n:-0}" =~ ^[0-9]+$ && "$n" -gt 0 ]] && echo "RESULT|PASS|V70|Endpoint hook denials reach the SIEM view (v_endpoint_events)|$n DENY rows for $vm in 30 min" \
    || echo "RESULT|FAIL|V70|Endpoint hook denials reach the SIEM view|no hook DENY rows for $vm after 5 min (${n:-query failed})"
}

p7_validate() {
  banner 7 "validation -> install-report.md"
  VM="$(tfo workstation_name)"
  local out rep="$ROOT/install-report.md" fails warns plan_rc=0
  if [[ -n "$VM" ]]; then
    out="$(retry 3 20 vm_ssh --command "sudo bash -s" < "$ROOT/install/validate-vm.sh" | grep '^RESULT|' || true)"
    [[ -n "$out" ]] || out="RESULT|FAIL|V00|Validation script ran on the workstation|no output (SSH via IAP failed?)"
  else
    out="$(fleet_profile_checks)"
  fi
  # seat mode: run the inspector end-to-end first, so the evidence check (V54) can see its flagged prompt
  if [[ "$(tfo client_mode)" =~ ^(seat|mixed)$ ]]; then out+=$'\n'"$(seat_checks)"; fi
  out+=$'\n'"$(evidence_checks)"
  out+=$'\n'"$(logging_network_checks)"
  out+=$'\n'"$(groups_checks)"
  [[ "$(tfo client_mode)" =~ ^(seat|mixed)$ ]] && out+=$'\n'"$(seat_user_checks)"
  out+=$'\n'"$(siem_checks)"
  out+=$'\n'"$(telemetry_checks)"
  out+=$'\n'"$(windows_checks)"
  if [[ "$(tfo gateway_enabled)" == "false" ]]; then   # seat-only composition: the gateway checks don't apply
    out+=$'\n'"RESULT|SKIP|V91|Vertex AI audit attribution of gateway calls|gateway not deployed (enable_gateway = false)"
    out+=$'\n'"RESULT|SKIP|V92|Streamed responses are not buffered|gateway not deployed (enable_gateway = false)"
  elif [[ "$(tfo client_mode)" != "seat" ]]; then out+=$'\n'"$(gateway_checks)"; fi   # gateway + mixed
  if [[ -n "$VM" ]]; then
    local fl; fl="$(tfo fleet)"
    if [[ -n "$fl" && "$fl" != "null" ]] && python3 -c 'import json,sys; sys.exit(0 if json.loads(sys.argv[1])["selftest"] else 1)' "$fl"; then
      out+=$'\n'"$(bash "$ROOT/install/fleet-selftest.sh" "$VM" "$ZONE" "$REGION" \
        "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["ca_pool"])' "$fl")" \
        "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["spiffe_prefix"])' "$fl")" \
        "$(tfo gateway_mtls_url)" | grep '^RESULT|')"
    fi
    local rp; rp="$(gcloud compute disks describe "$(tfo workstation_name | sed 's/-dev-ws$//')-data" --zone "$ZONE" --format='value(resourcePolicies.basename())' 2>/dev/null)"
    if [[ -n "$rp" ]]; then out+=$'\n'"RESULT|PASS|V62|Workspace disk snapshot schedule attached|$rp"
    else out+=$'\n'"RESULT|WARN|V62|Workspace disk snapshot schedule attached|none (snapshot_every_hours=0?)"; fi
  fi
  tf plan -input=false -detailed-exitcode -var "gateway_image=$(current_image)" >/dev/null 2>&1 || plan_rc=$?
  if [[ $plan_rc -eq 0 ]]; then out+=$'\n'"RESULT|PASS|V90|Terraform converged (plan: no changes)|"
  else out+=$'\n'"RESULT|WARN|V90|Terraform converged (plan: no changes)|plan exit code $plan_rc"; fi
  fails=$(grep -c '^RESULT|FAIL|' <<<"$out" || true); warns=$(grep -c '^RESULT|WARN|' <<<"$out" || true)
  {
    echo "# AGY POC install report"; echo
    echo "- Date: $(date -u '+%Y-%m-%d %H:%M UTC')"
    echo "- Project: \`$PROJECT_ID\`  Region: \`$REGION\`  Zone: \`$ZONE\`"
    echo "- Gateway: $(tfo gateway_url)  mTLS front door: $(tfo gateway_mtls_url)"
    echo "- Installer identity: \`$(gcloud config get-value account 2>/dev/null)\`"
    echo; echo "| Status | ID | Check | Detail |"; echo "|---|---|---|---|"
    awk -F'|' '{icon=($2=="PASS"?"✅":($2=="FAIL"?"❌":($2=="SKIP"?"⏭️":"⚠️"))); printf "| %s %s | %s | %s | %s |\n", icon, $2, $3, $4, $5}' <<<"$out"
    echo; echo "**Result: $([[ $fails -eq 0 ]] && echo PASSED || echo "FAILED ($fails)")** - $warns warning(s)"
    if [[ -n "$VM" ]]; then echo; echo "Persona desktop: \`make desktop PERSONA=dev\` (or contractor) from a machine with an RDP client."
    elif [[ -n "${AGY_POC:-}" ]]; then echo; echo "POC: devices come from \`devices.csv\`; certificates and device kits from \`poc/poc-gateway.sh\`; each laptop installs from its kit."
    else echo; echo "Gateway profile: register devices in \`fleet_devices\`, issue certificates with \`make fleet-cert DEVICE=<id>\`, then run \`scripts/fleet-probe.sh\` from a connected device."; fi
  } > "$rep"
  awk -F'|' '{c=($2=="PASS"?"32":($2=="FAIL"?"31":($2=="SKIP"?"36":"33"))); printf "\033[1;%sm[%s]\033[0m %s %s %s\n", c, $2, $3, $4, ($5==""?"":"- "$5)}' <<<"$out"
  log "report: ${rep#"$ROOT"/}"
  [[ $fails -eq 0 ]]
}

p8_handoff() {
  banner 8 "test hand-off -> TESTING.md + testing.env"
  local j; j="$(mktemp)"
  tf output -json > "$j" 2>/dev/null || { warn "terraform output unavailable - hand-off skipped"; rm -f "$j"; return 0; }
  PROJECT_ID="$PROJECT_ID" REGION="$REGION" ZONE="$ZONE" AGY_POC="${AGY_POC:-}" \
    python3 "$ROOT/install/handoff.py" --tf-json "$j" --outdir "$ROOT"
  rm -f "$j"; chmod 644 "$ROOT/TESTING.md" "$ROOT/testing.env"
}

destroy() {
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib.sh"
  cat <<MSG

 This DESTROYS the POC in project ${PROJECT_ID}: workstation VM + disks, gateway, CAS pools, load balancer,
 secrets, buckets, log bucket, BigQuery dataset, alerts. CMEK key versions are SCHEDULED for destruction (24h).
 APIs stay enabled; the project is not deleted. The Terraform state bucket is $([[ $PURGE_STATE -eq 1 ]] && echo "ALSO DELETED" || echo "kept").
MSG
  if [[ "${DESTROY_ACK:-}" != "$PROJECT_ID" ]]; then
    [[ $YES -eq 1 ]] && die "set DESTROY_ACK=\"$PROJECT_ID\" in $CONF for unattended destroy"
    local a; read -r -p "Type the project id to confirm: " a; [[ "$a" == "$PROJECT_ID" ]] || die "aborted"
  fi
  [[ -f "$TF_DIR/backend.hcl" ]] || die "terraform/backend.hcl missing - nothing to destroy from this checkout"
  tf init -input=false -reconfigure -backend-config=backend.hcl >/dev/null
  # prompt evidence outlives the POC: keep the evidence bucket, its keys and the wrapped token key
  local keep; keep="$(tf state list 2>/dev/null | grep -E '^module\.evidence\[0\]\.(google_kms_key_ring\.ev|google_kms_crypto_key\.|google_storage_bucket\.ev|google_secret_manager_secret\.wrapped|google_iam_deny_policy\.evidence|google_tags_)' || true)"
  if [[ -n "$keep" ]]; then
    warn "preserving prompt evidence (removed from Terraform state, NOT deleted):"; echo "$keep" | sed 's/^/    /'
    # shellcheck disable=SC2086
    tf state rm $keep >/dev/null
  fi
  retry 2 60 tf destroy -input=false -auto-approve -var "gateway_image=$(current_image)"
  rm -rf "$STATE_DIR"
  log "POC removed."
  if [[ $PURGE_STATE -eq 1 ]]; then
    local bucket; bucket="$(awk -F'"' '/^bucket/{print $2}' "$TF_DIR/backend.hcl")"
    if [[ $YES -eq 0 ]]; then
      local b; read -r -p "Delete state bucket gs://${bucket} (all versions)? Type 'purge': " b; [[ "$b" == "purge" ]] || die "state kept"
    fi
    gcloud storage rm -r --all-versions "gs://${bucket}/**" --quiet 2>/dev/null || true
    gcloud storage buckets delete "gs://${bucket}" --quiet
    for v in $(gcloud kms keys versions list --key agy-tfstate-key --keyring agy-tfstate-ring --location "$REGION" \
                 --filter='state=ENABLED OR state=DISABLED' --format='value(name.basename())' 2>/dev/null); do
      gcloud kms keys versions destroy "$v" --key agy-tfstate-key --keyring agy-tfstate-ring --location "$REGION" --quiet >/dev/null
    done
    rm -f "$TF_DIR/backend.hcl"
    log "state bucket deleted; state key versions scheduled for destruction (key ring names persist - KMS limitation)"
  fi
}

# ----------------------------------------------------------------------------- main
command -v gcloud >/dev/null || die "gcloud not found - https://cloud.google.com/sdk/docs/install"
command -v python3 >/dev/null || die "python3 not found"
# macOS python.org builds lack a CA bundle; Linux/Cloud Shell are unaffected
[[ "$(uname)" == "Darwin" && -z "${SSL_CERT_FILE:-}" && -f /etc/ssl/cert.pem ]] && export SSL_CERT_FILE=/etc/ssl/cert.pem

if [[ $DESTROY -eq 1 ]]; then
  [[ -f "$CONF" && -n "${PROJECT_ID:-}" ]] || die "no install.conf - nothing to destroy from this checkout"
  export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"
  ensure_terraform; destroy; exit 0
fi

if [[ $VALIDATE_ONLY -eq 1 ]]; then
  [[ -f "$CONF" && -n "${PROJECT_ID:-}" ]] || die "no install.conf - run ./install.sh first"
  export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"
  ensure_terraform
  # shellcheck disable=SC1091
  source "$ROOT/scripts/lib.sh"; mkdir -p "$STATE_DIR"
  tf init -input=false -reconfigure -backend-config=backend.hcl >/dev/null
  RC=0; p7_validate || RC=$?; p8_handoff; exit $RC
fi

questionnaire
# organisation id (only needed for the seat perimeter): from the project ancestry, never asked
if [[ "${CLIENT_MODE:-gateway}" =~ ^(seat|mixed)$ && "${SEAT_VPC_SC:-n}" == "y" && -z "${ORG_ID:-}" ]]; then
  ORG_ID="$(gcloud projects get-ancestors "$PROJECT_ID" --format='value(id,type)' 2>/dev/null | awk '$2=="organization"{print $1}')"
  [[ -n "$ORG_ID" ]] || die "seat perimeter needs the project to be in an organisation (no organisation found for $PROJECT_ID)"
fi
guard_project_binding
export CLOUDSDK_CORE_PROJECT="$PROJECT_ID"
write_conf
gen_tfvars
ensure_terraform
run_preflight
[[ $PREFLIGHT_ONLY -eq 1 ]] && { log "preflight-only: stopping here"; exit 0; }
cost_confirm
write_conf   # persist COST_ACK
mkdir -p "$STATE_DIR"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib.sh"   # tf / tfo / current_image / gateway_image_tag (reads the generated tfvars)
START=$(date +%s)

if phase_done p2; then tf init -input=false -reconfigure -backend-config=backend.hcl >/dev/null; else p2_bootstrap; mark p2; fi
phase_done p3 || { p3_foundation; p3b_token_key; mark p3; }
{ phase_done p4 && [[ -f "$STATE_DIR/image" ]]; } || { p4_image; mark p4; }
phase_done p5 || { p5_gateway; mark p5; }
if [[ "$PROFILE" == "gateway" ]]; then log "gateway profile: no reference workstation (phase 6 skipped)"
else phase_done p6 || { p6_endpoint; mark p6; }; fi
RC=0; p7_validate || RC=$?
p8_handoff

cat <<MSG

=====================================================================
 AGY POC installed in ${PROJECT_ID} ($(( ($(date +%s) - START) / 60 )) min) - validation: $([[ $RC -eq 0 ]] && echo PASSED || echo "FAILED (see install-report.md)")
   Test hand-off      : TESTING.md (what to test, how to connect, where evidence lands) + testing.env
$( if [[ -n "${AGY_POC:-}" ]]; then
cat <<P
   Profile            : POC gateway (certificate-only devices)
   Devices            : devices.csv -> poc/poc-gateway.sh issues certificates and writes one kit per device
   Laptops            : install from the device kit (endpoint script -Install, then -Test)
P
elif [[ "$PROFILE" == "gateway" ]]; then
cat <<G
   Profile            : gateway only (certificate-only devices)
   Register a device  : fleet_devices in terraform/custom.auto.tfvars, then ./install.sh
   Device certificate : make fleet-cert DEVICE=<id> CSR=<file>
   Probe from device  : scripts/fleet-probe.sh <front-door-url> <crt> <key> <ca>
G
else
cat <<F
   Operator SSH (IAP) : make ssh
   Persona desktop    : make desktop PERSONA=dev   (RDP over IAP; run where an RDP client exists)
   Cost control       : make stop   /   make start
F
fi )
   Gateway audit log  : make logs
   Remove             : ./install.sh --destroy
=====================================================================
MSG
exit $RC
