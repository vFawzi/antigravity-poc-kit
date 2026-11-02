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

# ----------------------------------------------------------------------------- core
variable "project_id" {
  description = "Target project (green field)."
  type        = string
}

variable "region" {
  description = "Region for all regional resources (EU data residency)."
  type        = string
  default     = "europe-west4"
}

variable "zone" {
  description = "Zone for the workstation VM and disks."
  type        = string
  default     = "europe-west4-a"
}

variable "name_prefix" {
  description = "Prefix for resource names."
  type        = string
  default     = "agy"
}

variable "labels" {
  description = "Mandatory resource labels."
  type        = map(string)
  default = {
    environment         = "poc"
    data_classification = "confidential"
    cost_center         = "security"
    owner               = "secops"
    workload            = "antigravity-controls-poc"
  }
}

# ----------------------------------------------------------------------------- identity
variable "operator_principals" {
  description = "Principals allowed to administer the POC (IAP SSH + OS Admin Login + read admin secret), e.g. [\"user:admin@example.com\"]."
  type        = list(string)
}

variable "secops_email" {
  description = "Notification channel for blocked-prompt / tamper alerts."
  type        = string
}

# ----------------------------------------------------------------------------- network
variable "subnet_cidr" {
  description = "Primary CIDR of the workstation subnet."
  type        = string
  default     = "10.40.0.0/24"
}

variable "network_mode" {
  description = "create = own VPC, subnets, router, NAT and firewall rules in this project (default). shared = use an existing Shared VPC subnet of a host project for the gateway load balancer IP; nothing is created or changed in the host project."
  type        = string
  default     = "create"
  validation {
    condition     = contains(["create", "shared"], var.network_mode)
    error_message = "network_mode must be \"create\" or \"shared\"."
  }
}

variable "shared_vpc_host_project" {
  description = "network_mode = shared: Shared VPC host project ID (owned by your network team)."
  type        = string
  default     = ""
  validation {
    condition     = var.shared_vpc_host_project == "" || can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.shared_vpc_host_project))
    error_message = "shared_vpc_host_project must be a valid project ID (or empty)."
  }
}

variable "shared_vpc_network" {
  description = "network_mode = shared: name of the Shared VPC network in the host project."
  type        = string
  default     = ""
  validation {
    condition     = var.shared_vpc_network == "" || can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.shared_vpc_network))
    error_message = "shared_vpc_network must be a network name (lowercase letters, digits, hyphens), not a URL."
  }
}

variable "shared_vpc_subnet" {
  description = "network_mode = shared: name of the subnet (in var.region) shared with this project; the gateway load balancer IP comes from it."
  type        = string
  default     = ""
  validation {
    condition     = var.shared_vpc_subnet == "" || can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.shared_vpc_subnet))
    error_message = "shared_vpc_subnet must be a subnet name (lowercase letters, digits, hyphens), not a URL."
  }
}

variable "gateway_ilb_ip" {
  description = "Optional static internal IP for the gateway load balancer (must be free in the subnet). Empty = any free IP."
  type        = string
  default     = ""
  validation {
    condition     = var.gateway_ilb_ip == "" || can(cidrhost("${var.gateway_ilb_ip}/32", 0))
    error_message = "gateway_ilb_ip must be an IPv4 address (or empty for automatic)."
  }
}

variable "ilb_global_access" {
  description = "Allow clients from other regions (e.g. a VPN or Interconnect that ends in another region) to reach the gateway load balancer."
  type        = bool
  default     = false
}

# ----------------------------------------------------------------------------- workstation
variable "machine_type" {
  description = "Workstation machine type."
  type        = string
  default     = "e2-standard-4"
}

variable "snapshot_every_hours" {
  description = "Snapshot interval of the workspace (data) disk - recovery from destructive or ransomware-like agent actions. 0 = off."
  type        = number
  default     = 4
  validation {
    condition     = contains([0, 1, 2, 3, 4, 6, 8, 12], var.snapshot_every_hours)
    error_message = "snapshot_every_hours must be 0 (off) or one of 1, 2, 3, 4, 6, 8, 12."
  }
}

variable "snapshot_retention_days" {
  description = "Retention of workspace snapshots (kept if the disk is deleted)."
  type        = number
  default     = 7
}

variable "boot_disk_gb" {
  description = "Boot disk size (C: stand-in)."
  type        = number
  default     = 50
}

variable "data_disk_gb" {
  description = "Data disk size (D: stand-in)."
  type        = number
  default     = 50
}

variable "secure_disk_gb" {
  description = "Admin disk size (/secure-admin)."
  type        = number
  default     = 10
}

variable "apparmor_mode" {
  description = "AppArmor mode for the Antigravity profile: enforce | complain."
  type        = string
  default     = "enforce"
  validation {
    condition     = contains(["enforce", "complain"], var.apparmor_mode)
    error_message = "apparmor_mode must be enforce or complain."
  }
}

variable "install_desktop" {
  description = "Install the XFCE desktop and Chrome (needed for the persona desktop and the Desktop app)."
  type        = bool
  default     = true
}

variable "desktop_access" {
  description = "Graphical access for the personas: xrdp (RDP over IAP TCP forwarding, zero-touch) or none."
  type        = string
  default     = "xrdp"
  validation {
    condition     = contains(["xrdp", "none"], var.desktop_access)
    error_message = "desktop_access must be xrdp or none."
  }
}

variable "rdp_clipboard" {
  description = "Allow RDP clipboard redirection (cliprdr) for the personas. Drive and printer redirection are always off."
  type        = bool
  default     = true
}

variable "desktop_personas" {
  description = "Local personas that get an RDP password (stored in Secret Manager, CMEK)."
  type        = list(string)
  default     = ["dev", "contractor"]
}

variable "agy_cli_manifest_url" {
  description = <<-EOT
    Antigravity CLI release manifest (linux x64): the same release server the official installer
    https://antigravity.google/cli uses (DOWNLOAD_BASE_URL + /manifests/<platform>.json). The manifest is fetched
    over TLS; the binary must come from storage.googleapis.com/antigravity-public and match the manifest sha512.
    For change control pin agy_cli_sha512 to a reviewed release.
  EOT
  type        = string
  default     = "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/linux_amd64.json"
  validation {
    condition     = can(regex("^https://[a-z0-9.-]+/manifests/linux_amd64\\.json$", var.agy_cli_manifest_url))
    error_message = "agy_cli_manifest_url must be an https URL ending in /manifests/linux_amd64.json."
  }
}

variable "agy_cli_sha512" {
  description = "Optional pinned sha512 of the CLI tarball (overrides the manifest digest; pins the version)."
  type        = string
  default     = ""
}

variable "agy_desktop_object" {
  description = "Object path of the Antigravity Desktop Linux build in the official distribution bucket gs://antigravity-public (empty = not installed)."
  type        = string
  default     = "antigravity-hub/2.24.0-5780333019398144/linux-x64/Antigravity.tar.gz"
}

variable "agy_desktop_sha256" {
  description = <<-EOT
    Recommended: SHA-256 of the Desktop archive approved by your software-intake review. When set, installation
    fails on any mismatch. When empty, only transport security (TLS to storage.googleapis.com) and the GCS crc32c
    integrity check apply (crc32c detects corruption, it is not an authenticity control).
  EOT
  type        = string
  default     = ""
  validation {
    condition     = var.agy_desktop_sha256 == "" || can(regex("^[a-f0-9]{64}$", var.agy_desktop_sha256))
    error_message = "agy_desktop_sha256 must be empty or a 64-character lowercase hex SHA-256."
  }
}

variable "egress_allowlist" {
  description = <<-EOT
    Per persona group: FQDNs the user's own processes may reach over HTTP(S). Everything else is dropped (and logged).
    The agent's model traffic does not need entries: it goes through the local credential proxy (separate system user).
    Resolved to addresses every minute on the endpoint (entries kept 1 h). In production enforce the same through your SSE / proxy.
  EOT
  type        = map(list(string))
  default = {
    "agy-dev" = [
      "github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
      "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "proxy.golang.org", "sum.golang.org",
    ]
    "agy-contractor" = []
  }
}

variable "hosts_pin" {
  description = <<-EOT
    Publicly documented Google AI endpoints pinned to 0.0.0.0 on the workstation, so every non-gateway Antigravity
    mode fails closed (Gemini Code Assist backend, Gemini API, Vertex AI global/regional/multi-region endpoints and
    the Business AI Code API from the public API catalog, incl. its regional endpoints). Add further endpoints from your Google account team in
    terraform/custom.auto.tfvars. In production, enforce the same with your SSE / proxy egress allowlist.
  EOT
  type        = list(string)
  default = [
    "cloudcode-pa.googleapis.com", "generativelanguage.googleapis.com",
    "businessaicode.googleapis.com", "businessaicode.eu.rep.googleapis.com", "businessaicode.us.rep.googleapis.com",
    "aiplatform.googleapis.com", "aiplatform.eu.rep.googleapis.com", "aiplatform.us.rep.googleapis.com",
    "europe-west4-aiplatform.googleapis.com", "us-central1-aiplatform.googleapis.com",
  ]
}

# ----------------------------------------------------------------------------- gateway
variable "gateway_image" {
  description = "Container image for the gateway. Empty = gateway not deployed yet (stage 1)."
  type        = string
  default     = ""
  validation {
    condition     = var.gateway_image == "" || can(regex("^[a-z0-9-]+-docker\\.pkg\\.dev/\\S+:[A-Za-z0-9._-]+$", var.gateway_image))
    error_message = "gateway_image must be empty or an Artifact Registry image with a tag."
  }
}

variable "vertex_location" {
  description = "Vertex AI location for inference (the eu multi-region serves the Antigravity models)."
  type        = string
  default     = "eu"
}

variable "gateway_ingress" {
  description = "Cloud Run ingress. INGRESS_TRAFFIC_INTERNAL_ONLY keeps it reachable from the VPC only."
  type        = string
  default     = "INGRESS_TRAFFIC_INTERNAL_ONLY"
}

variable "prompt_logging" {
  description = <<-EOT
    What the audit trail keeps of a BLOCKED prompt:
      none         event + incident id only
      hash         + SHA-256 of the prompt
      deidentified + full prompt with sensitive values replaced by reversible SDP tokens (KMS-wrapped Cloud HSM key)
      evidence     deidentified + the exact original, envelope-encrypted with a Cloud HSM key, in a retention-locked
                   evidence bucket. Restore only through a Privileged Access Manager grant (make investigate).
  EOT
  type        = string
  default     = "hash"
  validation {
    condition     = contains(["none", "hash", "deidentified", "evidence"], var.prompt_logging)
    error_message = "prompt_logging must be none, hash, deidentified or evidence."
  }
}

variable "evidence_retention_days" {
  description = "Retention of prompt evidence (evidence mode). Objects can't be deleted earlier."
  type        = number
  default     = 365
}

variable "investigators" {
  description = "Principals who may REQUEST a break-glass grant to restore prompts (Privileged Access Manager)."
  type        = list(string)
  default     = []
}

variable "investigation_approvers" {
  description = "Principals who must approve restore grants (empty = no approval step; justification still required)."
  type        = list(string)
  default     = []
}

variable "gateway_block_response_mode" {
  description = "How policy blocks are returned: message (normal model reply showing reason + incident; works in Desktop UI) or error (HTTP 403)."
  type        = string
  default     = "message"
  validation {
    condition     = contains(["message", "error"], var.gateway_block_response_mode)
    error_message = "gateway_block_response_mode must be message or error."
  }
}

variable "client_mode" {
  description = "How Antigravity clients reach models: gateway (Enterprise Gateway, pay-as-you-go, inline inspection), mixed (both: e.g. developers on seat devices, contractors on gateway devices - each device has one mode) or seat (signed-in Gemini Enterprise seat with the seat hardening profile: pinned licence project/location, consumer tier blocked, Google admin controls, tool hook, log-based inspection)."
  type        = string
  default     = "gateway"
  validation {
    condition     = contains(["gateway", "seat", "mixed"], var.client_mode)
    error_message = "client_mode must be gateway, seat or mixed."
  }
}

variable "workstation_client_mode" {
  description = "Mode of the Linux reference workstation: gateway | seat. Empty = client_mode (mixed -> seat). With client_mode = mixed both the gateway and the seat side are deployed; each device (reference workstation, managed laptop via agy-client-mode) uses one of them."
  type        = string
  default     = ""
  validation {
    condition     = contains(["", "gateway", "seat"], var.workstation_client_mode)
    error_message = "workstation_client_mode must be empty, gateway or seat."
  }
}

variable "windows_workstation_client_mode" {
  description = "Mode of the Windows reference workstation: gateway | seat. Empty = client_mode (mixed -> seat; Windows gateway mode needs the Windows device proxy)."
  type        = string
  default     = ""
  validation {
    condition     = contains(["", "gateway", "seat"], var.windows_workstation_client_mode)
    error_message = "windows_workstation_client_mode must be empty, gateway or seat."
  }
}

variable "seat_project" {
  description = "Seat mode: project that holds the Gemini Enterprise licences (pinned in the managed client settings, so users can't pick another licence). Empty = this project."
  type        = string
  default     = ""
}

variable "seat_location" {
  description = "Seat mode: licence location pinned in the client (eu keeps inference on businessaicode.eu.rep.googleapis.com)."
  type        = string
  default     = "eu"
  validation {
    condition     = contains(["eu", "us", "global"], var.seat_location)
    error_message = "seat_location must be eu, us or global."
  }
}

variable "seat_signin_hosts" {
  description = <<-EOT
    Seat mode: hosts the Antigravity Desktop app and its Google sign-in need from the persona session (added to every
    persona group's egress allowlist). Google's sign-in pages are also served from rotating front-end addresses that a
    DNS-based allowlist can't follow: use your SSE / proxy for browser traffic, or open a time-boxed operator sign-in
    window (`make signin-window`).
  EOT
  type        = list(string)
  default = [
    "accounts.google.com", "antigravity.google", "antigravity-unleash.goog", "antigravity-pa.googleapis.com",
    "www.googleapis.com", "ssl.gstatic.com", "www.gstatic.com", "fonts.gstatic.com", "fonts.googleapis.com",
    "lh3.googleusercontent.com",
  ]
}

variable "seat_default_group" {
  description = "Seat mode: policy group (group_policy key) applied by the prompt-log inspector to seat users not listed in seat_user_groups."
  type        = string
  default     = "agy-dev"
}

variable "seat_user_groups" {
  description = "Seat mode: seat user e-mail -> policy group used by the prompt-log inspector (rules, classifier mode, pci_scope)."
  type        = map(string)
  default     = {}
}

variable "groups_mode" {
  description = "AGY user groups: none (map users individually), create (create agy-developers@ / agy-contractors@ as Cloud Identity security groups) or existing (use dev_group / contractor_group, e.g. synced from Entra ID or created by hand)."
  type        = string
  default     = "none"
  validation {
    condition     = contains(["none", "create", "existing"], var.groups_mode)
    error_message = "groups_mode must be none, create or existing."
  }
}

variable "cloud_identity_customer_id" {
  description = "Cloud Identity customer id (C0xxxxxxx) - groups_mode = create. Find it in the Admin console (Account settings) or with gcloud organizations describe."
  type        = string
  default     = ""
}

variable "groups_domain" {
  description = "Domain of the created groups (groups_mode = create), e.g. example.com."
  type        = string
  default     = ""
}

variable "dev_group" {
  description = "Existing developers group e-mail (groups_mode = existing), e.g. agy-developers@example.com (synced from Entra ID or created by hand)."
  type        = string
  default     = ""
}

variable "contractor_group" {
  description = "Existing contractors group e-mail (groups_mode = existing)."
  type        = string
  default     = ""
}

variable "seat_users" {
  description = "Seat mode: principals (user:, group:) allowed to use the Gemini Enterprise seat - granted roles/discoveryengine.agentspaceUser on the seat project only. Users in seat_user_groups are added automatically. A licence alone is not enough: without the role the client gets PERMISSION_DENIED; an unlicensed account silently falls back to Vertex AI pay-as-you-go."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for m in var.seat_users : can(regex("^(user|group):[^@\\s]+@[^@\\s]+$", m))])
    error_message = "seat_users entries must be user:<email> or group:<email>."
  }
}

variable "seat_containment" {
  description = "Seat mode: automated containment on high-risk findings or stolen-token signals. off | dry_run (log what would happen) | enforce (remove the user's Gemini Enterprise licence; access stops in about 1-2 minutes)."
  type        = string
  default     = "dry_run"
  validation {
    condition     = contains(["off", "dry_run", "enforce"], var.seat_containment)
    error_message = "seat_containment must be off, dry_run or enforce."
  }
}

variable "seat_contain_exempt" {
  description = "Seat mode: e-mail addresses never auto-contained (break-glass and administrator accounts)."
  type        = list(string)
  default     = []
}

variable "seat_vpc_sc" {
  description = "Seat mode: put the seat API (businessaicode.googleapis.com) in a VPC Service Controls perimeter (project-scoped access policy). Stolen refresh tokens used elsewhere are refused and trigger containment. Needs organisation-level Access Context Manager rights."
  type        = bool
  default     = false
}

variable "seat_vpc_sc_dry_run" {
  description = "Seat perimeter in dry-run (log violations, block nothing). Switch to false after reviewing the dry-run logs."
  type        = bool
  default     = true
}

variable "seat_corp_ip_ranges" {
  description = "Seat perimeter: corporate / SSE egress CIDRs from which seat users outside the protected VPC may call the seat API."
  type        = list(string)
  default     = []
}

variable "seat_device_policy" {
  description = "Seat perimeter: optional device posture access level (Chrome Enterprise Premium + Endpoint Verification)."
  type = object({
    require_corp_owned        = bool
    require_screen_lock       = bool
    allowed_encryption_status = list(string)
    os_types                  = list(string)
  })
  default = null
}

variable "org_id" {
  description = "Organisation ID (needed only for seat_vpc_sc; the installer fills it from the project ancestry)."
  type        = string
  default     = ""
}

variable "consumer_tier_hosts" {
  description = "Hostnames of the consumer/free Antigravity tier to pin away on the endpoint (both client modes). Complements the Workspace block of the consumer OAuth client; take the current host list from your Google account team or your proxy logs."
  type        = list(string)
  default     = []
}

variable "evidence_name_suffix" {
  description = "Suffix for evidence resources that --destroy deliberately preserves (wrapped-key secret, tag key, deny policy). Set it when re-installing with prompt evidence into a project that still holds a preserved evidence set."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[a-z0-9]{0,8}$", var.evidence_name_suffix))
    error_message = "evidence_name_suffix: up to 8 lowercase letters/digits."
  }
}

variable "log_bucket_id" {
  description = "Central security log bucket id (empty = <prefix>-security). Set a new id when re-installing into the same project within 7 days of --destroy (the old bucket stays in DELETE_REQUESTED for 7 days)."
  type        = string
  default     = ""
}

variable "enable_gateway" {
  description = "Deploy the Enterprise Gateway (pay-as-you-go path with inline prompt inspection). false = seat-only: no gateway service, no mTLS front door or device CA; the seat prompt-log inspector still runs. Requires client_mode = seat."
  type        = bool
  default     = true
}

variable "deploy_workstation" {
  description = "Deploy the reference workstation VM (full profile). false = gateway-only profile for your own fleet (requires device_auth_modes = [\"cert\"])."
  type        = bool
  default     = true
}

variable "device_auth_modes" {
  description = "How devices prove themselves to the gateway: gce (Compute Engine identity token + device-bound mTLS, the reference workstation) and/or cert (certificate-only fleet devices such as laptops, from the FLEET CA pool, listed in fleet_devices)."
  type        = list(string)
  default     = ["gce"]
  validation {
    condition     = length(var.device_auth_modes) > 0 && alltrue([for m in var.device_auth_modes : contains(["gce", "cert"], m)])
    error_message = "device_auth_modes must be a non-empty list of gce and/or cert."
  }
}

variable "fleet_devices" {
  description = "Registry of certificate-only devices: device id (the SPIFFE suffix in its certificate) -> the user and group it is assigned to. The gateway takes identity from here, never from the client. Remove an entry to revoke the device."
  type = map(object({
    user  = string
    group = string
  }))
  default = {}
  validation {
    condition     = alltrue([for k in keys(var.fleet_devices) : can(regex("^[a-z0-9][a-z0-9._-]{1,62}$", k))])
    error_message = "fleet_devices keys must be lowercase device ids (letters, digits, . _ -)."
  }
}

variable "fleet_issuers" {
  description = "Principals allowed to request fleet device certificates from the FLEET CA pool (your MDM or enrolment service account), e.g. [\"serviceAccount:mdm@corp.iam.gserviceaccount.com\"]."
  type        = list(string)
  default     = []
}

variable "fleet_selftest" {
  description = "Register the device agy-fleet-selftest so validation can prove the certificate-only path end to end with a 1-hour certificate (full profile; the workstation acts as the in-VPC client)."
  type        = bool
  default     = false
}

variable "fleet_selftest_group" {
  description = "Group the self-test device is assigned to (use the most restricted one)."
  type        = string
  default     = "agy-contractor"
}

variable "inference_project" {
  description = "Project whose Vertex AI quota and billing the model calls use (empty = this project). The gateway injects X-Goog-User-Project with it; the gateway SA gets generate-only + serviceusage.services.use there. Gateway controls (Model Armor, SDP, classifier, logs) stay in this project. The installer needs iam.roles.create and resourcemanager.projects.setIamPolicy on it, and aiplatform.googleapis.com must be enabled there."
  type        = string
  default     = ""
  validation {
    condition     = var.inference_project == "" || can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.inference_project))
    error_message = "inference_project must be empty or a valid project ID."
  }
}

variable "extra_forwarded_headers" {
  description = "Extra request header names forwarded to Vertex AI, on top of the customHeaders in endpoint/files/policies/admin_settings.json. Identity, billing (X-Goog-*), routing and X-AGY-* headers are refused."
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([for h in var.extra_forwarded_headers :
    can(regex("^[A-Za-z0-9][A-Za-z0-9-]{0,63}$", h)) && !can(regex("(?i)^(authorization|host|cookie|x-goog-|x-agy-|x-client-cert-|x-forwarded-|proxy-)", h))])
    error_message = "extra_forwarded_headers must be plain header names and must not be identity, billing or gateway-internal headers."
  }
}

variable "response_flush_ms" {
  description = "Max time (ms) streamed model text is held for sensitive-data inspection before it is sent (time-bound flush)."
  type        = number
  default     = 500
  validation {
    condition     = var.response_flush_ms >= 100 && var.response_flush_ms <= 5000
    error_message = "response_flush_ms must be between 100 and 5000."
  }
}

variable "response_window_chars" {
  description = "Max chars of streamed model text inspected per window (sent earlier if response_flush_ms elapses)."
  type        = number
  default     = 1200
  validation {
    condition     = var.response_window_chars >= 256 && var.response_window_chars <= 20000
    error_message = "response_window_chars must be between 256 and 20000."
  }
}

variable "model_armor_fail_closed" {
  description = "Block prompts if Model Armor is unavailable."
  type        = bool
  default     = true
}

variable "prompt_categories" {
  description = "Admin-defined blocked prompt categories: name -> case-insensitive regex."
  type        = map(string)
  default = {
    port_scanning          = "\\b(nmap|masscan|zmap|syn[ -]?scan|port[ -]?scan(ning|ner)?)\\b|\\bscan(s|ning)?\\b.{0,40}\\b(ports?|subnet|/\\d{1,2})\\b"
    dos                    = "\\b(launch|run|perform|carry out|start|conduct|send|generate)\\b.{0,30}\\b(d?dos|denial[ -]of[ -]service|syn[ -]?flood|udp flood|packet flood|traffic flood)\\b|\\b(slowloris|hping3)\\b|\\bflood\\b.{0,30}\\b(the |a )?(server|host|site|network|target)\\b"
    dlp_evasion            = "\\b(bypass|evade|disable|circumvent|get around|tamper with|uninstall|kill)\\b.{0,40}\\b(dlp|netskope|proxy|edr|jamf|casb|crowdstrike|defender|mdm|apparmor)\\b"
    recon                  = "\\b(network recon(naissance)?|ping[ -]?sweep|subnet[ -]?sweep|enumerate (live )?hosts|arp[ -]?scan|host discovery)\\b"
    credential             = "\\b(dump|extract|steal|crack)\\b.{0,30}\\b(credentials?|passwords?|hashes|lsass|shadow file|tokens?)\\b"
    access_control_evasion = "\\b(bypass|circumvent|disable|defeat|get around|evade)\\b.{0,40}\\b(uac|user account control|access controls?|authentication|mfa|2fa|login checks?|authori[sz]ation|permissions? checks?)\\b"
    endpoint_tampering     = "\\b(disable|turn off|stop|kill|uninstall|evade|bypass|blind|tamper with|get past)\\b.{0,40}\\b(antivirus|anti-virus|symantec|defender|edr|endpoint protection|crowdstrike|sentinelone|security agent)\\b"
    mail_impersonation     = "\\b(send|forge|spoof|fake)\\b.{0,40}\\b(e-?mails?|mail)\\b.{0,40}\\b(on behalf of|as (another|a different) (user|person|employee)|from (someone|another) (else|user)|spoofed|forged)\\b|\\bspoof(ed|ing)?\\b.{0,20}\\b(sender|e-?mail)\\b"
    data_exfiltration      = "\\b(exfiltrat\\w*|smuggle|sneak)\\b.{0,40}\\b(data|files?|records|database|pii)\\b"
    ransomware_like        = "\\bencrypt\\w*\\b.{0,60}\\b(then |and )?(delete|remove|wipe|destroy)\\w*\\b.{0,30}\\b(originals?|source files?|plaintext)\\b|\\b(write|build|create|make)\\b.{0,20}\\bransomware\\b"
    phishing_clone         = "\\b(clone|copy|mirror|replicate)\\b.{0,30}\\b(login|sign-?in|banking|dlp test(ing)?)\\b.{0,20}\\b(page|site|website|portal)\\b|\\b(create|build|send|write)\\b.{0,20}\\bphishing\\b.{0,20}\\b(page|site|e-?mails?|campaign|kit)\\b"
  }
}

variable "grounding_instruction" {
  description = "Corporate instruction appended to every model request's system prompt to reduce unverified claims (empty = off)."
  type        = string
  default     = "Corporate policy: when you report results of commands, scans, tests or file contents, state only what the actual tool output shows. If you did not run a tool, the output is missing or a check failed, say so explicitly instead of inferring a result, and label any statement you could not verify as unverified."
}

variable "classifier_model" {
  description = "Small Gemini model for the LLM intent classifier (empty = off). Called in vertex_location."
  type        = string
  default     = "gemini-3.5-flash-lite"
}

variable "classifier_threshold" {
  description = "Minimum classifier confidence for a block verdict to be enforced."
  type        = number
  default     = 0.7
}

variable "authorized_models" {
  description = <<-EOT
    Antigravity authorized models - MUST mirror Gemini Enterprise > Settings > AI developer tools >
    'Antigravity authorized models' (console is manual; this is the gateway-enforced copy).
    Each level becomes one picker entry "<display> (<Level>)" -> Vertex model + thinkingLevel.
  EOT
  type = map(object({
    display = string
    levels  = list(string)
  }))
  default = {
    "gemini-4-argon"   = { display = "Gemini 4 Argon", levels = ["high", "medium", "low"] }
    "gemini-3.8-flash" = { display = "Gemini 3.8 Flash", levels = ["high", "medium", "low"] }
  }
}

variable "group_policy" {
  description = "Per-group policy: picker models the group may select (subset of authorized_models, empty = all), the Auto tiers (picker ids) and pci_scope (sensitive data is blocked instead of masked)."
  type = map(object({
    allowed = optional(list(string), [])
    tiers = object({
      light   = string
      default = string
      complex = string
    })
    smart_route        = optional(bool, false)
    blocked_categories = optional(list(string), [])
    pci_scope          = optional(bool, false)
    classifier         = optional(string, "enforce")
  }))
  default = {
    "agy-dev" = {
      tiers = { light = "gemini-3.8-flash-low", default = "gemini-3.8-flash-medium", complex = "gemini-4-argon-high" }
    }
    "agy-contractor" = {
      # no Argon for contractors (cost cap); Auto 'complex' capped to Flash (High)
      allowed = ["gemini-3.8-flash-high", "gemini-3.8-flash-medium", "gemini-3.8-flash-low"]
      tiers   = { light = "gemini-3.8-flash-low", default = "gemini-3.8-flash-medium", complex = "gemini-3.8-flash-high" }
      # demo of PCI scope: sensitive data in requests/responses is blocked (dev: masked)
      pci_scope = true
    }
  }
}

variable "sdp_info_types" {
  description = "Sensitive Data Protection info types masked in requests/responses (EU banking, PCI, credentials)."
  type        = list(string)
  default = [
    "CREDIT_CARD_NUMBER", "CREDIT_CARD_TRACK_NUMBER", "IBAN_CODE", "SWIFT_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "PERSON_NAME", "STREET_ADDRESS", "DATE_OF_BIRTH", "PASSPORT", "NETHERLANDS_BSN_NUMBER", "BELGIUM_NATIONAL_ID_CARD_NUMBER",
    "GERMANY_IDENTITY_CARD_NUMBER", "FRANCE_NIR", "IP_ADDRESS", "GCP_CREDENTIALS", "GCP_API_KEY", "AUTH_TOKEN",
    "AWS_CREDENTIALS", "AZURE_AUTH_TOKEN", "ENCRYPTION_KEY", "PASSWORD", "JSON_WEB_TOKEN", "HTTP_COOKIE",
  ]
}

variable "sdp_checksum_info_types" {
  description = "Info types with built-in checksums (Luhn / ISO 13616): masked from POSSIBLE so bare values without context words are caught."
  type        = list(string)
  default     = ["CREDIT_CARD_NUMBER", "CREDIT_CARD_TRACK_NUMBER", "IBAN_CODE"]
}

variable "sdp_min_likelihood" {
  description = "Minimum SDP likelihood for masking (POSSIBLE | LIKELY | VERY_LIKELY). Lower = more masking, more false positives."
  type        = string
  default     = "LIKELY"
  validation {
    condition     = contains(["POSSIBLE", "LIKELY", "VERY_LIKELY"], var.sdp_min_likelihood)
    error_message = "sdp_min_likelihood must be POSSIBLE, LIKELY or VERY_LIKELY."
  }
}

variable "device_instance_prefixes" {
  description = "GCE instance-name prefixes accepted as managed devices (identity token check at the gateway)."
  type        = list(string)
  default     = ["agy-dev-ws"]
}

# ----------------------------------------------------------------------------- security / ops
variable "enable_cmek" {
  description = "Encrypt disks, bucket, registry, secrets and Cloud Run with a CMEK key."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Retention of the central security log bucket."
  type        = number
  default     = 30
}

variable "log_lock_days" {
  description = <<-EOT
    Lock the security, SIEM and audit log buckets so nobody (incl. project owners) can delete logs or shorten retention.
    0 = not locked. N > 0 = the buckets are locked and their retention is fixed at N days: Cloud Logging fixes the
    retention when a bucket is locked, irreversibly. A locked log bucket does not block deleting the project.
    Test projects: 2. Production: 400 or more (BIO / PCI DSS v4: >= 12 months).
  EOT
  type        = number
  default     = 0
  validation {
    condition     = var.log_lock_days == 0 || (var.log_lock_days >= 1 && var.log_lock_days <= 3650)
    error_message = "log_lock_days must be 0 (no lock) or 1-3650."
  }
}

variable "audit_log_retention_days" {
  description = "Retention of the audit log bucket (Admin Activity, Data Access, System Event, Policy Denied; your region, CMEK). Ignored when log_lock_days > 0 (the lock fixes the retention)."
  type        = number
  default     = 400
  validation {
    condition     = var.audit_log_retention_days >= 1 && var.audit_log_retention_days <= 3650
    error_message = "audit_log_retention_days must be 1-3650."
  }
}

variable "vpc_egress_restricted" {
  description = "Deny-by-default VPC egress: workstations may reach the internet on TCP 80/443 only (the device allowlist filters destinations per persona) and Google APIs; every other port and protocol is denied and logged, for every account on the VM."
  type        = bool
  default     = true
}

variable "enable_bigquery_sink" {
  description = "Export security events to BigQuery (EU) for Looker Studio reporting."
  type        = bool
  default     = true
}

variable "enable_saved_queries" {
  description = "Create shared Log Analytics saved queries for the security events (POC evidence). Off by default."
  type        = bool
  default     = false
}

# ----------------------------------------------------------------- device mTLS front door
variable "enable_mtls" {
  description = "Deploy the CAS + internal ALB (frontend mTLS) front door for the gateway."
  type        = bool
  default     = true
}

variable "proxy_subnet_cidr" {
  description = "Proxy-only subnet for the regional internal Application Load Balancer."
  type        = string
  default     = "10.40.1.0/24"
}

variable "internal_dns_domain" {
  description = "Private Cloud DNS zone for internal service names."
  type        = string
  default     = "agy.internal"
}

variable "gateway_mtls_hostname" {
  description = "Private hostname of the mTLS gateway front door."
  type        = string
  default     = "gateway.agy.internal"
}

variable "require_mtls" {
  description = "Cut-over: credproxy uses the mTLS front door and the gateway requires a verified, device-bound client certificate. false = instant rollback to the direct path."
  type        = bool
  default     = true
}

variable "cas_template_suffix" {
  description = "Optional suffix for the device certificate template ID. Set on re-install into a project where the template was previously deleted (CAS IDs are not reusable)."
  type        = string
  default     = ""
  validation {
    condition     = can(regex("^[a-z0-9]{0,8}$", var.cas_template_suffix))
    error_message = "cas_template_suffix: up to 8 lowercase letters/digits."
  }
}

variable "seat_model_policy" {
  description = "Seat mode: allowed Gemini Enterprise catalogue models per policy group (exact IDs incl. effort, e.g. gemini-3.8-flash-low, or a prefix ending in *). Empty = model checks off. Used by the workstation hook and the prompt-log inspector (detect + respond); the preventive control is the console authorized-models list."
  type        = map(list(string))
  default     = {}
  validation {
    condition     = alltrue([for g, l in var.seat_model_policy : alltrue([for m in l : can(regex("^[a-z0-9][a-z0-9.-]*\\*?$", m))])])
    error_message = "seat_model_policy: entries must be lowercase catalogue IDs, optionally ending in * (prefix match)."
  }
}

variable "seat_aux_models" {
  description = "Seat mode: client-internal helper models that are never flagged by model checks (not user-selectable)."
  type        = list(string)
  default     = ["gemini-3.5-flash-lite"]
}

variable "seat_model_contain_after" {
  description = "Seat mode: off-policy model uses per user per hour before the inspector requests containment (follows seat_containment: off | dry_run | enforce)."
  type        = number
  default     = 3
  validation {
    condition     = var.seat_model_contain_after >= 1
    error_message = "seat_model_contain_after must be at least 1."
  }
}

variable "enable_siem" {
  description = "BigQuery SIEM: dedicated analytics log bucket (CMEK, this region) + linked BigQuery dataset + normalised views (endpoint Linux/Windows, gateway, timeline) + scheduled detections."
  type        = bool
  default     = true
}

variable "siem_retention_days" {
  description = "SIEM retention in days (log bucket and detections table). 400 covers BIO and PCI DSS v4 (>= 12 months, 3 months immediately available)."
  type        = number
  default     = 400
  validation {
    condition     = var.siem_retention_days >= 1 && var.siem_retention_days <= 3650
    error_message = "siem_retention_days must be between 1 and 3650 (compliance baselines usually need 400; short retention is a documented customer choice)."
  }
}

variable "siem_detection_schedule" {
  description = "Schedule of the SIEM detection query (BigQuery scheduled query syntax)."
  type        = string
  default     = "every 15 minutes"
}

variable "siem_probe_threshold" {
  description = "Detection D1: hook denials per user and VM within the detection window that count as probing."
  type        = number
  default     = 5
}

variable "siem_viewer_members" {
  description = "SOC analysts (e.g. group:soc@example.com): read the SIEM views dataset and only this SIEM log bucket."
  type        = list(string)
  default     = []
}

variable "deploy_windows_workstation" {
  description = "Deploy the Windows reference workstation (Windows Server 2025, licence-included) next to the Linux one, in the same client mode."
  type        = bool
  default     = false
}

variable "windows_image" {
  description = "Windows boot image: the custom sysprepped image family built by windows/image (e.g. projects/<PROJECT_ID>/global/images/family/agy-win2025-dev), or the public licence-included family until it exists."
  type        = string
  default     = "projects/windows-cloud/global/images/family/windows-2025"
  validation {
    condition     = can(regex("^projects/[a-z0-9-]+/global/images/(family/)?[a-z0-9-]+$", var.windows_image))
    error_message = "windows_image must be projects/<project>/global/images/[family/]<name>."
  }
}

variable "windows_machine_type" {
  description = "Machine type of the Windows workstation (Intel recommended for the vTPM-backed credential proxy and Hyper-V features)."
  type        = string
  default     = "e2-standard-4"
}

variable "windows_boot_disk_gb" {
  description = "Windows boot disk size (GB)."
  type        = number
  default     = 100
}

variable "agy_cli_manifest_url_windows" {
  description = "Official Antigravity CLI update manifest for windows_amd64 (the binary is pinned by the sha512 it lists)."
  type        = string
  default     = "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/windows_amd64.json"
}

variable "enable_windows_image_pipeline" {
  description = "Create the least-privilege identities and IAP WinRM rule for the Windows image pipeline (Packer on Cloud Build, `make windows-image`)."
  type        = bool
  default     = false
}

variable "agent_service_accounts" {
  description = "Per persona group (agy-dev, agy-contractor): service account the AGENT must use for gcloud / bq / gsutil / terraform (hook-enforced impersonation). Grant it the agent tier's roles only (T0 sandbox project / T1 read-only / none). Empty = no agent gcloud identity enforced (token / config verbs stay denied)."
  type        = map(string)
  default     = {}
  validation {
    condition     = alltrue([for g, sa in var.agent_service_accounts : contains(["agy-dev", "agy-contractor"], g) && can(regex("^[a-z][a-z0-9-]{4,29}@[a-z][a-z0-9-]{4,29}\\.iam\\.gserviceaccount\\.com$", sa))])
    error_message = "agent_service_accounts: keys agy-dev / agy-contractor, values user-managed service account emails (<name>@<project>.iam.gserviceaccount.com)."
  }
}

variable "windows_corp_script_publisher" {
  description = "AppLocker publisher (certificate subject, e.g. \"O=CONTOSO LTD, L=AMSTERDAM, C=NL\") whose signed PowerShell scripts / modules run in FullLanguage for developers, next to Microsoft-signed ones. Empty = Microsoft only."
  type        = string
  default     = ""
}

variable "enable_package_proxy" {
  description = "Corporate package proxy: Artifact Registry remote repositories (var.region, CMEK) for npm / PyPI / Maven / Go (/ Docker). Workstations get the client endpoints; public_registry_hosts leave the egress allowlist."
  type        = bool
  default     = false
}

variable "package_proxy_formats" {
  description = "Remote repositories to create: any of npm, python, maven, go, docker."
  type        = list(string)
  default     = ["npm", "python", "maven", "go"]
}

variable "package_proxy_readers" {
  description = "Principals allowed to pull through the proxy (people / groups, e.g. group:developers@example.com)."
  type        = list(string)
  default     = []
}

variable "nuget_feed_url" {
  description = "NuGet v3 feed that proxies nuget.org (Azure Artifacts EU organisation, Nexus, Artifactory); Artifact Registry has no NuGet remote. Written as the only machine-wide NuGet source with package source mapping. Empty = unchanged."
  type        = string
  default     = ""
  validation {
    condition     = var.nuget_feed_url == "" || can(regex("^https://[^\\s]+/index\\.json$", var.nuget_feed_url))
    error_message = "nuget_feed_url must be an https NuGet v3 service index (.../index.json)."
  }
}

variable "public_registry_hosts" {
  description = "Public package registry hosts removed from every persona's egress allowlist when enable_package_proxy = true."
  type        = list(string)
  default = [
    # sum.golang.org stays: Go's checksum database (integrity), not a package source
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com", "proxy.golang.org",
    "repo.maven.apache.org", "repo1.maven.org", "api.nuget.org", "www.nuget.org", "registry-1.docker.io", "index.docker.io",
  ]
}

variable "tunnel_hosts" {
  description = "Inbound-tunnel service hosts pinned to 0.0.0.0 on every workstation (exact names; the IP allowlist already drops them unless allowlisted)."
  type        = list(string)
  default = [
    "global.rel.tunnels.api.visualstudio.com", "tunnels.api.visualstudio.com", "connect.ngrok-agent.com", "tunnel.eu.ngrok.com",
    "tunnel.us.ngrok.com", "api.ngrok.com", "api.trycloudflare.com", "region1.v2.argotunnel.com", "region2.v2.argotunnel.com",
    "localtunnel.me", "loca.lt", "bore.pub",
  ]
}

variable "linux_pkg_allowlist" {
  description = "Linux workstations: packages developers may install with `sudo agy-pkg install <pkg>` (the only root action; no general sudo). Ships empty: add packages your catalog approves, e.g. [\"jq\", \"make\"]."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for p in var.linux_pkg_allowlist : can(regex("^[a-z0-9][a-z0-9+.-]{1,62}$", p))])
    error_message = "linux_pkg_allowlist: Debian package names only."
  }
}

variable "browser_allowlist" {
  description = "Extra hosts the agent's browser may open, on top of localhost and 127.0.0.1 (managed, read-only browserAllowlist.txt per persona). A leading \"*.\" matches subdomains."
  type        = list(string)
  default     = []
  validation {
    condition     = alltrue([for h in var.browser_allowlist : can(regex("^(\\*\\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", h))])
    error_message = "browser_allowlist: lower-case host names only (optionally prefixed with \"*.\")."
  }
}

variable "windows_wdac_mode" {
  description = "WDAC base policy on the Windows workstation: Audit (log would-be blocks, events 3076 -> SIEM) or Enforce. Start with Audit, review the SIEM, then enforce."
  type        = string
  default     = "Audit"
  validation {
    condition     = contains(["Audit", "Enforce"], var.windows_wdac_mode)
    error_message = "windows_wdac_mode must be Audit or Enforce."
  }
}

# ---------------------------------------------------------------- device telemetry (laptops, no gateway)
variable "enable_telemetry" {
  description = "Devices ship AGY security events to Cloud Logging / the SIEM with a write-only identity from your PKI (Workload Identity Federation, X.509). Needs device_trust_anchor_files."
  type        = bool
  default     = false
}

variable "device_trust_anchor_files" {
  description = "Root / issuing CA certificate files (PEM) of your PKI that issue device certificates; relative paths are relative to the repository root. 1-3 files."
  type        = list(string)
  default     = []
}

variable "device_intermediate_files" {
  description = "Intermediate CA certificate files (PEM) of your PKI, if the devices don't send them (max 10)."
  type        = list(string)
  default     = []
}

variable "device_subject_cn_regex" {
  description = "Pattern (RE2) the device certificate subject CN must match; the CN becomes the device id in the logs."
  type        = string
  default     = "^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$"
}

variable "device_issuer_cn" {
  description = "Optional: only certificates issued by the CA with this CN are accepted (empty = any CA of the trust anchors)."
  type        = string
  default     = ""
}

# ----------------------------------------------------------------- cost per persona (pay-as-you-go)
variable "billing_labels" {
  description = "The gateway labels every Vertex AI call with agy_persona and agy_device (from the authenticated identity; client labels are replaced). Needed for cost per persona in billing and for persona_budgets."
  type        = bool
  default     = false
}

variable "billing_account" {
  description = "Billing account id (XXXXXX-XXXXXX-XXXXXX) for persona_budgets. Empty = no budgets."
  type        = string
  default     = ""
  validation {
    condition     = var.billing_account == "" || can(regex("^[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$", var.billing_account))
    error_message = "billing_account must be empty or XXXXXX-XXXXXX-XXXXXX."
  }
}

variable "persona_budgets" {
  description = "Monthly budget alert per persona (key = persona without the agy- prefix, e.g. dev, contractor), in the billing account's currency. Counts the Vertex AI spend labelled agy_persona=<key> in the inference project. Alerts only: a budget never stops spend."
  type = map(object({
    amount     = number
    thresholds = optional(list(number), [0.5, 0.9, 1.0])
  }))
  default = {}
  validation {
    condition     = alltrue([for k, b in var.persona_budgets : can(regex("^[a-z0-9_-]{1,63}$", k)) && b.amount > 0 && alltrue([for t in b.thresholds : t > 0 && t <= 2])])
    error_message = "persona_budgets: keys are label values (a-z0-9_-), amount > 0, thresholds in (0, 2]."
  }
}

variable "model_prices_usd_per_mtok" {
  description = "Indicative list prices per million tokens (input, output incl. thinking) per Vertex model, for the v_persona_usage cost estimate. The billing export stays the authoritative cost."
  type = map(object({
    input  = number
    output = number
  }))
  default = {}
}
