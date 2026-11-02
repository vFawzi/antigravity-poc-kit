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

locals {
  evidence_on = contains(["deidentified", "evidence"], var.prompt_logging)
  # Header names the gateway forwards to Vertex AI = admin customHeaders (single source: the managed admin file)
  # + extra_forwarded_headers. Reserved identity/billing headers are refused by the gateway at startup.
  admin_custom_headers = keys(try(jsondecode(file("${path.root}/../vm/files/policies/admin_settings.json")).gateway.customHeaders, {}))
  forward_headers      = distinct([for h in concat(local.admin_custom_headers, var.extra_forwarded_headers) : lower(h)])
  # certificate-only device registry (+ the installer's short-lived self-test device, mapped to the most restricted group)
  # Seat mode: the only Antigravity hosts left reachable are the business control plane and the pinned licence location.
  # Optional consumer/free-tier hosts (consumer_tier_hosts) are pinned away in both modes; the primary control is the
  # Workspace block of the consumer OAuth client (Admin checklist).
  seat_project = var.seat_project == "" ? var.project_id : var.seat_project
  seat_hosts   = distinct(["cloudcode-pa.googleapis.com", "businessaicode.googleapis.com", var.seat_location == "global" ? "businessaicode.googleapis.com" : "businessaicode.${var.seat_location}.rep.googleapis.com"])
  # client_mode = mixed deploys both sides; every device runs one mode (reference workstations below, laptops via the
  # agy-client-mode setting), so hosts pins and egress allowlists are computed per device mode
  seat_on = contains(["seat", "mixed"], var.client_mode)
  # gateway deployed: an image built and the gateway module selected (seat-only compositions can leave it out; the seat
  # inspector keeps running on the same image and engines)
  gw_on       = var.enable_gateway && var.gateway_image != ""
  gateway_on  = contains(["gateway", "mixed"], var.client_mode)
  ws_mode     = var.workstation_client_mode != "" ? var.workstation_client_mode : (var.client_mode == "mixed" ? "seat" : var.client_mode)
  win_ws_mode = var.windows_workstation_client_mode != "" ? var.windows_workstation_client_mode : (var.client_mode == "mixed" ? "seat" : var.client_mode)
  pin_for = {
    seat    = distinct(concat([for h in distinct(concat(var.hosts_pin, var.consumer_tier_hosts)) : h if !contains(local.seat_hosts, h)], var.tunnel_hosts))
    gateway = distinct(concat(var.hosts_pin, var.consumer_tier_hosts, var.tunnel_hosts))
  }
  effective_pin = local.pin_for[local.ws_mode]
  # corporate package proxy: public registries leave the allowlist, the Artifact Registry endpoints (+ token endpoint) join it
  proxy_hosts = var.enable_package_proxy ? concat(module.package_proxy[0].hosts, ["oauth2.googleapis.com"]) : []
  base_egress = var.enable_package_proxy ? { for g, l in var.egress_allowlist : g => distinct(concat([for h in l : h if !contains(var.public_registry_hosts, h)], local.proxy_hosts)) } : var.egress_allowlist
  # personas talk to Google directly in seat mode: allow the seat hosts + OAuth token endpoints (IP-level; host-level restriction = hosts pins / SSE)
  egress_for = {
    seat    = { for g, l in local.base_egress : g => distinct(concat(l, local.seat_hosts, ["oauth2.googleapis.com", "openidconnect.googleapis.com"], var.seat_signin_hosts)) }
    gateway = local.base_egress
  }
  effective_egress   = local.egress_for[local.ws_mode]
  package_proxy_json = jsonencode(var.enable_package_proxy ? merge(module.package_proxy[0].endpoints, var.nuget_feed_url == "" ? {} : { nuget = var.nuget_feed_url }) : (var.nuget_feed_url == "" ? {} : { nuget = var.nuget_feed_url }))
  fleet_devices = merge(var.fleet_devices, var.fleet_selftest ? {
    "agy-fleet-selftest" = { user = "fleet-selftest@agy.invalid", group = var.fleet_selftest_group }
  } : {})
  labels = var.labels
  p      = var.name_prefix

  services = [
    "compute.googleapis.com", "run.googleapis.com", "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com", "modelarmor.googleapis.com", "secretmanager.googleapis.com",
    "logging.googleapis.com", "monitoring.googleapis.com", "iap.googleapis.com",
    "cloudkms.googleapis.com", "storage.googleapis.com", "bigquery.googleapis.com", "bigquerydatatransfer.googleapis.com",
    "oslogin.googleapis.com", "iam.googleapis.com", "sts.googleapis.com", "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com", "businessaicode.googleapis.com",
    "aiplatform.googleapis.com", "cloudaicompanion.googleapis.com", "discoveryengine.googleapis.com",
    "privateca.googleapis.com", "certificatemanager.googleapis.com", "networksecurity.googleapis.com", "dns.googleapis.com",
    "dlp.googleapis.com", "privilegedaccessmanager.googleapis.com", "pubsub.googleapis.com", "cloudidentity.googleapis.com",
  ]
  budgets_on = var.billing_account != "" && length(var.persona_budgets) > 0
}

resource "google_project_service" "svc" {
  for_each                   = toset(concat(local.services, local.budgets_on ? ["billingbudgets.googleapis.com", "cloudbilling.googleapis.com"] : []))
  project                    = var.project_id
  service                    = each.value
  disable_on_destroy         = false
  disable_dependent_services = false
}

resource "random_id" "suffix" {
  byte_length = 3
}

# Secret the internal LB injects so the gateway can tell LB traffic from direct VPC calls to *.run.app
resource "random_password" "lb_header" {
  length  = 40
  special = false
}

module "security" {
  source      = "./modules/security"
  project_id  = var.project_id
  region      = var.region
  prefix      = local.p
  suffix      = random_id.suffix.hex
  enable_cmek = var.enable_cmek
  depends_on  = [google_project_service.svc]
}

module "network" {
  source            = "./modules/network"
  project_id        = var.project_id
  region            = var.region
  prefix            = local.p
  subnet_cidr       = var.subnet_cidr
  enable_rdp        = var.desktop_access == "xrdp" || var.deploy_windows_workstation
  egress_restricted = var.vpc_egress_restricted
  depends_on        = [google_project_service.svc]
}

module "gateway" {
  source                   = "./modules/gateway"
  project_id               = var.project_id
  region                   = var.region
  prefix                   = local.p
  kms_key                  = module.security.kms_key
  image                    = var.gateway_image
  deploy_gateway           = var.enable_gateway
  vertex_location          = var.vertex_location
  ingress                  = var.gateway_ingress
  device_prefixes          = distinct(concat(var.device_instance_prefixes, var.deploy_windows_workstation && local.win_ws_mode == "gateway" ? ["${local.p}-win-ws"] : []))
  group_policy             = var.group_policy
  authorized_models        = var.authorized_models
  prompt_categories        = var.prompt_categories
  prompt_logging           = var.prompt_logging
  sdp_info_types           = var.sdp_info_types
  classifier_model         = var.classifier_model
  grounding                = var.grounding_instruction
  classifier_threshold     = var.classifier_threshold
  sdp_likelihood           = var.sdp_min_likelihood
  sdp_checksum_types       = var.sdp_checksum_info_types
  evidence                 = local.evidence_on ? module.evidence[0] : null
  ma_fail_closed           = var.model_armor_fail_closed
  block_mode               = var.gateway_block_response_mode
  require_mtls             = var.enable_mtls && var.require_mtls
  lb_header_secret         = random_password.lb_header.result
  spiffe_prefix            = "spiffe://${var.project_id}.${var.internal_dns_domain}/device/"
  forward_headers          = local.forward_headers
  inference_project        = var.inference_project
  seat_inspector           = local.seat_on
  seat_default_group       = var.seat_default_group
  seat_user_groups         = var.seat_user_groups
  seat_containment         = var.seat_containment
  seat_contain_exempt      = var.seat_contain_exempt
  seat_model_policy        = var.seat_model_policy
  seat_aux_models          = var.seat_aux_models
  seat_model_contain_after = var.seat_model_contain_after
  seat_project             = local.seat_project
  seat_location            = var.seat_location
  seat_vpc_sc              = local.seat_on && var.seat_vpc_sc
  cmek_enabled             = var.enable_cmek
  device_auth_modes        = var.device_auth_modes
  fleet_spiffe_prefix      = contains(var.device_auth_modes, "cert") ? "spiffe://${var.project_id}.${var.internal_dns_domain}/fleet/" : ""
  fleet_devices            = local.fleet_devices
  response_flush_ms        = var.response_flush_ms
  response_window_chars    = var.response_window_chars
  billing_labels           = var.billing_labels
  depends_on               = [module.security]
}

module "workstation" {
  count                  = var.deploy_workstation ? 1 : 0
  source                 = "./modules/workstation"
  project_id             = var.project_id
  region                 = var.region
  zone                   = var.zone
  prefix                 = local.p
  suffix                 = random_id.suffix.hex
  kms_key                = module.security.kms_key
  subnet_id              = module.network.subnet_id
  operator_principals    = var.operator_principals
  machine_type           = var.machine_type
  boot_disk_gb           = var.boot_disk_gb
  snapshot_every_hours   = var.snapshot_every_hours
  snapshot_retention     = var.snapshot_retention_days
  labels                 = var.labels
  data_disk_gb           = var.data_disk_gb
  secure_disk_gb         = var.secure_disk_gb
  apparmor_mode          = var.apparmor_mode
  install_desktop        = var.install_desktop
  agy_cli_manifest_url   = var.agy_cli_manifest_url
  agy_cli_sha512         = var.agy_cli_sha512
  agy_desktop_object     = var.agy_desktop_object
  agy_desktop_sha256     = var.agy_desktop_sha256
  hosts_pin              = local.effective_pin
  egress_allowlist       = local.effective_egress
  client_mode            = local.ws_mode
  seat_project           = local.seat_project
  seat_location          = var.seat_location
  agent_service_accounts = jsonencode(var.agent_service_accounts)
  pkg_allowlist          = var.linux_pkg_allowlist
  browser_allowlist      = var.browser_allowlist
  package_proxy          = local.package_proxy_json
  seat_model_policy_json = local.seat_on && length(var.seat_model_policy) > 0 ? jsonencode({
    groups = var.seat_model_policy, aux = var.seat_aux_models
  }) : ""
  desktop_access     = var.desktop_access
  cost_center        = lookup(var.labels, "cost_center", "unset")
  rdp_clipboard      = var.rdp_clipboard
  desktop_personas   = var.desktop_personas
  gateway_url        = (var.enable_mtls && var.require_mtls && local.gw_on ? "https://${var.gateway_mtls_hostname}" : module.gateway.url)
  gateway_direct_url = module.gateway.url
  mtls_enabled       = var.enable_mtls && var.require_mtls && local.gw_on
  device_ca_pool     = var.enable_mtls && local.gw_on ? module.mtls[0].ca_pool_name : ""
  device_template    = var.enable_mtls && local.gw_on ? module.mtls[0].device_template : ""
  spiffe_prefix      = "spiffe://${var.project_id}.${var.internal_dns_domain}/device/"
  bootstrap_path     = "${path.root}/../vm/bootstrap.sh"
  vm_files_dir       = "${path.root}/../vm/files"
  device_root_pem    = var.enable_mtls && local.gw_on ? module.mtls[0].server_root_pem : ""
  depends_on         = [module.security, module.network]
}

module "observability" {
  source                   = "./modules/observability"
  project_id               = var.project_id
  region                   = var.region
  prefix                   = local.p
  kms_key                  = module.security.kms_key
  secops_email             = var.secops_email
  log_retention_days       = var.log_retention_days
  log_lock_days            = var.log_lock_days
  audit_log_retention_days = var.audit_log_retention_days
  enable_bigquery_sink     = var.enable_bigquery_sink
  enable_saved_queries     = var.enable_saved_queries
  log_bucket_id            = var.log_bucket_id
  depends_on               = [google_project_service.svc]
}

module "workstation_windows" {
  count                = var.deploy_windows_workstation ? 1 : 0
  source               = "./modules/workstation_windows"
  project_id           = var.project_id
  region               = var.region
  zone                 = var.zone
  prefix               = local.p
  suffix               = random_id.suffix.hex
  kms_key              = module.security.kms_key
  subnet_id            = module.network.subnet_id
  operator_principals  = var.operator_principals
  image                = var.windows_image
  machine_type         = var.windows_machine_type
  boot_disk_gb         = var.windows_boot_disk_gb
  data_disk_gb         = var.data_disk_gb
  snapshot_every_hours = var.snapshot_every_hours
  snapshot_retention   = var.snapshot_retention_days
  labels               = var.labels
  personas             = var.desktop_personas
  client_mode          = local.win_ws_mode
  seat_project         = local.seat_project
  seat_location        = var.seat_location
  egress_allowlist     = local.egress_for[local.win_ws_mode]
  hosts_pin            = local.pin_for[local.win_ws_mode]
  gateway_url          = (var.enable_mtls && var.require_mtls && local.gw_on ? "https://${var.gateway_mtls_hostname}" : module.gateway.url)
  agy_cli_manifest_url = var.agy_cli_manifest_url_windows
  # gateway-mode Windows workstation: device certificate from the device CA pool (same template as Linux)
  device_ca_pool         = var.enable_mtls && local.gw_on && local.win_ws_mode == "gateway" ? module.mtls[0].ca_pool_name : ""
  device_template        = var.enable_mtls && local.gw_on && local.win_ws_mode == "gateway" ? module.mtls[0].device_template : ""
  spiffe_prefix          = "spiffe://${var.project_id}.${var.internal_dns_domain}/device/"
  device_root_pem        = var.enable_mtls && local.gw_on && local.win_ws_mode == "gateway" ? module.mtls[0].server_root_pem : ""
  rdp_clipboard          = var.rdp_clipboard
  bootstrap_path         = "${path.root}/../windows/bootstrap.ps1"
  files_dir              = "${path.root}/../windows"
  wdac_mode              = var.windows_wdac_mode
  agent_service_accounts = jsonencode(var.agent_service_accounts)
  browser_allowlist      = var.browser_allowlist
  package_proxy          = local.package_proxy_json
  corp_script_publisher  = var.windows_corp_script_publisher
  depends_on             = [module.security, module.network]
}

module "package_proxy" {
  count             = var.enable_package_proxy ? 1 : 0
  source            = "./modules/package_proxy"
  project_id        = var.project_id
  region            = var.region
  prefix            = local.p
  kms_key           = module.security.kms_key
  labels            = var.labels
  formats           = var.package_proxy_formats
  reader_principals = var.package_proxy_readers
  depends_on        = [google_project_service.svc, module.security]
}

module "image_pipeline" {
  count         = var.enable_windows_image_pipeline ? 1 : 0
  source        = "./modules/image_pipeline"
  project_id    = var.project_id
  prefix        = local.p
  network_id    = module.network.network_id
  repo_region   = var.region
  repo_name     = "${local.p}-images"
  source_bucket = module.gateway.build_bucket
  depends_on    = [google_project_service.svc, module.gateway]
}

module "siem" {
  count              = var.enable_siem ? 1 : 0
  source             = "./modules/siem"
  project_id         = var.project_id
  region             = var.region
  prefix             = local.p
  kms_key            = module.security.kms_key
  retention_days     = var.siem_retention_days
  lock_days          = var.log_lock_days
  log_filter         = module.observability.security_filter
  detection_schedule = var.siem_detection_schedule
  probe_threshold    = var.siem_probe_threshold
  viewer_members     = var.siem_viewer_members
  labels             = merge(local.labels, { data_classification = "confidential" })
  model_prices       = var.model_prices_usd_per_mtok
  depends_on         = [google_project_service.svc, module.observability]
}

# ----------------------------------------------------------------- per-persona budgets (pay-as-you-go cost alerts)
data "google_project" "inference" {
  count      = local.budgets_on ? 1 : 0
  project_id = var.inference_project != "" ? var.inference_project : var.project_id
  lifecycle {
    precondition {
      condition     = var.billing_labels
      error_message = "persona_budgets need billing_labels = true (the budgets filter on the agy_persona label)."
    }
  }
}

module "budget" {
  count                 = local.budgets_on ? 1 : 0
  source                = "./modules/budget"
  project_number        = data.google_project.inference[0].number
  billing_account       = var.billing_account
  prefix                = local.p
  budgets               = { for k, b in var.persona_budgets : k => { amount = b.amount, thresholds = b.thresholds } }
  notification_channels = [module.observability.notification_channel]
  depends_on            = [google_project_service.svc]
}

module "mtls" {
  count                   = var.enable_mtls && local.gw_on ? 1 : 0
  source                  = "./modules/mtls"
  project_id              = var.project_id
  region                  = var.region
  prefix                  = local.p
  suffix                  = random_id.suffix.hex
  template_name_suffix    = var.cas_template_suffix
  network_id              = module.network.network_id
  subnet_id               = module.network.subnet_id
  proxy_subnet_cidr       = var.proxy_subnet_cidr
  cloud_run_service       = module.gateway.service_name
  gateway_hostname        = var.gateway_mtls_hostname
  dns_zone_domain         = var.internal_dns_domain
  lb_header_secret        = random_password.lb_header.result
  device_requester        = var.deploy_workstation ? module.workstation[0].vm_sa_email : ""
  extra_device_requesters = var.deploy_windows_workstation && local.win_ws_mode == "gateway" ? { windows = module.workstation_windows[0].vm_sa_email } : {}
  enable_fleet            = contains(var.device_auth_modes, "cert")
  fleet_issuers           = var.fleet_issuers
  depends_on              = [google_project_service.svc, module.gateway]
}

module "evidence" {
  count                = local.evidence_on ? 1 : 0
  source               = "./modules/evidence"
  project_id           = var.project_id
  region               = var.region
  prefix               = local.p
  suffix               = random_id.suffix.hex
  mode                 = var.prompt_logging
  kms_key              = module.security.kms_key
  retention_days       = var.evidence_retention_days
  gateway_sa           = module.gateway.sa_email
  name_suffix          = var.evidence_name_suffix
  investigators        = var.investigators
  approvers            = var.investigation_approvers
  labels               = var.labels
  notification_channel = module.observability.notification_channel
  depends_on           = [google_project_service.svc]
}

data "google_project" "seat" {
  count      = local.seat_on && var.seat_vpc_sc ? 1 : 0
  project_id = local.seat_project
}

data "google_project" "self" {
  count      = local.seat_on && var.seat_vpc_sc ? 1 : 0
  project_id = var.project_id
}

module "seat_perimeter" {
  count                          = local.seat_on && var.seat_vpc_sc ? 1 : 0
  source                         = "./modules/seat_perimeter"
  org_id                         = var.org_id
  prefix                         = local.p
  seat_project_number            = data.google_project.seat[0].number
  trusted_source_project_numbers = local.seat_project == var.project_id ? [] : [data.google_project.self[0].number]
  corp_ip_ranges                 = var.seat_corp_ip_ranges
  device_policy                  = var.seat_device_policy
  dry_run                        = var.seat_vpc_sc_dry_run
}

# the reference workstation became optional (gateway-only profile): keep the existing state address
moved {
  from = module.workstation
  to   = module.workstation[0]
}

# cross-variable guardrails (fail the plan, never deploy a gateway no client can reach)
resource "terraform_data" "config_guard" {
  lifecycle {
    precondition {
      condition     = !contains(var.device_auth_modes, "cert") || (var.enable_mtls && var.require_mtls)
      error_message = "device_auth_modes \"cert\" needs enable_mtls = true and require_mtls = true (the internal LB verifies the device certificate)."
    }
    precondition {
      condition     = var.deploy_workstation || contains(var.device_auth_modes, "cert")
      error_message = "Without the reference workstation (deploy_workstation = false) only certificate-only devices can connect: set device_auth_modes = [\"cert\"]."
    }
    precondition {
      condition     = !(local.seat_on && var.seat_vpc_sc) || var.org_id != ""
      error_message = "seat_vpc_sc needs org_id (the installer fills it automatically)."
    }
    precondition {
      condition     = var.client_mode != "seat" || var.deploy_workstation
      error_message = "client_mode = \"seat\" configures the reference workstation; it needs deploy_workstation = true (full profile)."
    }
    precondition {
      condition     = !var.fleet_selftest || contains(keys(var.group_policy), var.fleet_selftest_group)
      error_message = "fleet_selftest_group must be a group in group_policy."
    }
  }
}

# ----------------------------------------------------------------- seat users: may use the Gemini Enterprise seat
# (least privilege: only roles/discoveryengine.agentspaceUser, only on the seat project)
module "groups" {
  source           = "./modules/groups"
  mode             = var.groups_mode
  customer_id      = var.cloud_identity_customer_id
  domain           = var.groups_domain
  dev_group        = var.dev_group
  contractor_group = var.contractor_group
  prefix           = local.p
  depends_on       = [google_project_service.svc]
}

locals {
  # developers group = seat users by default (contractors use the gateway)
  seat_members = local.seat_on ? toset(concat(var.seat_users, [for e in keys(var.seat_user_groups) : "user:${e}"],
  module.groups.dev_group == "" ? [] : ["group:${module.groups.dev_group}"])) : toset([])
}

resource "google_project_iam_member" "seat_users" {
  for_each = local.seat_members
  project  = local.seat_project
  role     = "roles/discoveryengine.agentspaceUser"
  member   = each.value
}

module "telemetry" {
  count             = var.enable_telemetry ? 1 : 0
  source            = "./modules/telemetry"
  project_id        = var.project_id
  prefix            = local.p
  trust_anchor_pems = [for f in var.device_trust_anchor_files : trimspace(file(startswith(f, "/") ? f : "${path.root}/../${f}"))] # the API rejects a trailing newline
  intermediate_pems = [for f in var.device_intermediate_files : trimspace(file(startswith(f, "/") ? f : "${path.root}/../${f}"))]
  subject_cn_regex  = var.device_subject_cn_regex
  issuer_cn         = var.device_issuer_cn
  depends_on        = [google_project_service.svc]
}

# composition guard: a seat-only deployment (no gateway) can't serve gateway or mixed devices
resource "terraform_data" "composition_guard" {
  input = { enable_gateway = var.enable_gateway, client_mode = var.client_mode }
  lifecycle {
    precondition {
      condition     = var.enable_gateway || var.client_mode == "seat"
      error_message = "enable_gateway = false needs client_mode = \"seat\" (gateway and mixed devices use the gateway)."
    }
    precondition {
      condition     = !var.enable_telemetry || length(var.device_trust_anchor_files) > 0
      error_message = "enable_telemetry = true needs device_trust_anchor_files (the CA certificates of your device PKI)."
    }
  }
}
