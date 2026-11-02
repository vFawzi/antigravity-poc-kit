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

output "workstation_name" {
  value = var.deploy_workstation ? module.workstation[0].instance_name : ""
}

output "ssh_command" {
  description = "Operator access via IAP (OS Login)."
  value       = var.deploy_workstation ? "gcloud compute ssh ${module.workstation[0].instance_name} --zone ${var.zone} --project ${var.project_id} --tunnel-through-iap" : ""
}

output "gateway_url" {
  value = module.gateway.url
}

output "gateway_image_in_use" {
  description = "Image currently deployed (re-used by scripts so plain re-applies never undeploy the gateway)."
  value       = var.gateway_image
}

output "build_bucket" {
  value = module.gateway.build_bucket
}

output "artifact_repo" {
  value = module.gateway.repo_path
}

output "build_service_account" {
  value = module.gateway.build_sa_email
}

output "config_bucket" {
  value = var.deploy_workstation ? module.workstation[0].config_bucket : ""
}

output "security_log_bucket" {
  value = module.observability.log_bucket
}

output "gateway_mtls_url" {
  value = var.enable_mtls && local.gw_on ? module.mtls[0].gateway_mtls_url : ""
}

output "gateway_ilb_ip" {
  value = var.enable_mtls && local.gw_on ? module.mtls[0].ilb_ip : ""
}

output "device_ca_pool" {
  value = var.enable_mtls && local.gw_on ? module.mtls[0].ca_pool : ""
}

output "desktop_secrets" {
  description = "Secret Manager secret per persona holding the RDP password (xrdp)."
  value       = var.deploy_workstation ? module.workstation[0].desktop_secrets : {}
}

output "zone" {
  value = var.zone
}

output "model_armor_template" {
  value = module.gateway.ma_template
}

output "bigquery_dataset" {
  value = module.observability.bq_dataset
}

output "test_kit" {
  description = "Non-secret values the test team needs (consumed by install.sh -> TESTING.md / testing.env)."
  value = {
    models = flatten([for m, v in var.authorized_models : [for l in v.levels : "${m}-${l}"]])
    groups = { for g, p in var.group_policy : g => {
      allowed = length(p.allowed) == 0 ? ["(all authorized models)"] : p.allowed
      auto    = p.tiers
      blocked = p.blocked_categories
    } }
    prompt_categories = keys(var.prompt_categories)
    block_mode        = var.gateway_block_response_mode
    prompt_logging    = var.prompt_logging
    desktop_access    = var.desktop_access
    rdp_clipboard     = var.rdp_clipboard
    mtls              = var.enable_mtls && var.require_mtls
  }
}

output "evidence" {
  description = "Prompt-evidence resources (empty when prompt_logging is none/hash)."
  value = local.evidence_on ? {
    tokenization_key = module.evidence[0].tokenization_key
    wrapped_secret   = module.evidence[0].wrapped_secret
    evidence_key     = module.evidence[0].evidence_key
    evidence_bucket  = module.evidence[0].evidence_bucket
    entitlement      = module.evidence[0].entitlement
    retention_days   = var.evidence_retention_days
  } : null
}

output "gateway_service_account" {
  description = "Runtime service account of the gateway (the principal in Vertex AI audit logs; checked by V91)."
  value       = module.gateway.sa_email
}

output "inference_project" {
  description = "Project that Vertex AI model calls are billed to and logged in (V91 reads its Data Access log)."
  value       = var.inference_project == "" ? var.project_id : var.inference_project
}

output "fleet" {
  description = "Certificate-only device settings (empty when device_auth_modes has no cert)."
  value = var.enable_mtls && local.gw_on && contains(var.device_auth_modes, "cert") ? {
    ca_pool       = module.mtls[0].fleet_ca_pool
    ca_pool_name  = module.mtls[0].fleet_ca_pool_name
    spiffe_prefix = module.mtls[0].fleet_spiffe_prefix
    devices       = keys(local.fleet_devices)
    selftest      = var.fleet_selftest
    server_ca_pem = module.mtls[0].server_root_pem
    gateway_url   = module.mtls[0].gateway_mtls_url
  } : null
}

output "profile" {
  value = var.deploy_workstation ? "full" : "gateway"
}

output "client_mode" {
  value = var.client_mode
}

output "seat_inspector_url" {
  value = module.gateway.seat_inspector_url
}

output "seat_perimeter" {
  value = contains(["seat", "mixed"], var.client_mode) && var.seat_vpc_sc ? { policy = module.seat_perimeter[0].policy, perimeter = module.seat_perimeter[0].perimeter, mode = module.seat_perimeter[0].mode } : null
}

output "siem" {
  description = "BigQuery SIEM: views dataset, linked log dataset, log bucket (empty when enable_siem = false)"
  value       = var.enable_siem ? { dataset = module.siem[0].dataset, linked_dataset = module.siem[0].linked_dataset, bucket = module.siem[0].bucket } : null
}

output "windows_workstation_name" {
  description = "Windows reference workstation (empty when deploy_windows_workstation = false)"
  value       = var.deploy_windows_workstation ? module.workstation_windows[0].instance_name : ""
}

output "windows_desktop_secrets" {
  description = "Secret Manager secret per Windows persona (RDP password)"
  value       = var.deploy_windows_workstation ? module.workstation_windows[0].desktop_secrets : {}
}

output "windows_image_pipeline" {
  description = "Windows image pipeline identities (null when enable_windows_image_pipeline = false)"
  value = var.enable_windows_image_pipeline ? {
    build_sa = module.image_pipeline[0].build_sa_email, vm_sa = module.image_pipeline[0].vm_sa_email,
    kms_key  = module.security.kms_key, repo = "${var.region}-docker.pkg.dev/${var.project_id}/${local.p}-images",
    subnet   = basename(module.network.subnet_id)
    # mandatory labels for the image
    environment = lookup(var.labels, "environment", "unset"), data_classification = lookup(var.labels, "data_classification", "internal")
    cost_center = lookup(var.labels, "cost_center", "unset")
  } : null
}

output "agy_groups" {
  description = "AGY user groups (developers / contractors) used for seat access and gateway policy mapping."
  value       = { dev = module.groups.dev_group, contractor = module.groups.contractor_group }
}

output "workstation_client_modes" {
  description = "Mode of each reference workstation (client_mode = mixed deploys both sides)."
  value       = { linux = local.ws_mode, windows = local.win_ws_mode }
}

output "device_settings_by_mode" {
  description = "Per device mode (seat / gateway): the values a managed laptop needs in HKLM\\SOFTWARE\\Policies\\AGY (one SCCM configuration item per collection): agy-client-mode, agy-egress-allowlist, agy-hosts-pin, seat pin. client_mode = mixed uses both."
  value = { for mode in compact([local.seat_on ? "seat" : "", local.gateway_on ? "gateway" : ""]) : mode => {
    "agy-client-mode"      = mode
    "agy-egress-allowlist" = jsonencode(local.egress_for[mode])
    "agy-hosts-pin"        = join(",", local.pin_for[mode])
    "agy-seat-project"     = mode == "seat" ? local.seat_project : ""
    "agy-seat-location"    = mode == "seat" ? var.seat_location : ""
  } }
}

output "gateway_enabled" {
  description = "The gateway (pay-as-you-go path) is deployed; false for seat-only compositions."
  value       = local.gw_on
}

output "telemetry" {
  description = "Device telemetry (write-only federated identity): what the device packages need"
  value = var.enable_telemetry ? {
    project             = var.project_id
    audience            = module.telemetry[0].audience
    principal_set       = module.telemetry[0].principal_set
    attribute_condition = module.telemetry[0].attribute_condition
    log_id              = "agy_winevt"
    location            = var.region
  } : null
}

output "telemetry_anchor_hashes" {
  description = "Short SHA-256 of each configured device trust anchor (validation compares them with the live trust store)"
  value       = [for f in var.device_trust_anchor_files : substr(sha256(trimspace(file(startswith(f, "/") ? f : "${path.root}/../${f}"))), 0, 16)]
}

output "persona_budgets" {
  description = "Per-persona billing budgets (alerts at the configured thresholds; amounts in the billing account currency)"
  value       = local.budgets_on ? module.budget[0].budgets : {}
}
