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

# Windows reference workstation (Windows Server 2025, licence-included custom image family). Separate from the Linux
# module on purpose: own identity, own policy bundle, own persona secrets - the Linux workstation is never touched.

variable "project_id" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "prefix" { type = string }
variable "suffix" { type = string }
variable "kms_key" {
  type    = string
  default = null
}
variable "subnet_id" { type = string }
variable "operator_principals" { type = list(string) }
variable "image" { type = string }
variable "machine_type" { type = string }
variable "boot_disk_gb" { type = number }
variable "data_disk_gb" { type = number }
variable "snapshot_every_hours" { type = number }
variable "snapshot_retention" { type = number }
variable "labels" { type = map(string) }
variable "personas" { type = list(string) }
variable "client_mode" { type = string }
variable "device_ca_pool" {
  type    = string
  default = ""
}
variable "device_template" {
  type    = string
  default = ""
}
variable "spiffe_prefix" {
  type    = string
  default = ""
}
variable "device_root_pem" {
  type    = string
  default = ""
}
variable "seat_project" { type = string }
variable "seat_location" { type = string }
variable "egress_allowlist" { type = map(list(string)) }
variable "hosts_pin" { type = list(string) }
variable "gateway_url" { type = string }
variable "agy_cli_manifest_url" { type = string }
variable "rdp_clipboard" { type = bool }
variable "bootstrap_path" { type = string }
variable "files_dir" { type = string }
variable "wdac_mode" { type = string }
variable "corp_script_publisher" {
  description = "AppLocker publisher of corporate-signed PowerShell scripts allowed in FullLanguage for developers."
  type        = string
  default     = ""
}
variable "package_proxy" {
  description = "JSON {format: client endpoint} of the corporate package proxy (empty object = public registries)."
  type        = string
  default     = "{}"
}
variable "browser_allowlist" {
  description = "Extra hosts for the managed browser allowlist (comma-separated in metadata agy-browser-allowlist)."
  type        = list(string)
  default     = []
}
variable "agent_service_accounts" {
  description = "JSON {group: agent service account email} merged into the hook policy (agent gcloud identity)."
  type        = string
  default     = "{}"
}

locals {
  name  = "${var.prefix}-win-ws"
  files = toset([for f in fileset(var.files_dir, "**") : f if !can(regex("(^|/)__pycache__/|\\.pyc$|^w0/", f))])
}

# ----------------------------------------------------------------- VM identity: logs / metrics + read its own bundle
resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.prefix}-win-workstation"
  display_name = "AGY POC - Windows workstation VM (minimal)"
}

resource "google_project_iam_member" "vm" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.vm.email}"
}

# ----------------------------------------------------------------- policy bundle (simulated MDM / SCCM payload)
resource "google_storage_bucket" "cfg" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.prefix}-mdm-win-${var.suffix}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  labels                      = var.labels
  versioning { enabled = true }
  dynamic "encryption" {
    for_each = var.kms_key == null ? [] : [1]
    content { default_kms_key_name = var.kms_key }
  }
}

resource "google_storage_bucket_iam_member" "vm_read" {
  bucket = google_storage_bucket.cfg.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_storage_bucket_object" "files" {
  for_each       = local.files
  bucket         = google_storage_bucket.cfg.name
  name           = "win/${each.value}"
  source         = "${var.files_dir}/${each.value}"
  detect_md5hash = filemd5("${var.files_dir}/${each.value}")
}

# ----------------------------------------------------------------- persona RDP passwords (typeable, Secret Manager)
resource "random_password" "persona" {
  for_each    = toset(var.personas)
  length      = 24
  special     = false
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

locals {
  persona_password = { for k, p in random_password.persona : k => replace(replace(replace(replace(replace(p.result, "l", "L"), "I", "J"), "1", "7"), "0", "8"), "O", "P") }
}

resource "google_secret_manager_secret" "persona" {
  for_each  = toset(var.personas)
  project   = var.project_id
  secret_id = "${var.prefix}-win-desktop-${each.key}"
  labels    = var.labels
  replication {
    user_managed {
      replicas {
        location = var.region
        dynamic "customer_managed_encryption" {
          for_each = var.kms_key == null ? [] : [1]
          content { kms_key_name = var.kms_key }
        }
      }
    }
  }
}

resource "google_secret_manager_secret_version" "persona" {
  for_each    = toset(var.personas)
  secret      = google_secret_manager_secret.persona[each.key].id
  secret_data = local.persona_password[each.key]
}

resource "google_secret_manager_secret_iam_member" "persona_vm" {
  for_each  = toset(var.personas)
  project   = var.project_id
  secret_id = google_secret_manager_secret.persona[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_secret_manager_secret_iam_member" "persona_ops" {
  for_each  = { for pair in setproduct(var.personas, var.operator_principals) : "${pair[0]}|${pair[1]}" => pair }
  project   = var.project_id
  secret_id = google_secret_manager_secret.persona[each.value[0]].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value[1]
}

# ----------------------------------------------------------------- workspace disk D:\projects (CMEK + snapshots)
resource "google_compute_disk" "data" {
  project = var.project_id
  name    = "${local.name}-data"
  zone    = var.zone
  size    = var.data_disk_gb
  type    = "pd-balanced"
  labels  = var.labels
  disk_encryption_key { kms_key_self_link = var.kms_key }
}

resource "google_compute_resource_policy" "snap" {
  count   = var.snapshot_every_hours > 0 ? 1 : 0
  project = var.project_id
  name    = "${local.name}-snapshots"
  region  = var.region
  snapshot_schedule_policy {
    schedule {
      hourly_schedule {
        hours_in_cycle = var.snapshot_every_hours
        start_time     = "00:00"
      }
    }
    retention_policy {
      max_retention_days    = var.snapshot_retention
      on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"
    }
    snapshot_properties {
      storage_locations = [var.region]
      labels            = var.labels
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "data" {
  count   = var.snapshot_every_hours > 0 ? 1 : 0
  project = var.project_id
  name    = google_compute_resource_policy.snap[0].name
  disk    = google_compute_disk.data.name
  zone    = var.zone
}

# ----------------------------------------------------------------- the workstation (Shielded, no external IP, IAP only)
resource "google_compute_instance" "ws" {
  project      = var.project_id
  name         = local.name
  zone         = var.zone
  machine_type = var.machine_type
  tags         = ["agy-workstation"] # IAP-only SSH (operator automation) + RDP rules of the network module
  labels       = merge(var.labels, { os = "windows" })

  boot_disk {
    kms_key_self_link = var.kms_key
    initialize_params {
      image = var.image
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }
  attached_disk {
    source      = google_compute_disk.data.id
    device_name = "data"
  }

  network_interface {
    subnetwork = var.subnet_id # no access_config => no external IP
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true # holds the non-exportable device key of the credential proxy (gateway mode)
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-windows-ssh         = "TRUE" # operator automation over IAP (gcloud compute ssh), OS Login not available
    block-project-ssh-keys     = "TRUE"
    windows-startup-script-ps1 = file(var.bootstrap_path)
    agy-config-bucket          = google_storage_bucket.cfg.name
    agy-client-mode            = var.client_mode
    agy-seat-project           = var.seat_project
    agy-seat-location          = var.seat_location
    agy-gateway-url            = var.gateway_url
    agy-device-ca-pool         = var.device_ca_pool
    agy-device-template        = var.device_template
    agy-spiffe-prefix          = var.spiffe_prefix
    agy-device-root-pem        = var.device_root_pem
    agy-cli-manifest-url       = var.agy_cli_manifest_url
    agy-hosts-pin              = join(",", var.hosts_pin)
    agy-egress-allowlist       = jsonencode(var.egress_allowlist)
    agy-rdp-clipboard          = tostring(var.rdp_clipboard)
    agy-agent-sa               = var.agent_service_accounts
    agy-browser-allowlist      = join(",", var.browser_allowlist)
    agy-package-proxy          = var.package_proxy
    agy-corp-script-publisher  = var.corp_script_publisher
    agy-wdac-mode              = var.wdac_mode
    agy-desktop-secrets        = join(",", [for u in sort(var.personas) : "${u}=${google_secret_manager_secret.persona[u].secret_id}"])
    agy-desktop-secret-ver     = sha256(join(",", [for u in sort(var.personas) : google_secret_manager_secret_version.persona[u].name]))
    agy-bundle-hash            = sha256(join(",", [for f in local.files : filemd5("${var.files_dir}/${f}")]))
  }

  allow_stopping_for_update = true
  depends_on                = [google_storage_bucket_object.files, google_storage_bucket_iam_member.vm_read, google_secret_manager_secret_iam_member.persona_vm]
  # the operator's IAP SSH (validation, ops) adds its key to the instance metadata; it isn't part of the desired state
  lifecycle {
    ignore_changes = [metadata["ssh-keys"]]
  }
}

# ----------------------------------------------------------------- operator access (IAP tunnel only)
resource "google_iap_tunnel_instance_iam_member" "op" {
  for_each = toset(var.operator_principals)
  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.ws.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}

output "instance_name" { value = google_compute_instance.ws.name }
output "config_bucket" { value = google_storage_bucket.cfg.name }
output "vm_sa_email" { value = google_service_account.vm.email }
output "desktop_secrets" { value = { for u in var.personas : u => google_secret_manager_secret.persona[u].secret_id } }
