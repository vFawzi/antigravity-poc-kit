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
variable "machine_type" { type = string }
variable "boot_disk_gb" { type = number }
variable "snapshot_every_hours" { type = number }
variable "snapshot_retention" { type = number }
variable "labels" { type = map(string) }
variable "data_disk_gb" { type = number }
variable "secure_disk_gb" { type = number }
variable "apparmor_mode" { type = string }
variable "install_desktop" { type = bool }
variable "agy_cli_manifest_url" { type = string }
variable "agy_cli_sha512" { type = string }
variable "agy_desktop_object" { type = string }
variable "agy_desktop_sha256" { type = string }
variable "hosts_pin" { type = list(string) }
variable "client_mode" {
  type    = string
  default = "gateway"
}
variable "seat_project" {
  type    = string
  default = ""
}
variable "seat_location" {
  type    = string
  default = "eu"
}
variable "pkg_allowlist" {
  description = "Packages installable with sudo agy-pkg (comma-separated in metadata agy-pkg-allow)."
  type        = list(string)
  default     = []
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
variable "seat_model_policy_json" {
  description = "Seat mode: JSON {groups, aux} merged into the hook policy (empty = model checks off)."
  type        = string
  default     = ""
}
variable "egress_allowlist" { type = map(list(string)) }
variable "gateway_url" { type = string }
variable "gateway_direct_url" { type = string }
variable "mtls_enabled" { type = bool }
variable "device_ca_pool" { type = string }
variable "device_template" { type = string }
variable "spiffe_prefix" { type = string }
variable "device_root_pem" { type = string }
variable "bootstrap_path" { type = string }
variable "vm_files_dir" { type = string }
variable "desktop_access" { type = string }
variable "cost_center" { type = string }
variable "rdp_clipboard" { type = bool }
variable "desktop_personas" { type = list(string) }

locals {
  name  = "${var.prefix}-dev-ws"
  files = toset([for f in fileset(var.vm_files_dir, "**") : f if !can(regex("(^|/)__pycache__/|\\.pyc$", f))])
}

# ----------------------------------------------------------------- VM identity: logs/metrics + read config only
resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.prefix}-workstation"
  display_name = "AGY POC - workstation VM (minimal)"
}

resource "google_project_iam_member" "vm" {
  for_each = toset(["roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.vm.email}"
}

# ----------------------------------------------------------------- policy bundle (simulated MDM payload)
resource "google_storage_bucket" "cfg" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.prefix}-mdm-${var.suffix}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
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
  name           = "vm/${each.value}"
  source         = "${var.vm_files_dir}/${each.value}"
  content_type   = "text/plain"
  detect_md5hash = filemd5("${var.vm_files_dir}/${each.value}")
}

# ----------------------------------------------------------------- persona desktop passwords (xrdp, option A)
# Random per persona, Secret Manager (CMEK, regional). Readable by the VM SA (sets them at boot) and operators only.
# Rotate: make rotate-desktop-passwords (replaces random_password + re-runs the bootstrap).
locals {
  rdp_personas = var.desktop_access == "xrdp" ? toset(var.desktop_personas) : toset([])
}

resource "random_password" "persona" {
  for_each    = local.rdp_personas
  length      = 24
  special     = false # typed on the xrdp login screen: symbols move between keyboard layouts
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

locals {
  # read-and-type safe: no look-alike characters (l/I/1, O/0); ~140 bits remain
  persona_password = { for k, p in random_password.persona : k => replace(replace(replace(replace(replace(p.result, "l", "L"), "I", "J"), "1", "7"), "0", "8"), "O", "P") }
}

resource "google_secret_manager_secret" "persona" {
  for_each  = local.rdp_personas
  project   = var.project_id
  secret_id = "${var.prefix}-desktop-${each.key}"
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
  for_each    = local.rdp_personas
  secret      = google_secret_manager_secret.persona[each.key].id
  secret_data = local.persona_password[each.key]
}

resource "google_secret_manager_secret_iam_member" "persona_vm" {
  for_each  = local.rdp_personas
  project   = var.project_id
  secret_id = google_secret_manager_secret.persona[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.vm.email}"
}

resource "google_secret_manager_secret_iam_member" "persona_ops" {
  for_each = {
    for pair in setproduct(tolist(local.rdp_personas), var.operator_principals) : "${pair[0]}|${pair[1]}" => pair
  }
  project   = var.project_id
  secret_id = google_secret_manager_secret.persona[each.value[0]].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value[1]
}

# ----------------------------------------------------------------- disks: C: / D: / admin stand-ins
resource "google_compute_disk" "data" {
  project = var.project_id
  name    = "${var.prefix}-data"
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.data_disk_gb
  dynamic "disk_encryption_key" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_self_link = var.kms_key }
  }
}

resource "google_compute_disk" "secure" {
  project = var.project_id
  name    = "${var.prefix}-secure"
  zone    = var.zone
  type    = "pd-balanced"
  size    = var.secure_disk_gb
  dynamic "disk_encryption_key" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_self_link = var.kms_key }
  }
}

# ----------------------------------------------------------------- workspace snapshots (ransomware / destructive-action recovery)
resource "google_compute_resource_policy" "snap" {
  count   = var.snapshot_every_hours > 0 ? 1 : 0
  project = var.project_id
  name    = "${var.prefix}-workspace-snapshots"
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
      storage_locations = [var.region] # EU residency
      guest_flush       = false
      labels            = merge(var.labels, { purpose = "workspace-recovery" })
    }
  }
}

resource "google_compute_disk_resource_policy_attachment" "data" {
  count   = var.snapshot_every_hours > 0 ? 1 : 0
  project = var.project_id
  zone    = var.zone
  disk    = google_compute_disk.data.name
  name    = google_compute_resource_policy.snap[0].name
}

resource "google_compute_instance" "ws" {
  project      = var.project_id
  name         = local.name
  zone         = var.zone
  machine_type = var.machine_type
  tags         = ["agy-workstation"]

  boot_disk {
    kms_key_self_link = var.kms_key
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2404-lts-amd64"
      size  = var.boot_disk_gb
      type  = "pd-balanced"
    }
  }
  attached_disk {
    source      = google_compute_disk.data.id
    device_name = "data"
  }
  attached_disk {
    source      = google_compute_disk.secure.id
    device_name = "secure"
  }

  network_interface {
    subnetwork = var.subnet_id # no access_config => no external IP
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  service_account {
    email  = google_service_account.vm.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin         = "TRUE"
    block-project-ssh-keys = "TRUE"
    startup-script         = file(var.bootstrap_path)
    agy-config-bucket      = google_storage_bucket.cfg.name
    agy-gateway-direct-url = var.gateway_direct_url
    agy-mtls-enabled       = tostring(var.mtls_enabled)
    agy-device-ca-pool     = var.device_ca_pool
    agy-device-template    = var.device_template
    agy-spiffe-prefix      = var.spiffe_prefix
    agy-device-root-pem    = var.device_root_pem
    agy-gateway-url        = var.gateway_url
    agy-cli-manifest-url   = var.agy_cli_manifest_url
    agy-desktop-object     = var.agy_desktop_object
    agy-desktop-sha256     = var.agy_desktop_sha256
    agy-cli-sha512         = var.agy_cli_sha512
    agy-apparmor-mode      = var.apparmor_mode
    agy-hosts-pin          = join(",", var.hosts_pin)
    agy-client-mode        = var.client_mode
    agy-seat-project       = var.seat_project
    agy-seat-location      = var.seat_location
    agy-seat-model-policy  = var.seat_model_policy_json
    agy-agent-sa           = var.agent_service_accounts
    agy-package-proxy      = var.package_proxy
    agy-pkg-allow          = join(",", var.pkg_allowlist)
    agy-browser-allowlist  = join(",", var.browser_allowlist)
    agy-egress-allowlist   = jsonencode(var.egress_allowlist)
    agy-install-desktop    = tostring(var.install_desktop)
    agy-desktop-access     = var.desktop_access
    agy-cost-center        = var.cost_center
    agy-rdp-clipboard      = tostring(var.rdp_clipboard)
    agy-desktop-secrets    = join(",", [for u in sort(tolist(local.rdp_personas)) : "${u}=${google_secret_manager_secret.persona[u].secret_id}"])
    agy-desktop-secret-ver = sha256(join(",", [for u in sort(tolist(local.rdp_personas)) : google_secret_manager_secret_version.persona[u].name]))
    agy-bundle-hash        = sha256(join(",", [for f in local.files : filemd5("${var.vm_files_dir}/${f}")]))
  }

  allow_stopping_for_update = true
  depends_on                = [google_storage_bucket_object.files, google_storage_bucket_iam_member.vm_read, google_secret_manager_secret_iam_member.persona_vm]
}

# ----------------------------------------------------------------- operator access (IAP + OS Admin Login)
resource "google_iap_tunnel_instance_iam_member" "op" {
  for_each = toset(var.operator_principals)
  project  = var.project_id
  zone     = var.zone
  instance = google_compute_instance.ws.name
  role     = "roles/iap.tunnelResourceAccessor"
  member   = each.value
}

resource "google_compute_instance_iam_member" "op_login" {
  for_each      = toset(var.operator_principals)
  project       = var.project_id
  zone          = var.zone
  instance_name = google_compute_instance.ws.name
  role          = "roles/compute.osAdminLogin"
  member        = each.value
}

resource "google_service_account_iam_member" "op_sa_user" {
  for_each           = toset(var.operator_principals)
  service_account_id = google_service_account.vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = each.value
}

output "instance_name" { value = google_compute_instance.ws.name }
output "config_bucket" { value = google_storage_bucket.cfg.name }
output "vm_sa_email" { value = google_service_account.vm.email }
output "desktop_secrets" {
  value = { for u in local.rdp_personas : u => google_secret_manager_secret.persona[u].secret_id }
}
