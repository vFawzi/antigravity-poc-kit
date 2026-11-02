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

# Windows image pipeline (Packer on Cloud Build): least-privilege identities and the IAP-only WinRM path used to
# build the custom Windows Server 2025 image family. The build runs on demand (`make windows-image`).

variable "project_id" { type = string }
variable "prefix" { type = string }
variable "network_id" { type = string }
variable "repo_region" { type = string }
variable "repo_name" { type = string }
variable "source_bucket" { type = string }

# temporary build VM identity: logs only
resource "google_service_account" "vm" {
  project      = var.project_id
  account_id   = "${var.prefix}-img-vm"
  display_name = "AGY - Windows image build VM (temporary)"
}

resource "google_project_iam_member" "vm_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.vm.email}"
}

# Cloud Build identity: exactly what Packer's googlecompute builder needs (custom role, no compute.admin)
resource "google_service_account" "build" {
  project      = var.project_id
  account_id   = "${var.prefix}-img-build"
  display_name = "AGY - Windows image pipeline (Cloud Build / Packer)"
}

resource "google_project_iam_custom_role" "packer" {
  project     = var.project_id
  role_id     = replace("${var.prefix}_image_builder", "-", "_")
  title       = "AGY Windows image builder (Packer)"
  description = "Create a temporary build VM, generalise it and publish a custom image (Packer googlecompute)."
  permissions = [
    "compute.instances.create", "compute.instances.delete", "compute.instances.get", "compute.instances.list",
    "compute.instances.setMetadata", "compute.instances.setServiceAccount", "compute.instances.setTags",
    "compute.instances.setLabels", "compute.instances.stop", "compute.instances.start",
    "compute.instances.getSerialPortOutput", "compute.instances.getGuestAttributes", "compute.instances.use",
    "compute.disks.create", "compute.disks.delete", "compute.disks.get", "compute.disks.use", "compute.disks.useReadOnly",
    "compute.disks.setLabels",
    "compute.images.create", "compute.images.get", "compute.images.getFromFamily", "compute.images.list",
    "compute.images.useReadOnly", "compute.images.setLabels",
    "compute.images.deprecate", # googlecompute plugin >= 1.1.x sets the deprecation status after creating the image
    "compute.subnetworks.use", "compute.subnetworks.get", "compute.networks.get",
    "compute.zoneOperations.get", "compute.globalOperations.get", "compute.regionOperations.get",
    "compute.projects.get", "compute.machineTypes.get", "compute.zones.get", "compute.zones.list",
  ]
}

resource "google_project_iam_member" "build" {
  for_each = {
    packer = google_project_iam_custom_role.packer.id, iap = "roles/iap.tunnelResourceAccessor", logs = "roles/logging.logWriter"
  }
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.build.email}"
}

resource "google_service_account_iam_member" "build_uses_vm_sa" {
  service_account_id = google_service_account.vm.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.build.email}"
}

resource "google_artifact_registry_repository_iam_member" "build_writer" {
  project    = var.project_id
  location   = var.repo_region
  repository = var.repo_name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.build.email}"
}

resource "google_storage_bucket_iam_member" "build_source" {
  bucket = var.source_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.build.email}"
}

# WinRM over HTTPS only from Google's IAP range, only to the build VM tag
resource "google_compute_firewall" "winrm_iap" {
  project       = var.project_id
  name          = "${var.prefix}-allow-iap-winrm-build"
  network       = var.network_id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["agy-image-build"]
  allow {
    protocol = "tcp"
    ports    = ["5986"]
  }
  log_config { metadata = "INCLUDE_ALL_METADATA" }
}

output "build_sa_email" { value = google_service_account.build.email }
output "vm_sa_email" { value = google_service_account.vm.email }
