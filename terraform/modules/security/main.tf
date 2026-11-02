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
variable "prefix" { type = string }
variable "suffix" { type = string }
variable "enable_cmek" { type = bool }

data "google_project" "this" {
  project_id = var.project_id
}

# Service identities that must be able to use the CMEK key
resource "google_project_service_identity" "agents" {
  provider = google-beta
  for_each = var.enable_cmek ? toset(["secretmanager.googleapis.com", "artifactregistry.googleapis.com", "run.googleapis.com"]) : toset([])
  project  = var.project_id
  service  = each.value
}

data "google_storage_project_service_account" "gcs" {
  project = var.project_id
}

data "google_logging_project_cmek_settings" "logging" {
  project = var.project_id
}

data "google_bigquery_default_service_account" "bq" {
  project = var.project_id
}

# Key rings cannot be deleted: a random suffix makes re-provisioning collision-free.
resource "google_kms_key_ring" "ring" {
  count    = var.enable_cmek ? 1 : 0
  name     = "${var.prefix}-ring-${var.suffix}"
  location = var.region
  project  = var.project_id
}

resource "google_kms_crypto_key" "key" {
  count                      = var.enable_cmek ? 1 : 0
  name                       = "${var.prefix}-cmek"
  key_ring                   = google_kms_key_ring.ring[0].id
  rotation_period            = "7776000s" # 90 days
  destroy_scheduled_duration = "86400s"
  purpose                    = "ENCRYPT_DECRYPT"
  lifecycle {
    prevent_destroy = false
  }
}

locals {
  # static keys so for_each is known at plan time; values resolve at apply
  agents = var.enable_cmek ? merge(
    { for k, v in google_project_service_identity.agents : k => "serviceAccount:${v.email}" },
    {
      "compute"  = "serviceAccount:service-${data.google_project.this.number}@compute-system.iam.gserviceaccount.com"
      "storage"  = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
      "logging"  = "serviceAccount:${data.google_logging_project_cmek_settings.logging.service_account_id}"
      "bigquery" = "serviceAccount:${data.google_bigquery_default_service_account.bq.email}"
    }
  ) : {}
}

resource "google_kms_crypto_key_iam_member" "agents" {
  for_each      = local.agents
  crypto_key_id = google_kms_crypto_key.key[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value
}

output "kms_key" {
  description = "CMEK key id, or null when CMEK is disabled."
  value       = var.enable_cmek ? google_kms_crypto_key.key[0].id : null
  depends_on  = [google_kms_crypto_key_iam_member.agents]
}
