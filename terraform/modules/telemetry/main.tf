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

# Device telemetry without a gateway: devices write AGY security events straight to Cloud Logging with a write-only
# federated identity. Workload Identity Federation (X.509) trusts ONLY the customer's PKI roots; the device presents its
# certificate in the mTLS handshake to Google STS and gets a 1 h token whose only right is roles/logging.logWriter.
# No service-account key, no impersonation, no gateway. Revocation: short-lived device certificates + the attribute
# condition (WIF reads no CRL).

variable "project_id" { type = string }
variable "prefix" { type = string }
variable "trust_anchor_pems" {
  description = "Root (or issuing) CA certificates of the customer PKI, PEM, one per entry (max 3)"
  type        = list(string)
  validation {
    condition     = length(var.trust_anchor_pems) >= 1 && length(var.trust_anchor_pems) <= 3
    error_message = "1-3 trust anchors (Workload Identity Federation limit)."
  }
}
variable "intermediate_pems" {
  description = "Intermediate CA certificates, PEM, one per entry (max 10)"
  type        = list(string)
  default     = []
}
variable "subject_cn_regex" {
  description = "RE2 pattern the device certificate's subject CN must match (becomes the device id)"
  type        = string
}
variable "issuer_cn" {
  description = "If set, the leaf certificate's issuer CN must equal this (restricts which CA of the PKI may issue device identities)"
  type        = string
  default     = ""
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  pool_id = "${var.prefix}-devices"
  condition = join(" && ", compact([
    "assertion.subject.dn.cn.matches('${var.subject_cn_regex}')",
    var.issuer_cn == "" ? "" : "assertion.issuer.dn.cn == '${var.issuer_cn}'",
  ]))
  pool_path     = "projects/${data.google_project.this.number}/locations/global/workloadIdentityPools/${local.pool_id}"
  principal_set = "principalSet://iam.googleapis.com/${local.pool_path}/attribute.kind/agy-device"
}

resource "google_iam_workload_identity_pool" "devices" {
  project                   = var.project_id
  workload_identity_pool_id = local.pool_id
  display_name              = "AGY devices"
  description               = "Managed devices (customer PKI certificates) that ship AGY security events"
}

resource "google_iam_workload_identity_pool_provider" "pki" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.devices.workload_identity_pool_id
  workload_identity_pool_provider_id = "customer-pki"
  display_name                       = "Customer PKI (X.509)"
  attribute_mapping = {
    "google.subject" = "assertion.subject.dn.cn"
    "attribute.kind" = "'agy-device'"
  }
  attribute_condition = local.condition
  x509 {
    trust_store {
      dynamic "trust_anchors" {
        for_each = var.trust_anchor_pems
        content { pem_certificate = trust_anchors.value }
      }
      dynamic "intermediate_cas" {
        for_each = var.intermediate_pems
        content { pem_certificate = intermediate_cas.value }
      }
    }
  }
}

# write-only: a device can add log entries, never read, change or delete anything
resource "google_project_iam_member" "log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = local.principal_set
}

output "audience" {
  description = "STS audience for the device token exchange"
  value       = "//iam.googleapis.com/${local.pool_path}/providers/${google_iam_workload_identity_pool_provider.pki.workload_identity_pool_provider_id}"
}
output "principal_set" { value = local.principal_set }
output "pool" { value = local.pool_path }
output "attribute_condition" { value = local.condition }
