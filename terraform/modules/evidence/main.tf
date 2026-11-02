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
variable "mode" { type = string } # deidentified | evidence
variable "kms_key" {
  type    = string
  default = null
}
variable "retention_days" { type = number }
variable "gateway_sa" { type = string }
variable "investigators" { type = list(string) }
variable "approvers" { type = list(string) }
variable "labels" { type = map(string) }
variable "notification_channel" { type = string }
variable "name_suffix" {
  description = "Optional suffix for the evidence names that outlive --destroy (wrapped-key secret, tag key, deny policy)."
  type        = string
  default     = ""
}
locals {
  ns = var.name_suffix == "" ? "" : "-${var.name_suffix}"
}

data "google_project" "this" {
  project_id = var.project_id
}

locals {
  evidence = var.mode == "evidence"
}

# ----------------------------------------------------------------- keys (Cloud HSM, EU)
# Separate ring: these keys must survive a POC teardown (evidence stays decryptable) - see install.sh --destroy.
resource "google_kms_key_ring" "ev" {
  project  = var.project_id
  name     = "${var.prefix}-evidence-ring-${var.suffix}"
  location = var.region
}

# Wraps the SDP token key (Tier 1, reversible tokens in audit logs / BigQuery)
resource "google_kms_crypto_key" "tokenization" {
  name                       = "${var.prefix}-tokenization-key"
  key_ring                   = google_kms_key_ring.ev.id
  purpose                    = "ENCRYPT_DECRYPT"
  destroy_scheduled_duration = "2592000s" # 30 days
  labels                     = var.labels
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }
}

# Envelope key for the exact original prompt (Tier 2)
resource "google_kms_crypto_key" "evidence" {
  count                      = local.evidence ? 1 : 0
  name                       = "${var.prefix}-evidence-key"
  key_ring                   = google_kms_key_ring.ev.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s" # 90 days (old versions stay usable for decrypt)
  destroy_scheduled_duration = "2592000s"
  labels                     = var.labels
  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }
}

# Holds ONLY the KMS-wrapped token key (ciphertext). The plaintext key is generated and wrapped by
# install.sh in a pipe and never written to disk, Terraform state or the image.
resource "google_secret_manager_secret" "wrapped" {
  project   = var.project_id
  secret_id = "${var.prefix}-tokenization-wrapped-key${local.ns}"
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

# ----------------------------------------------------------------- evidence store (Tier 2)
resource "google_storage_bucket" "ev" {
  count                       = local.evidence ? 1 : 0
  project                     = var.project_id
  name                        = "${var.project_id}-${var.prefix}-evidence-${var.suffix}"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = merge(var.labels, { data_classification = "restricted", purpose = "prompt-evidence" })
  retention_policy {
    retention_period = var.retention_days * 86400
    is_locked        = false # locking is irreversible: only with the customer's explicit approval
  }
  dynamic "encryption" {
    for_each = var.kms_key == null ? [] : [1]
    content { default_kms_key_name = var.kms_key }
  }
}

# ----------------------------------------------------------------- gateway runtime: write-only for evidence
resource "google_kms_crypto_key_iam_member" "gw_tokenize" {
  crypto_key_id = google_kms_crypto_key.tokenization.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter" # SDP unwraps the token key with the caller's identity
  member        = "serviceAccount:${var.gateway_sa}"
}

resource "google_kms_crypto_key_iam_member" "gw_evidence_encrypt" {
  count         = local.evidence ? 1 : 0
  crypto_key_id = google_kms_crypto_key.evidence[0].id
  role          = "roles/cloudkms.cryptoKeyEncrypter" # encrypt only: the gateway can never read evidence back
  member        = "serviceAccount:${var.gateway_sa}"
}

resource "google_storage_bucket_iam_member" "gw_evidence_create" {
  count  = local.evidence ? 1 : 0
  bucket = google_storage_bucket.ev[0].name
  role   = "roles/storage.objectCreator" # create only: no read, list, overwrite or delete
  member = "serviceAccount:${var.gateway_sa}"
}

resource "google_secret_manager_secret_iam_member" "gw_wrapped" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.wrapped.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.gateway_sa}"
}

resource "google_project_iam_custom_role" "tokenizer" {
  project     = var.project_id
  role_id     = "${replace(var.prefix, "-", "_")}SdpTokenizer"
  title       = "AGY SDP tokenizer (KMS-wrapped keys)"
  description = "Use Sensitive Data Protection content methods with KMS-wrapped crypto keys."
  permissions = ["dlp.kms.encrypt", "serviceusage.services.use"]
}

resource "google_project_iam_member" "gw_tokenizer" {
  project = var.project_id
  role    = google_project_iam_custom_role.tokenizer.id
  member  = "serviceAccount:${var.gateway_sa}"
}

# ----------------------------------------------------------------- break-glass restore (Privileged Access Manager)
# No standing access: investigators request a time-bound grant with a justification (+ approval when approvers
# are configured). Every grant, re-identification and decrypt is in Cloud Audit Logs.
locals {
  ring_path   = google_kms_key_ring.ev.id
  bucket_path = local.evidence ? "projects/_/buckets/${google_storage_bucket.ev[0].name}" : ""
}

resource "google_privileged_access_manager_entitlement" "investigator" {
  count                = length(var.investigators) > 0 ? 1 : 0
  parent               = "projects/${var.project_id}"
  location             = "global"
  entitlement_id       = "${var.prefix}-prompt-investigator"
  max_request_duration = "3600s"
  eligible_users {
    principals = var.investigators
  }
  requester_justification_config {
    unstructured {}
  }
  privileged_access {
    gcp_iam_access {
      resource_type = "cloudresourcemanager.googleapis.com/Project"
      resource      = "//cloudresourcemanager.googleapis.com/projects/${var.project_id}"
      role_bindings {
        role                 = "roles/cloudkms.cryptoKeyDecrypter"
        condition_expression = "resource.name.startsWith(\"${local.ring_path}/cryptoKeys/\")"
      }
      role_bindings {
        role                 = "roles/secretmanager.secretAccessor"
        condition_expression = "resource.name.startsWith(\"projects/${data.google_project.this.number}/secrets/${google_secret_manager_secret.wrapped.secret_id}\")"
      }
      role_bindings {
        role = google_project_iam_custom_role.tokenizer.id
      }
      dynamic "role_bindings" {
        for_each = local.evidence ? [1] : []
        content {
          role                 = "roles/storage.objectViewer"
          condition_expression = "resource.name.startsWith(\"${local.bucket_path}\")"
        }
      }
    }
  }
  dynamic "approval_workflow" {
    for_each = length(var.approvers) > 0 ? [1] : []
    content {
      manual_approvals {
        require_approver_justification = true
        steps {
          approvals_needed = 1
          approvers {
            principals = var.approvers
          }
        }
      }
    }
  }
}

# ----------------------------------------------------------------- hard control: IAM deny on tagged evidence resources
# Allow policies can be bypassed by broad roles (Owner/Editor include KMS decrypt and Secret Manager access).
# This deny policy removes decrypt / secret access / evidence reads from EVERY principal on resources tagged
# agy-evidence=restricted - except the gateway (it can't read evidence anyway: encrypt/create-only) and the named
# investigators, who hold no standing roles and therefore can restore only inside an active PAM grant.
resource "google_tags_tag_key" "ev" {
  parent      = "projects/${var.project_id}"
  short_name  = "${var.prefix}-evidence${local.ns}"
  description = "Prompt-evidence resources protected by the agy evidence deny policy."
}

resource "google_tags_tag_value" "restricted" {
  parent      = google_tags_tag_key.ev.id
  short_name  = "restricted"
  description = "Restore only through a Privileged Access Manager grant."
}

resource "google_tags_location_tag_binding" "ring" {
  parent    = "//cloudkms.googleapis.com/${google_kms_key_ring.ev.id}"
  tag_value = google_tags_tag_value.restricted.id
  location  = var.region
}

resource "google_tags_location_tag_binding" "bucket" {
  count     = local.evidence ? 1 : 0
  parent    = "//storage.googleapis.com/projects/_/buckets/${google_storage_bucket.ev[0].name}"
  tag_value = google_tags_tag_value.restricted.id
  location  = var.region
}

resource "google_tags_tag_binding" "secret" {
  parent    = "//secretmanager.googleapis.com/projects/${data.google_project.this.number}/secrets/${google_secret_manager_secret.wrapped.secret_id}"
  tag_value = google_tags_tag_value.restricted.id
}

locals {
  # IAM v2 principal identifiers for deny-policy exceptions
  v2 = { for p in concat(["serviceAccount:${var.gateway_sa}"], var.investigators) : p => (
    startswith(p, "user:") ? "principal://goog/subject/${trimprefix(p, "user:")}" :
    startswith(p, "group:") ? "principalSet://goog/group/${trimprefix(p, "group:")}" :
    "principal://iam.googleapis.com/projects/-/serviceAccounts/${trimprefix(p, "serviceAccount:")}"
  ) }
  tag_ns = "${var.project_id}/${google_tags_tag_key.ev.short_name}"
}

# SDP unwraps KMS-wrapped token keys with ITS OWN service agent (verified in Cloud Audit Logs), so that agent must be
# an exception for KMS decrypt on the evidence ring. It never returns the unwrapped key, and using a wrapped key through
# SDP requires dlp.kms.encrypt - denied below to everyone but the gateway and investigators.
resource "google_project_service_identity" "dlp" {
  provider = google-beta
  project  = var.project_id
  service  = "dlp.googleapis.com"
}

resource "google_iam_deny_policy" "evidence" {
  parent       = urlencode("cloudresourcemanager.googleapis.com/projects/${var.project_id}")
  name         = "${var.prefix}-evidence-guard${local.ns}"
  display_name = "agy: prompt evidence - restore only via PAM"
  rules {
    description = "No KMS decrypt on tagged evidence keys except gateway, investigators and the SDP service agent (key unwrap)"
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = concat(values(local.v2), ["principal://iam.googleapis.com/projects/-/serviceAccounts/${google_project_service_identity.dlp.email}"])
      denied_permissions   = ["cloudkms.googleapis.com/cryptoKeyVersions.useToDecrypt"]
      denial_condition {
        title      = "agy-evidence=restricted"
        expression = "resource.matchTag('${local.tag_ns}', 'restricted')"
      }
    }
  }
  rules {
    description = "No secret access / evidence read on tagged evidence resources except gateway and investigators"
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = values(local.v2)
      denied_permissions = [
        "secretmanager.googleapis.com/versions.access",
        "storage.googleapis.com/objects.get",
      ]
      denial_condition {
        title      = "agy-evidence=restricted"
        expression = "resource.matchTag('${local.tag_ns}', 'restricted')"
      }
    }
  }
  rules {
    description = "Only the gateway and investigators may use KMS-wrapped keys with Sensitive Data Protection"
    deny_rule {
      denied_principals    = ["principalSet://goog/public:all"]
      exception_principals = values(local.v2)
      denied_permissions   = ["dlp.googleapis.com/kms.encrypt"]
    }
  }
  depends_on = [google_tags_location_tag_binding.ring, google_tags_location_tag_binding.bucket, google_tags_tag_binding.secret]
}

# ----------------------------------------------------------------- detection: restores + evidence failures
resource "google_logging_metric" "restore" {
  project = var.project_id
  name    = "${var.prefix}_evidence_restore"
  filter  = <<-EOT
    (protoPayload.serviceName="cloudkms.googleapis.com" AND protoPayload.methodName="Decrypt"
     AND protoPayload.resourceName:"${google_kms_key_ring.ev.id}/"
     AND protoPayload.authenticationInfo.principalEmail!="${var.gateway_sa}")
    OR (protoPayload.serviceName="dlp.googleapis.com" AND protoPayload.methodName:"ReidentifyContent")
  EOT
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "failed" {
  project = var.project_id
  name    = "${var.prefix}_evidence_failed"
  filter  = "resource.type=\"cloud_run_revision\" AND jsonPayload.component=\"agy-gateway\" AND jsonPayload.event=\"EVIDENCE_FAILED\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "time_sleep" "metrics" {
  create_duration = "90s"
  depends_on      = [google_logging_metric.restore, google_logging_metric.failed]
}

resource "google_monitoring_alert_policy" "restore" {
  project               = var.project_id
  display_name          = "agy - prompt evidence restored (break-glass)"
  combiner              = "OR"
  notification_channels = [var.notification_channel]
  conditions {
    display_name = "restore or decrypt outside the gateway"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.restore.name}\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  documentation {
    content = "A prompt was restored from the evidence trail (PAM break-glass). Verify the grant and justification in the PAM audit log."
  }
  depends_on = [time_sleep.metrics]
}

resource "google_monitoring_alert_policy" "failed" {
  project               = var.project_id
  display_name          = "agy - prompt evidence write failed"
  combiner              = "OR"
  notification_channels = [var.notification_channel]
  conditions {
    display_name = "EVIDENCE_FAILED events"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.failed.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  depends_on = [time_sleep.metrics]
}

output "tokenization_key" { value = google_kms_crypto_key.tokenization.id }
output "evidence_key" { value = local.evidence ? google_kms_crypto_key.evidence[0].id : "" }
output "evidence_bucket" { value = local.evidence ? google_storage_bucket.ev[0].name : "" }
output "wrapped_secret" { value = google_secret_manager_secret.wrapped.secret_id }
output "deny_policy" { value = google_iam_deny_policy.evidence.name }
output "entitlement" { value = length(var.investigators) > 0 ? google_privileged_access_manager_entitlement.investigator[0].id : "" }
