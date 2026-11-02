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
variable "kms_key" {
  type    = string
  default = null
}
variable "image" { type = string }
variable "deploy_gateway" {
  description = "false = seat-only: only the prompt-log inspector and its shared engines are deployed"
  type        = bool
  default     = true
}
variable "vertex_location" { type = string }
variable "ingress" { type = string }
variable "device_prefixes" { type = list(string) }
variable "group_policy" { type = any }
variable "authorized_models" { type = any }
variable "prompt_categories" { type = map(string) }
variable "prompt_logging" { type = string }
variable "sdp_info_types" { type = list(string) }
variable "classifier_model" { type = string }
variable "grounding" { type = string }
variable "classifier_threshold" { type = number }
variable "sdp_likelihood" { type = string }
variable "sdp_checksum_types" { type = list(string) }
variable "evidence" {
  type    = any
  default = null
}
variable "ma_fail_closed" { type = bool }
variable "block_mode" { type = string }
variable "require_mtls" { type = bool }
variable "lb_header_secret" {
  type      = string
  sensitive = true
}
variable "spiffe_prefix" { type = string }
variable "forward_headers" { type = list(string) }
variable "inference_project" { type = string }
variable "device_auth_modes" { type = list(string) }
variable "fleet_spiffe_prefix" { type = string }
variable "fleet_devices" { type = any }
variable "seat_inspector" {
  description = "Deploy the seat-mode prompt-log inspector (client_mode = seat)."
  type        = bool
  default     = false
}
variable "seat_default_group" {
  type    = string
  default = "agy-dev"
}
variable "seat_user_groups" {
  type    = map(string)
  default = {}
}
variable "seat_containment" {
  type    = string
  default = "dry_run"
}
variable "seat_contain_exempt" {
  type    = list(string)
  default = []
}
variable "seat_model_policy" {
  type    = map(list(string))
  default = {}
}
variable "seat_aux_models" {
  type    = list(string)
  default = []
}
variable "seat_model_contain_after" {
  type    = number
  default = 3
}
variable "seat_project" {
  type    = string
  default = ""
}
variable "seat_location" {
  type    = string
  default = "eu"
}
variable "cmek_enabled" {
  description = "CMEK is used (static at plan time; kms_key itself may be unknown until apply)."
  type        = bool
  default     = true
}
variable "seat_vpc_sc" {
  type    = bool
  default = false
}
variable "response_flush_ms" { type = number }
variable "response_window_chars" { type = number }
variable "billing_labels" {
  description = "Label every Vertex AI call with the persona and device (cost per persona, per-persona billing budgets)."
  type        = bool
  default     = false
}

locals {
  ma_template = "${var.prefix}-prompt-guard"
}

# ----------------------------------------------------------------- Model Armor (Req 4a)
# ----------------------------------------------------------------- Sensitive Data Protection (EU region)
# One inspect template (what is sensitive) + one irreversible de-identify template (mask as [INFO_TYPE]), used by
# Model Armor (advanced SDP) and by the gateway for request / tool-result / response masking.
resource "google_data_loss_prevention_inspect_template" "agy" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  template_id  = "${var.prefix}-sensitive"
  display_name = "agy - sensitive data (EU banking, PCI, credentials)"
  inspect_config {
    min_likelihood = var.sdp_likelihood
    dynamic "info_types" {
      for_each = var.sdp_info_types
      content { name = info_types.value }
    }
    # checksummed types: catch bare values (no context words) - low false-positive rate thanks to the checksum
    dynamic "min_likelihood_per_info_type" {
      for_each = [for t in var.sdp_checksum_types : t if contains(var.sdp_info_types, t)]
      content {
        min_likelihood = "POSSIBLE"
        info_type { name = min_likelihood_per_info_type.value }
      }
    }
  }
}

resource "google_data_loss_prevention_deidentify_template" "mask" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  template_id  = "${var.prefix}-mask"
  display_name = "agy - irreversible masking ([INFO_TYPE])"
  deidentify_config {
    info_type_transformations {
      transformations {
        primitive_transformation {
          replace_with_info_type_config = true
        }
      }
    }
  }
}

# Model Armor's service agent reads the templates and calls SDP on our behalf
resource "google_project_service_identity" "modelarmor" {
  provider = google-beta
  project  = var.project_id
  service  = "modelarmor.googleapis.com"
}

resource "google_project_iam_member" "modelarmor_dlp" {
  for_each = toset(["roles/dlp.user", "roles/dlp.reader"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_project_service_identity.modelarmor.email}"
}

resource "google_project_iam_custom_role" "sdp_user" {
  project     = var.project_id
  role_id     = "${replace(var.prefix, "-", "_")}SdpUser"
  title       = "AGY gateway - SDP masking"
  description = "Use the agy inspect / de-identify templates for content masking."
  permissions = ["dlp.inspectTemplates.get", "dlp.deidentifyTemplates.get", "serviceusage.services.use"]
}

resource "google_project_iam_member" "gw_sdp" {
  project = var.project_id
  role    = google_project_iam_custom_role.sdp_user.id
  member  = "serviceAccount:${google_service_account.gw.email}"
}

resource "google_model_armor_template" "guard" {
  provider    = google-beta
  project     = var.project_id
  location    = var.region
  template_id = local.ma_template

  filter_config {
    rai_settings {
      rai_filters {
        filter_type      = "DANGEROUS"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "HARASSMENT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "HATE_SPEECH"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
      rai_filters {
        filter_type      = "SEXUALLY_EXPLICIT"
        confidence_level = "MEDIUM_AND_ABOVE"
      }
    }
    pi_and_jailbreak_filter_settings {
      filter_enforcement = "ENABLED"
      confidence_level   = "MEDIUM_AND_ABOVE"
    }
    malicious_uri_filter_settings {
      filter_enforcement = "ENABLED"
    }
    sdp_settings {
      advanced_config {
        inspect_template    = google_data_loss_prevention_inspect_template.agy.id
        deidentify_template = google_data_loss_prevention_deidentify_template.mask.id
      }
    }
  }
  template_metadata {
    log_template_operations = true
    log_sanitize_operations = !contains(["deidentified", "evidence"], var.prompt_logging) # evidence path replaces content logging
  }
}

# ----------------------------------------------------------------- registry + build identity
resource "google_artifact_registry_repository" "repo" {
  project       = var.project_id
  location      = var.region
  repository_id = "${var.prefix}-images"
  format        = "DOCKER"
  kms_key_name  = var.kms_key
  docker_config {
    immutable_tags = true
  }
}

resource "google_service_account" "build" {
  project      = var.project_id
  account_id   = "${var.prefix}-build"
  display_name = "AGY POC - Cloud Build (gateway image)"
}

resource "google_artifact_registry_repository_iam_member" "build_writer" {
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.repo.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.build.email}"
}

resource "google_project_iam_member" "build_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.build.email}"
}

resource "google_storage_bucket" "build_src" {
  project                     = var.project_id
  name                        = "${var.project_id}-${var.prefix}-build-src"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = true
  lifecycle_rule {
    condition { age = 7 }
    action { type = "Delete" }
  }
  dynamic "encryption" {
    for_each = var.kms_key == null ? [] : [1]
    content { default_kms_key_name = var.kms_key }
  }
}

resource "google_storage_bucket_iam_member" "build_src" {
  bucket = google_storage_bucket.build_src.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.build.email}"
}

# ----------------------------------------------------------------- runtime identity (least privilege)
resource "google_service_account" "gw" {
  project      = var.project_id
  account_id   = "${var.prefix}-gateway"
  display_name = "AGY POC - Enterprise Gateway runtime"
}

resource "google_project_iam_member" "gw" {
  for_each = toset(["roles/modelarmor.user", "roles/logging.logWriter", "roles/monitoring.metricWriter"])
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.gw.email}"
}

# Only the gateway may call Gemini on Vertex AI; end users hold no predict permission,
# so going around the gateway fails at IAM even if the network path exists.
resource "google_project_iam_custom_role" "vertex_invoker" {
  project     = var.project_id
  role_id     = "agyVertexInvoker"
  title       = "AGY gateway - Vertex AI generate only"
  permissions = ["aiplatform.endpoints.predict"]
}

resource "google_project_iam_member" "gw_vertex" {
  project = var.project_id
  role    = google_project_iam_custom_role.vertex_invoker.id
  member  = "serviceAccount:${google_service_account.gw.email}"
}

# Optional separate inference project (billing / quota for model calls). The gateway SA gets generate-only plus
# serviceusage.services.use there (needed for X-Goog-User-Project); nothing else crosses the project boundary.
locals {
  separate_inference = var.inference_project != "" && var.inference_project != var.project_id
}

resource "google_project_iam_custom_role" "inference_invoker" {
  count       = local.separate_inference ? 1 : 0
  project     = var.inference_project
  role_id     = "agyGatewayInference"
  title       = "AGY gateway - Vertex AI generate + quota attribution"
  permissions = ["aiplatform.endpoints.predict", "serviceusage.services.use"]
}

resource "google_project_iam_member" "gw_inference" {
  count   = local.separate_inference ? 1 : 0
  project = var.inference_project
  role    = google_project_iam_custom_role.inference_invoker[0].id
  member  = "serviceAccount:${google_service_account.gw.email}"
}

# ----------------------------------------------------------------- LB shared-secret header (Secret Manager, CMEK)
resource "google_secret_manager_secret" "lb_header" {
  project   = var.project_id
  secret_id = "${var.prefix}-gw-lb-header"
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

resource "google_secret_manager_secret_version" "lb_header" {
  secret      = google_secret_manager_secret.lb_header.id
  secret_data = var.lb_header_secret
}

resource "google_secret_manager_secret_iam_member" "gw_lb_header" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.lb_header.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gw.email}"
}

# ----------------------------------------------------------------- Cloud Run (stage 2: needs image)
resource "google_cloud_run_v2_service" "gw" {
  count                = var.image != "" && var.deploy_gateway ? 1 : 0
  provider             = google-beta
  project              = var.project_id
  name                 = "${var.prefix}-gateway"
  location             = var.region
  ingress              = var.ingress
  invoker_iam_disabled = true # callers present a Google-signed device token (+ LB-verified client cert); the app authenticates them
  deletion_protection  = false

  template {
    service_account                  = google_service_account.gw.email
    timeout                          = "3600s"
    max_instance_request_concurrency = 80
    encryption_key                   = var.kms_key
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image = var.image
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      startup_probe {
        http_get { path = "/_gw/health" }
      }
      env {
        name  = "PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "VERTEX_LOCATION"
        value = var.vertex_location
      }
      env {
        name  = "DEVICE_AUDIENCE"
        value = "agy-gateway"
      }
      env {
        name  = "ALLOWED_DEVICE_PROJECTS"
        value = jsonencode([var.project_id])
      }
      env {
        name  = "ALLOWED_INSTANCE_PREFIXES"
        value = jsonencode(var.device_prefixes)
      }
      env {
        name  = "MA_LOCATION"
        value = var.region
      }
      env {
        name  = "MA_TEMPLATE"
        value = google_model_armor_template.guard.template_id
      }
      env {
        name  = "MA_FAIL_CLOSED"
        value = tostring(var.ma_fail_closed)
      }
      env {
        name  = "REQUIRE_MTLS"
        value = tostring(var.require_mtls)
      }
      env {
        name  = "SPIFFE_PREFIX"
        value = var.spiffe_prefix
      }
      env {
        name = "LB_HEADER_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.lb_header.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "BLOCK_RESPONSE_MODE"
        value = var.block_mode
      }
      env {
        name  = "DEVICE_AUTH_MODES"
        value = jsonencode(var.device_auth_modes)
      }
      env {
        name  = "FLEET_SPIFFE_PREFIX"
        value = var.fleet_spiffe_prefix
      }
      env {
        name  = "FLEET_DEVICES"
        value = jsonencode(var.fleet_devices)
      }
      env {
        name  = "INFERENCE_PROJECT"
        value = local.separate_inference ? var.inference_project : var.project_id
      }
      env {
        name  = "FORWARD_CUSTOM_HEADERS"
        value = jsonencode(var.forward_headers)
      }
      env {
        name  = "RESPONSE_FLUSH_MS"
        value = tostring(var.response_flush_ms)
      }
      env {
        name  = "RESPONSE_WINDOW_CHARS"
        value = tostring(var.response_window_chars)
      }
      env {
        name  = "PROMPT_LOGGING"
        value = var.prompt_logging
      }
      env {
        name  = "DLP_LOCATION"
        value = var.region
      }
      env {
        name  = "GROUNDING_INSTRUCTION"
        value = var.grounding
      }
      env {
        name  = "CLASSIFIER_MODEL"
        value = var.classifier_model
      }
      env {
        name  = "CLASSIFIER_THRESHOLD"
        value = tostring(var.classifier_threshold)
      }
      env {
        name  = "SDP_INSPECT_TEMPLATE"
        value = google_data_loss_prevention_inspect_template.agy.id
      }
      env {
        name  = "SDP_DEID_TEMPLATE"
        value = google_data_loss_prevention_deidentify_template.mask.id
      }
      env {
        name  = "TOKEN_KEY"
        value = var.evidence == null ? "" : var.evidence.tokenization_key
      }
      env {
        name  = "TOKEN_WRAPPED_SECRET"
        value = var.evidence == null ? "" : "projects/${var.project_id}/secrets/${var.evidence.wrapped_secret}"
      }
      env {
        name  = "EVIDENCE_BUCKET"
        value = var.evidence == null ? "" : var.evidence.evidence_bucket
      }
      env {
        name  = "EVIDENCE_KEY"
        value = var.evidence == null ? "" : var.evidence.evidence_key
      }
      env {
        name = "GROUP_POLICY"
        # empty allowlist = all authorized models
        value = jsonencode({ for g, p in var.group_policy : g => merge(p, length(p.allowed) == 0 ? {
          allowed = flatten([for m, spec in var.authorized_models : [for l in spec.levels : "${m}-${l}"]])
        } : {}) })
      }
      env {
        name  = "BILLING_LABELS"
        value = tostring(var.billing_labels)
      }
      env {
        name  = "AUTHORIZED_MODELS"
        value = jsonencode(var.authorized_models)
      }
      env {
        name  = "PROMPT_CATEGORIES"
        value = jsonencode(var.prompt_categories)
      }
    }
  }
  depends_on = [google_project_iam_member.gw, google_project_iam_member.gw_vertex, google_project_iam_member.gw_inference, google_secret_manager_secret_iam_member.gw_lb_header, google_secret_manager_secret_version.lb_header]
}

output "url" {
  value = length(google_cloud_run_v2_service.gw) == 0 ? "" : google_cloud_run_v2_service.gw[0].uri
}
output "repo_path" {
  value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.repo.repository_id}"
}
output "build_sa_email" { value = google_service_account.build.email }
output "sa_email" { value = google_service_account.gw.email }
output "build_bucket" { value = google_storage_bucket.build_src.name }
output "ma_template" { value = google_model_armor_template.guard.template_id }

output "service_name" {
  value = length(google_cloud_run_v2_service.gw) == 0 ? "" : google_cloud_run_v2_service.gw[0].name
}

# =============================================================================
# Seat mode: prompt-log inspector (detect and respond)
#   Gemini Enterprise inference logs (customer project) -> log sink -> Pub/Sub (CMEK) -> push (OIDC) -> Cloud Run
#   Same image as the gateway (SEAT_INSPECTOR=true): same rules, Model Armor, classifier, SDP, evidence.
# =============================================================================
locals {
  seat_on      = var.seat_inspector && var.image != ""
  seat_project = var.seat_project == "" ? var.project_id : var.seat_project
  seat_env = {
    PROJECT_ID           = var.project_id
    VERTEX_LOCATION      = var.vertex_location
    MA_LOCATION          = var.region
    MA_TEMPLATE          = google_model_armor_template.guard.template_id
    MA_FAIL_CLOSED       = tostring(var.ma_fail_closed)
    PROMPT_LOGGING       = var.prompt_logging
    DLP_LOCATION         = var.region
    CLASSIFIER_MODEL     = var.classifier_model
    CLASSIFIER_THRESHOLD = tostring(var.classifier_threshold)
    SDP_INSPECT_TEMPLATE = google_data_loss_prevention_inspect_template.agy.id
    SDP_DEID_TEMPLATE    = google_data_loss_prevention_deidentify_template.mask.id
    TOKEN_KEY            = var.evidence == null ? "" : var.evidence.tokenization_key
    TOKEN_WRAPPED_SECRET = var.evidence == null ? "" : "projects/${var.project_id}/secrets/${var.evidence.wrapped_secret}"
    EVIDENCE_BUCKET      = var.evidence == null ? "" : var.evidence.evidence_bucket
    EVIDENCE_KEY         = var.evidence == null ? "" : var.evidence.evidence_key
    GROUP_POLICY = jsonencode({ for g, p in var.group_policy : g => merge(p, length(p.allowed) == 0 ? {
      allowed = flatten([for m, spec in var.authorized_models : [for l in spec.levels : "${m}-${l}"]])
    } : {}) })
    AUTHORIZED_MODELS        = jsonencode(var.authorized_models)
    PROMPT_CATEGORIES        = jsonencode(var.prompt_categories)
    SEAT_INSPECTOR           = "true"
    SEAT_DEFAULT_GROUP       = var.seat_default_group
    SEAT_USER_GROUPS         = jsonencode(var.seat_user_groups)
    SEAT_CONTAINMENT         = var.seat_containment
    SEAT_CONTAIN_EXEMPT      = jsonencode(var.seat_contain_exempt)
    SEAT_MODEL_POLICY        = jsonencode(var.seat_model_policy)
    SEAT_AUX_MODELS          = jsonencode(var.seat_aux_models)
    SEAT_MODEL_CONTAIN_AFTER = tostring(var.seat_model_contain_after)
    SEAT_PROJECT             = var.seat_project == "" ? var.project_id : var.seat_project
    SEAT_LOCATION            = var.seat_location
  }
}

resource "google_project_service_identity" "pubsub" {
  count    = local.seat_on ? 1 : 0
  provider = google-beta
  project  = var.project_id
  service  = "pubsub.googleapis.com"
}

resource "google_kms_crypto_key_iam_member" "pubsub_cmek" {
  count         = local.seat_on && var.cmek_enabled ? 1 : 0 # static flag: the key id is unknown at plan time on a new project
  crypto_key_id = var.kms_key
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_project_service_identity.pubsub[0].email}"
}

resource "google_pubsub_topic" "seat_logs" {
  count        = local.seat_on ? 1 : 0
  project      = var.project_id
  name         = "${var.prefix}-seat-inference-logs"
  kms_key_name = var.kms_key
  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
  message_retention_duration = "86400s"
  depends_on                 = [google_kms_crypto_key_iam_member.pubsub_cmek]
}

resource "google_pubsub_topic" "seat_dead" {
  count        = local.seat_on ? 1 : 0
  project      = var.project_id
  name         = "${var.prefix}-seat-inference-dead"
  kms_key_name = var.kms_key
  message_storage_policy {
    allowed_persistence_regions = [var.region]
  }
  depends_on = [google_kms_crypto_key_iam_member.pubsub_cmek]
}

# only the two Gemini Enterprise inference logs (prompt + response) leave Cloud Logging
# the inference logs (and VPC-SC denials) are written in the SEAT project (licence project)
resource "google_logging_project_sink" "seat_logs" {
  count                  = local.seat_on ? 1 : 0
  project                = local.seat_project
  name                   = "${var.prefix}-seat-inference-to-inspector"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.seat_logs[0].id}"
  filter                 = "logName=(\"projects/${local.seat_project}/logs/businessaicode.googleapis.com%2Finference_request\" OR \"projects/${local.seat_project}/logs/businessaicode.googleapis.com%2Finference_response\")"
  unique_writer_identity = true
}

# stolen-token signal: VPC-SC denials of seat API calls go to the same inspector (only when the perimeter exists)
resource "google_logging_project_sink" "seat_vpcsc" {
  count                  = local.seat_on && var.seat_vpc_sc ? 1 : 0
  project                = local.seat_project
  name                   = "${var.prefix}-seat-vpcsc-to-inspector"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.seat_logs[0].id}"
  filter                 = "protoPayload.metadata.@type=\"type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata\" AND protoPayload.serviceName=\"businessaicode.googleapis.com\""
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "seat_vpcsc_publisher" {
  count   = local.seat_on && var.seat_vpc_sc ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.seat_logs[0].name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.seat_vpcsc[0].writer_identity
}

resource "google_pubsub_topic_iam_member" "seat_sink_publisher" {
  count   = local.seat_on ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.seat_logs[0].name
  role    = "roles/pubsub.publisher"
  member  = google_logging_project_sink.seat_logs[0].writer_identity
}

resource "google_cloud_run_v2_service" "seat_inspector" {
  count               = local.seat_on ? 1 : 0
  provider            = google-beta
  project             = var.project_id
  name                = "${var.prefix}-seat-inspector"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_INTERNAL_ONLY"
  deletion_protection = false
  template {
    service_account                  = google_service_account.gw.email # same engines + evidence rights as the gateway
    timeout                          = "60s"
    max_instance_request_concurrency = 20
    encryption_key                   = var.kms_key
    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
    containers {
      image = var.image
      resources {
        limits   = { cpu = "1", memory = "512Mi" }
        cpu_idle = true
      }
      startup_probe {
        http_get { path = "/_gw/health" }
      }
      dynamic "env" {
        for_each = local.seat_env
        content {
          name  = env.key
          value = env.value
        }
      }
    }
  }
  depends_on = [google_project_iam_member.gw, google_project_iam_member.gw_vertex]
}

# push identity: may only invoke the inspector
resource "google_service_account" "seat_push" {
  count        = local.seat_on ? 1 : 0
  project      = var.project_id
  account_id   = "${var.prefix}-seat-push"
  display_name = "AGY - Pub/Sub push to the seat inspector"
}

resource "google_cloud_run_v2_service_iam_member" "seat_push_invoker" {
  count    = local.seat_on ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.seat_inspector[0].name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.seat_push[0].email}"
}

resource "google_service_account_iam_member" "seat_push_token" {
  count              = local.seat_on ? 1 : 0
  service_account_id = google_service_account.seat_push[0].name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_project_service_identity.pubsub[0].email}"
}

resource "google_pubsub_subscription" "seat_push" {
  count                      = local.seat_on ? 1 : 0
  project                    = var.project_id
  name                       = "${var.prefix}-seat-inspector-push"
  topic                      = google_pubsub_topic.seat_logs[0].id
  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"
  push_config {
    push_endpoint = "${google_cloud_run_v2_service.seat_inspector[0].uri}/_seat/pubsub"
    oidc_token {
      service_account_email = google_service_account.seat_push[0].email
      audience              = google_cloud_run_v2_service.seat_inspector[0].uri
    }
  }
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.seat_dead[0].id
    max_delivery_attempts = 10
  }
  depends_on = [google_cloud_run_v2_service_iam_member.seat_push_invoker, google_service_account_iam_member.seat_push_token]
}

# dead-letter needs publish on the DLQ and subscribe on the source subscription for the Pub/Sub agent
resource "google_pubsub_topic_iam_member" "seat_dead_publisher" {
  count   = local.seat_on ? 1 : 0
  project = var.project_id
  topic   = google_pubsub_topic.seat_dead[0].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_project_service_identity.pubsub[0].email}"
}

resource "google_pubsub_subscription_iam_member" "seat_dead_subscriber" {
  count        = local.seat_on ? 1 : 0
  project      = var.project_id
  subscription = google_pubsub_subscription.seat_push[0].name
  role         = "roles/pubsub.subscriber"
  member       = "serviceAccount:${google_project_service_identity.pubsub[0].email}"
}

# containment: the inspector identity may only change licence assignments in the seat project
resource "google_project_iam_custom_role" "seat_containment" {
  count       = local.seat_on && var.seat_containment == "enforce" ? 1 : 0
  project     = var.seat_project == "" ? var.project_id : var.seat_project
  role_id     = "agySeatContainment"
  title       = "AGY seat inspector - licence unassignment only"
  permissions = ["discoveryengine.userStores.batchUpdateUserLicenses", "discoveryengine.userStores.listUserLicenses"]
}

resource "google_project_iam_member" "seat_containment" {
  count   = local.seat_on && var.seat_containment == "enforce" ? 1 : 0
  project = var.seat_project == "" ? var.project_id : var.seat_project
  role    = google_project_iam_custom_role.seat_containment[0].id
  member  = "serviceAccount:${google_service_account.gw.email}"
}

output "seat_inspector_url" {
  value = local.seat_on ? google_cloud_run_v2_service.seat_inspector[0].uri : ""
}
