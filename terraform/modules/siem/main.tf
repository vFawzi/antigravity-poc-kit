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

# BigQuery SIEM: every security-relevant log (gateway / inspector, endpoints Linux + Windows, Model Armor) lands in a
# dedicated analytics log bucket (retention = siem_retention_days, CMEK, EU region). A linked BigQuery dataset exposes
# it as the stable table `_AllLogs`; normalised views in a separate CMEK dataset are the analyst interface; a scheduled
# query writes detections every N minutes.

variable "project_id" { type = string }
variable "region" { type = string }
variable "prefix" { type = string }
variable "kms_key" {
  type    = string
  default = null
}
variable "retention_days" { type = number }
variable "lock_days" {
  type    = number
  default = 0
}
variable "log_filter" { type = string }
variable "model_prices" {
  description = "USD per million tokens per Vertex model (input, output) for the v_persona_usage estimate; {} = tokens only."
  type        = map(object({ input = number, output = number }))
  default     = {}
}
variable "detection_schedule" { type = string }
variable "probe_threshold" { type = number }
variable "viewer_members" { type = list(string) }
variable "labels" { type = map(string) }

locals {
  ds_prefix = replace(var.prefix, "-", "_")
  link_id   = "${local.ds_prefix}_siem_logs"
  logs      = "`${var.project_id}.${local.link_id}._AllLogs`"
  views     = "${var.project_id}.${google_bigquery_dataset.siem.dataset_id}"
}

# ----------------------------------------------------------------- storage: analytics log bucket + linked dataset
resource "google_logging_project_bucket_config" "siem" {
  project          = var.project_id
  location         = var.region
  bucket_id        = "${var.prefix}-siem"
  retention_days   = var.lock_days > 0 ? var.lock_days : var.retention_days # the lock fixes the retention
  enable_analytics = true
  locked           = var.lock_days > 0
  dynamic "cmek_settings" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
}

resource "google_logging_project_sink" "siem" {
  project     = var.project_id
  name        = "${var.prefix}-siem-sink"
  destination = "logging.googleapis.com/${google_logging_project_bucket_config.siem.id}"
  filter      = var.log_filter
}

resource "google_logging_linked_dataset" "siem" {
  link_id     = local.link_id
  bucket      = google_logging_project_bucket_config.siem.bucket_id
  parent      = "projects/${var.project_id}"
  location    = var.region
  description = "AGY SIEM: security logs (read-only link to the ${var.prefix}-siem log bucket)"
}

# ----------------------------------------------------------------- analyst dataset: views + detections (CMEK)
resource "google_bigquery_dataset" "siem" {
  project                    = var.project_id
  dataset_id                 = "${local.ds_prefix}_siem"
  location                   = var.region
  description                = "AGY SIEM: normalised views and detections"
  delete_contents_on_destroy = true
  labels                     = var.labels
  dynamic "default_encryption_configuration" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
}

resource "google_bigquery_table" "v_endpoint_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_endpoint_events"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_endpoint_events.sql", { logs = local.logs })
  }
  depends_on = [google_logging_linked_dataset.siem]
}

resource "google_bigquery_table" "v_persona_usage" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_persona_usage"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query = templatefile("${path.module}/sql/v_persona_usage.sql", {
      logs   = local.logs
      prices = length(var.model_prices) == 0 ? "SELECT CAST(NULL AS STRING) AS model, CAST(NULL AS FLOAT64) AS input, CAST(NULL AS FLOAT64) AS output" : join(" UNION ALL ", [for m, p in var.model_prices : format("SELECT '%s' AS model, %f AS input, %f AS output", replace(m, "'", ""), p.input, p.output)])
    })
  }
  depends_on = [google_logging_linked_dataset.siem]
}

resource "google_bigquery_table" "v_gateway_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_gateway_events"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_gateway_events.sql", { logs = local.logs })
  }
  depends_on = [google_logging_linked_dataset.siem]
}

resource "google_bigquery_table" "v_incident_timeline" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_incident_timeline"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_incident_timeline.sql", { views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events, google_bigquery_table.v_gateway_events]
}

resource "google_bigquery_table" "v_agent_process_tree" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_agent_process_tree"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_agent_process_tree.sql", { logs = local.logs })
  }
  depends_on = [google_logging_linked_dataset.siem]
}

resource "google_bigquery_table" "v_dx_kpis" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_dx_kpis"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_dx_kpis.sql", { views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events]
}

resource "google_bigquery_table" "v_block_tuning_weekly" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_block_tuning_weekly"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_block_tuning_weekly.sql", { views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events]
}

resource "google_bigquery_table" "v_elevation_events" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_elevation_events"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_elevation_events.sql", { logs = local.logs, views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events, google_bigquery_table.v_agent_process_tree]
}

resource "google_bigquery_table" "v_wdac_enforce_readiness" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_wdac_enforce_readiness"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_wdac_enforce_readiness.sql", { views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events]
}

# fleet AGY versions: latest version picture per device (CLI / Desktop installed vs target, policy, package)
resource "google_bigquery_table" "v_agy_versions" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "v_agy_versions"
  deletion_protection = false
  labels              = var.labels
  view {
    use_legacy_sql = false
    query          = templatefile("${path.module}/sql/v_agy_versions.sql", { views = local.views })
  }
  depends_on = [google_bigquery_table.v_endpoint_events]
}

resource "google_bigquery_table" "detections" {
  project             = var.project_id
  dataset_id          = google_bigquery_dataset.siem.dataset_id
  table_id            = "detections"
  deletion_protection = false
  labels              = var.labels
  # declared explicitly: the table inherits the dataset CMEK, and an undeclared key forces a replace (= history loss)
  dynamic "encryption_configuration" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
  time_partitioning {
    type          = "DAY"
    field         = "detected_at"
    expiration_ms = var.retention_days * 86400000
  }
  schema = jsonencode([
    { name = "detected_at", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "rule", type = "STRING", mode = "REQUIRED" },
    { name = "severity", type = "STRING", mode = "REQUIRED" },
    { name = "project", type = "STRING" },
    { name = "vm", type = "STRING" },
    { name = "user", type = "STRING" },
    { name = "count", type = "INT64" },
    { name = "first_seen", type = "TIMESTAMP" },
    { name = "last_seen", type = "TIMESTAMP" },
    { name = "sample", type = "STRING" },
  ])
}

# ----------------------------------------------------------------- scheduled detections
resource "google_service_account" "detect" {
  project      = var.project_id
  account_id   = "${var.prefix}-siem-detect"
  display_name = "AGY SIEM scheduled detections"
}

resource "google_bigquery_dataset_iam_member" "detect_write" {
  project    = var.project_id
  dataset_id = google_bigquery_dataset.siem.dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_project_iam_member" "detect_jobs" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.detect.email}"
}

# read access to the linked dataset: BigQuery Data Viewer on the link + the bucket's _AllLogs log view (this bucket only)
resource "google_bigquery_dataset_iam_member" "detect_link" {
  project    = var.project_id
  dataset_id = google_logging_linked_dataset.siem.link_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.detect.email}"
}

resource "google_project_iam_member" "detect_logs" {
  project = var.project_id
  role    = "roles/logging.viewAccessor"
  member  = "serviceAccount:${google_service_account.detect.email}"
  condition {
    title      = "siem-bucket-only"
    expression = "resource.name == \"projects/${var.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.siem.bucket_id}/views/_AllLogs\""
  }
}

resource "google_project_service_identity" "dts" {
  provider = google-beta
  project  = var.project_id
  service  = "bigquerydatatransfer.googleapis.com"
}

# the Data Transfer service agent mints tokens for the detection service account (no keys)
resource "google_service_account_iam_member" "dts_token" {
  service_account_id = google_service_account.detect.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_project_service_identity.dts.email}"
}

resource "google_bigquery_data_transfer_config" "detections" {
  project                = var.project_id
  location               = var.region
  display_name           = "${var.prefix}-siem-detections"
  data_source_id         = "scheduled_query"
  schedule               = var.detection_schedule
  destination_dataset_id = google_bigquery_dataset.siem.dataset_id
  service_account_name   = google_service_account.detect.email
  params = {
    destination_table_name_template = google_bigquery_table.detections.table_id
    write_disposition               = "WRITE_APPEND"
    query = templatefile("${path.module}/sql/detections.sql", {
      views = local.views, probe_threshold = var.probe_threshold
    })
  }
  depends_on = [
    google_bigquery_dataset_iam_member.detect_write, google_project_iam_member.detect_jobs,
    google_project_iam_member.detect_logs, google_service_account_iam_member.dts_token, google_bigquery_dataset_iam_member.detect_link,
    google_bigquery_table.v_incident_timeline,
    google_bigquery_table.v_agent_process_tree,
    google_bigquery_table.v_elevation_events,
  ]
}

# ----------------------------------------------------------------- analysts: views dataset + this bucket's log view only
resource "google_bigquery_dataset_iam_member" "viewers" {
  for_each   = toset(var.viewer_members)
  project    = var.project_id
  dataset_id = google_bigquery_dataset.siem.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = each.value
}

resource "google_bigquery_dataset_iam_member" "viewer_link" {
  for_each   = toset(var.viewer_members)
  project    = var.project_id
  dataset_id = google_logging_linked_dataset.siem.link_id
  role       = "roles/bigquery.dataViewer"
  member     = each.value
}

resource "google_project_iam_member" "viewer_logs" {
  for_each = toset(var.viewer_members)
  project  = var.project_id
  role     = "roles/logging.viewAccessor"
  member   = each.value
  condition {
    title      = "siem-bucket-only"
    expression = "resource.name == \"projects/${var.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.siem.bucket_id}/views/_AllLogs\""
  }
}

output "dataset" { value = google_bigquery_dataset.siem.dataset_id }
output "linked_dataset" { value = local.link_id }
output "bucket" { value = google_logging_project_bucket_config.siem.bucket_id }
