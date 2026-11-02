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
variable "secops_email" { type = string }
variable "log_retention_days" { type = number }
variable "log_lock_days" {
  type    = number
  default = 0
}
variable "audit_log_retention_days" {
  type    = number
  default = 400
}
variable "enable_bigquery_sink" { type = bool }
variable "enable_saved_queries" {
  type    = bool
  default = false
}
variable "log_bucket_id" {
  type    = string
  default = ""
}

locals {
  # gateway and (seat mode) the prompt-log inspector run the same image and write the same event schema
  gw_filter       = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=(\"${var.prefix}-gateway\" OR \"${var.prefix}-seat-inspector\") AND jsonPayload.component=\"agy-gateway\""
  vm_filter       = "(resource.type=\"gce_instance\" OR resource.type=\"generic_node\") AND (log_id(\"agy_kernel\") OR log_id(\"agy_syslog\") OR log_id(\"agy_audit\") OR log_id(\"agy_corp_tools\") OR log_id(\"agy_xrdp\") OR log_id(\"agy_winevt\"))"
  ma_filter       = "resource.type=\"modelarmor.googleapis.com/SanitizeOperation\""
  security_filter = "(${local.gw_filter}) OR (${local.vm_filter}) OR (${local.ma_filter})"
  # audit logs this project writes: Admin Activity, Data Access, System Event, Policy Denied. Admin Activity and System
  # Event are also kept by Google in the _Required bucket (fixed: 400 days, location and keys set at project creation).
  audit_filter = "LOG_ID(\"cloudaudit.googleapis.com/activity\") OR LOG_ID(\"cloudaudit.googleapis.com/data_access\") OR LOG_ID(\"cloudaudit.googleapis.com/system_event\") OR LOG_ID(\"cloudaudit.googleapis.com/policy\")"
  # log_lock_days > 0: buckets are locked and the lock fixes their retention (irreversible; project deletion is not blocked)
  locked          = var.log_lock_days > 0
  sec_retention   = var.log_lock_days > 0 ? var.log_lock_days : var.log_retention_days
  audit_retention = var.log_lock_days > 0 ? var.log_lock_days : var.audit_log_retention_days
}

# ----------------------------------------------------------------- Data Access audit logs
resource "google_project_iam_audit_config" "svc" {
  for_each = toset([
    "modelarmor.googleapis.com", "secretmanager.googleapis.com", "cloudkms.googleapis.com",
    "storage.googleapis.com", "run.googleapis.com", "iap.googleapis.com", "compute.googleapis.com",
    "aiplatform.googleapis.com", "dlp.googleapis.com", "privilegedaccessmanager.googleapis.com",
  ])
  project = var.project_id
  service = each.value
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# ----------------------------------------------------------------- central security log bucket (EU, short retention)
resource "google_logging_project_bucket_config" "sec" {
  project          = var.project_id
  location         = var.region
  bucket_id        = var.log_bucket_id == "" ? "${var.prefix}-security" : var.log_bucket_id
  retention_days   = local.sec_retention
  enable_analytics = true
  locked           = local.locked
  dynamic "cmek_settings" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
}

resource "google_logging_project_sink" "sec" {
  project                = var.project_id
  name                   = "${var.prefix}-security-sink"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.sec.id}"
  filter                 = local.security_filter
  unique_writer_identity = true
}

# ----------------------------------------------------------------- audit logs: your region, your key, your retention
resource "google_logging_project_bucket_config" "audit" {
  project        = var.project_id
  location       = var.region
  bucket_id      = "${var.prefix}-audit"
  retention_days = local.audit_retention
  locked         = local.locked
  dynamic "cmek_settings" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
}

resource "google_logging_project_sink" "audit" {
  project                = var.project_id
  name                   = "${var.prefix}-audit-sink"
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.audit.id}"
  filter                 = local.audit_filter
  unique_writer_identity = true
}

# keep Data Access / Policy Denied audit logs and the security events out of the global _Default bucket (Google keys,
# 30 days): they are stored only in the regional, CMEK-encrypted buckets above
resource "google_logging_project_exclusion" "default_audit" {
  project     = var.project_id
  name        = "${var.prefix}-default-excl-audit"
  description = "Data Access / Policy Denied audit logs are kept in the ${var.prefix}-audit bucket"
  filter      = "LOG_ID(\"cloudaudit.googleapis.com/data_access\") OR LOG_ID(\"cloudaudit.googleapis.com/policy\")"
  depends_on  = [google_logging_project_sink.audit]
}

resource "google_logging_project_exclusion" "default_security" {
  project     = var.project_id
  name        = "${var.prefix}-default-excl-security"
  description = "Gateway, endpoint and Model Armor events are kept in the ${var.prefix}-security bucket"
  filter      = local.security_filter
  depends_on  = [google_logging_project_sink.sec]
}

# ----------------------------------------------------------------- BigQuery export (Looker Studio reporting)
resource "google_bigquery_dataset" "sec" {
  count                       = var.enable_bigquery_sink ? 1 : 0
  project                     = var.project_id
  dataset_id                  = replace("${var.prefix}_security_events", "-", "_")
  location                    = var.region
  delete_contents_on_destroy  = true
  default_table_expiration_ms = var.log_retention_days * 86400000
  dynamic "default_encryption_configuration" {
    for_each = var.kms_key == null ? [] : [1]
    content { kms_key_name = var.kms_key }
  }
}

resource "google_logging_project_sink" "bq" {
  count                  = var.enable_bigquery_sink ? 1 : 0
  project                = var.project_id
  name                   = "${var.prefix}-security-bq"
  destination            = "bigquery.googleapis.com/projects/${var.project_id}/datasets/${google_bigquery_dataset.sec[0].dataset_id}"
  filter                 = "(${local.gw_filter}) AND jsonPayload.event=(\"PROMPT_BLOCKED\" OR \"ROUTED\" OR \"RESPONSE_FLAGGED\" OR \"DEVICE_REJECTED\" OR \"GROUP_UNKNOWN\" OR \"WIRE_PROTOCOL_DENIED\" OR \"PROMPT_FLAGGED\" OR \"STOLEN_TOKEN_SUSPECTED\" OR \"CONTAINMENT_APPLIED\" OR \"CONTAINMENT_DRYRUN\" OR \"CONTAINMENT_FAILED\" OR \"MODEL_OFF_POLICY\")"
  unique_writer_identity = true
  bigquery_options { use_partitioned_tables = true }
}

resource "google_bigquery_dataset_iam_member" "bq_sink" {
  count      = var.enable_bigquery_sink ? 1 : 0
  project    = var.project_id
  dataset_id = google_bigquery_dataset.sec[0].dataset_id
  role       = "roles/bigquery.dataEditor"
  member     = google_logging_project_sink.bq[0].writer_identity
}

# ----------------------------------------------------------------- log-based metrics
resource "google_logging_metric" "blocked" {
  project = var.project_id
  name    = "agy_blocked_prompts"
  filter  = "${local.gw_filter} AND jsonPayload.event=\"PROMPT_BLOCKED\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "group"
      value_type = "STRING"
    }
    labels {
      key        = "category"
      value_type = "STRING"
    }
  }
  label_extractors = {
    group    = "EXTRACT(jsonPayload.group)"
    category = "EXTRACT(jsonPayload.category)"
  }
}

resource "google_logging_metric" "routed" {
  project = var.project_id
  name    = "agy_routed_requests"
  filter  = "${local.gw_filter} AND jsonPayload.event=\"ROUTED\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "group"
      value_type = "STRING"
    }
    labels {
      key        = "routed"
      value_type = "STRING"
    }
    labels {
      key        = "reason"
      value_type = "STRING"
    }
  }
  label_extractors = {
    group  = "EXTRACT(jsonPayload.group)"
    routed = "EXTRACT(jsonPayload.routed)"
    reason = "EXTRACT(jsonPayload.reason)"
  }
}

resource "google_logging_metric" "apparmor" {
  project = var.project_id
  name    = "agy_apparmor_denials"
  filter  = "resource.type=\"gce_instance\" AND (log_id(\"agy_audit\") OR log_id(\"agy_kernel\")) AND jsonPayload.message=~\"apparmor=\\\"DENIED\\\".*antigravity-agent\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "netblock" {
  project = var.project_id
  name    = "agy_network_blocks"
  filter  = "resource.type=\"gce_instance\" AND log_id(\"agy_kernel\") AND jsonPayload.message=~\"AGY-([A-Z-]+BLOCK|RATE-LIMIT)\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

resource "google_logging_metric" "corp_tools" {
  project = var.project_id
  name    = "agy_corp_tool_executions"
  filter  = "resource.type=\"gce_instance\" AND log_id(\"agy_corp_tools\")"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# ----------------------------------------------------------------- alerting
# seat mode: high-risk detections, stolen-token signals and containment outcomes (inspector events)
resource "google_logging_metric" "seat" {
  project = var.project_id
  name    = "agy_seat_high_risk"
  filter  = "${local.gw_filter} AND (jsonPayload.event=(\"STOLEN_TOKEN_SUSPECTED\" OR \"CONTAINMENT_APPLIED\" OR \"CONTAINMENT_FAILED\") OR (jsonPayload.event=\"PROMPT_FLAGGED\" AND jsonPayload.risk=\"high\"))"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "event"
      value_type = "STRING"
    }
  }
  label_extractors = {
    event = "EXTRACT(jsonPayload.event)"
  }
}

# Seat model policy: off-policy model use, from the prompt-log inspector (server side) and the workstation hook (client side)
resource "google_logging_metric" "seat_model" {
  project = var.project_id
  name    = "agy_seat_model_off_policy"
  filter  = "(${local.gw_filter} AND jsonPayload.event=\"MODEL_OFF_POLICY\") OR (logName=\"projects/${var.project_id}/logs/agy_syslog\" AND jsonPayload.message:\"MODEL_OFF_POLICY\")"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key        = "source"
      value_type = "STRING"
    }
  }
  label_extractors = {
    source = "EXTRACT(jsonPayload.source)"
  }
}

# user-defined log metrics take a few minutes before Monitoring accepts them in alert filters
resource "time_sleep" "metric_propagation" {
  create_duration = "240s"
  triggers = {
    m = join(",", [google_logging_metric.blocked.id, google_logging_metric.corp_tools.id, google_logging_metric.apparmor.id, google_logging_metric.seat.id])
  }
}

resource "google_monitoring_notification_channel" "secops" {
  project      = var.project_id
  display_name = "AGY SecOps"
  type         = "email"
  labels       = { email_address = var.secops_email }
}

resource "google_monitoring_alert_policy" "blocked" {
  depends_on   = [time_sleep.metric_propagation]
  project      = var.project_id
  display_name = "AGY - prompt blocked by corporate AI policy"
  combiner     = "OR"
  conditions {
    display_name = "blocked prompts > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.blocked.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.group", "metric.label.category"]
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.secops.id]
  documentation {
    content   = "A prompt was blocked by the AGY gateway. Query the security log bucket for jsonPayload.event=\"PROMPT_BLOCKED\" and the incident ID."
    mime_type = "text/markdown"
  }
  alert_strategy {
    auto_close = "1800s"
  }
}

resource "google_monitoring_alert_policy" "corp_tools" {
  depends_on   = [time_sleep.metric_propagation]
  project      = var.project_id
  display_name = "AGY - corporate security tool executed from workstation"
  combiner     = "OR"
  conditions {
    display_name = "corp tool execution > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.corp_tools.name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.secops.id]
}

resource "google_monitoring_alert_policy" "netblock" {
  depends_on   = [time_sleep.metric_propagation]
  project      = var.project_id
  display_name = "AGY - persona egress blocks burst (scanning / flooding / exfiltration attempt)"
  combiner     = "OR"
  conditions {
    display_name = "egress / mail / remote-access / rate-limit drops > 50 / 5 min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.netblock.name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 50
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  documentation {
    content = "A persona process hit the endpoint egress policy repeatedly (AGY-EGRESS-BLOCK / MAIL-BLOCK / NET-BLOCK / RATE-LIMIT). Check agy_kernel logs for DST/DPT and the agent session."
  }
  notification_channels = [google_monitoring_notification_channel.secops.id]
}

resource "google_monitoring_alert_policy" "apparmor" {
  depends_on   = [time_sleep.metric_propagation]
  project      = var.project_id
  display_name = "AGY - AppArmor denial burst on agent profile"
  combiner     = "OR"
  conditions {
    display_name = "AppArmor denials > 20 / 5 min"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.apparmor.name}\" AND resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = 20
      duration        = "0s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.secops.id]
}

# ----------------------------------------------------------------- shared saved queries (Log Analytics, POC evidence)
# SQL over the security bucket's _AllLogs view (the gateway events are excluded from _Default), shared in the project
locals {
  sq_table = "`${var.project_id}.${var.region}.${google_logging_project_bucket_config.sec.bucket_id}._AllLogs`"
  sq_cols  = "timestamp, JSON_VALUE(json_payload.event) AS event, JSON_VALUE(json_payload.user) AS user, JSON_VALUE(json_payload.group) AS policy_group, JSON_VALUE(json_payload.device.device_id) AS device, JSON_VALUE(json_payload.incident) AS incident"
  sq_gw    = "JSON_VALUE(json_payload.component) = 'agy-gateway'"
  saved_queries = {
    "blocked" = {
      title = "AGY - blocked or flagged prompts and responses"
      sql   = "SELECT ${local.sq_cols}, JSON_VALUE(json_payload.category) AS category, JSON_VALUE(json_payload.source) AS source FROM ${local.sq_table} WHERE ${local.sq_gw} AND JSON_VALUE(json_payload.event) IN ('PROMPT_BLOCKED', 'PROMPT_FLAGGED', 'RESPONSE_BLOCKED', 'RESPONSE_FLAGGED') ORDER BY timestamp DESC LIMIT 1000"
    }
    "masked" = {
      title = "AGY - sensitive data masked before the model or in the answer"
      sql   = "SELECT ${local.sq_cols}, TO_JSON_STRING(json_payload) AS detail FROM ${local.sq_table} WHERE ${local.sq_gw} AND JSON_VALUE(json_payload.event) IN ('REQUEST_MASKED', 'RESPONSE_MASKED') ORDER BY timestamp DESC LIMIT 1000"
    }
    "devices" = {
      title = "AGY - rejected devices (unregistered or invalid certificate)"
      sql   = "SELECT ${local.sq_cols}, TO_JSON_STRING(json_payload) AS detail FROM ${local.sq_table} WHERE ${local.sq_gw} AND JSON_VALUE(json_payload.event) IN ('DEVICE_REJECTED', 'STOLEN_TOKEN_SUSPECTED', 'WIRE_PROTOCOL_DENIED') ORDER BY timestamp DESC LIMIT 1000"
    }
    "routing" = {
      title = "AGY - model routing per persona (downgrades: reason not_authorized->tier)"
      sql   = "SELECT ${local.sq_cols}, JSON_VALUE(json_payload.requested) AS requested, JSON_VALUE(json_payload.routed) AS routed, JSON_VALUE(json_payload.reason) AS reason FROM ${local.sq_table} WHERE ${local.sq_gw} AND JSON_VALUE(json_payload.event) = 'ROUTED' ORDER BY timestamp DESC LIMIT 1000"
    }
    "usage" = {
      title = "AGY - token usage per persona, user and device (last 7 days)"
      sql   = "SELECT DATE(timestamp) AS day, JSON_VALUE(json_payload.group) AS policy_group, JSON_VALUE(json_payload.user) AS user, JSON_VALUE(json_payload.device.device_id) AS device, COUNT(*) AS calls, SUM(SAFE_CAST(JSON_VALUE(json_payload.usage.promptTokenCount) AS INT64)) AS input_tokens, SUM(SAFE_CAST(JSON_VALUE(json_payload.usage.candidatesTokenCount) AS INT64)) AS output_tokens FROM ${local.sq_table} WHERE ${local.sq_gw} AND JSON_VALUE(json_payload.event) = 'STREAM_DONE' AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY) GROUP BY 1, 2, 3, 4 ORDER BY day DESC"
    }
  }
}

resource "google_logging_saved_query" "poc" {
  for_each     = var.enable_saved_queries ? local.saved_queries : {}
  parent       = "projects/${var.project_id}"
  location     = "global"
  name         = "${var.prefix}-${each.key}"
  display_name = each.value.title
  description  = "Antigravity POC evidence (managed by Terraform)"
  visibility   = "SHARED"
  ops_analytics_query { sql_query_text = each.value.sql }
}

output "log_bucket" { value = google_logging_project_bucket_config.sec.id }
output "bq_dataset" { value = var.enable_bigquery_sink ? google_bigquery_dataset.sec[0].dataset_id : "" }
output "security_filter" { value = local.security_filter }
output "notification_channel" { value = google_monitoring_notification_channel.secops.id }

resource "google_monitoring_alert_policy" "seat" {
  depends_on   = [time_sleep.metric_propagation]
  project      = var.project_id
  display_name = "AGY - seat mode: high-risk prompt, stolen token or containment"
  combiner     = "OR"
  conditions {
    display_name = "seat high-risk events > 0"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.seat.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"
      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.event"]
      }
    }
  }
  notification_channels = [google_monitoring_notification_channel.secops.id]
  documentation {
    content   = "Seat mode (detect and contain): query jsonPayload.mode=\"seat\" for PROMPT_FLAGGED (risk high), STOLEN_TOKEN_SUSPECTED or CONTAINMENT_* and the incident ID. Containment removes the user's Gemini Enterprise licence (enforce) or records what would happen (dry_run)."
    mime_type = "text/markdown"
  }
  alert_strategy {
    auto_close = "1800s"
  }
}
