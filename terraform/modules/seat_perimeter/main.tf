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

# =============================================================================
# Seat mode: VPC Service Controls perimeter around the Gemini Enterprise seat API (optional)
#   * project-scoped access policy (never touches the organisation-wide policy)
#   * restricted service businessaicode.googleapis.com on the seat project (+ workstation project)
#   * access levels: corporate egress IP ranges and/or device posture (Chrome Enterprise Premium /
#     Endpoint Verification). Requests from VPC networks of the protected projects are inside the perimeter.
#   * dry_run = true writes the perimeter as a dry-run spec (violations are logged, nothing is blocked)
# Validated 2026-10-25: a stolen refresh token used from another project was refused within ~50 s
# (NO_MATCHING_ACCESS_LEVEL); the workstation inside the perimeter kept working.
# =============================================================================
terraform {
  required_providers {
    google = { source = "hashicorp/google" }
  }
}

variable "org_id" { type = string }
variable "prefix" { type = string }
variable "seat_project_number" { type = string }
variable "trusted_source_project_numbers" {
  description = "Projects whose VPC networks may call the seat API (e.g. the workstation project when it differs from the seat project)."
  type        = list(string)
  default     = []
}
variable "corp_ip_ranges" {
  description = "Public egress CIDRs of your corporate network / SSE (devices outside a protected VPC)."
  type        = list(string)
  default     = []
}
variable "device_policy" {
  description = "Optional device posture (needs Chrome Enterprise Premium + Endpoint Verification on the devices)."
  type = object({
    require_corp_owned        = bool
    require_screen_lock       = bool
    allowed_encryption_status = list(string)
    os_types                  = list(string)
  })
  default = null
}
variable "dry_run" {
  type    = bool
  default = true
}
variable "restricted_services" {
  type    = list(string)
  default = ["businessaicode.googleapis.com"]
}

resource "google_access_context_manager_access_policy" "seat" {
  parent = "organizations/${var.org_id}"
  title  = "${var.prefix}-seat-perimeter-policy"
  scopes = ["projects/${var.seat_project_number}"]
}

resource "google_access_context_manager_access_level" "corp" {
  count  = length(var.corp_ip_ranges) > 0 || var.device_policy != null ? 1 : 0
  parent = "accessPolicies/${google_access_context_manager_access_policy.seat.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.seat.name}/accessLevels/${replace(var.prefix, "-", "_")}_seat_corp"
  title  = "${var.prefix} seat users: corporate network or managed device"
  basic {
    combining_function = "OR"
    dynamic "conditions" {
      for_each = length(var.corp_ip_ranges) > 0 ? [1] : []
      content {
        ip_subnetworks = var.corp_ip_ranges
      }
    }
    dynamic "conditions" {
      for_each = var.device_policy == null ? [] : [var.device_policy]
      content {
        device_policy {
          require_corp_owned          = conditions.value.require_corp_owned
          require_screen_lock         = conditions.value.require_screen_lock
          allowed_encryption_statuses = conditions.value.allowed_encryption_status
          require_admin_approval      = false
          dynamic "os_constraints" {
            for_each = conditions.value.os_types
            content {
              os_type = os_constraints.value
            }
          }
        }
      }
    }
  }
}

locals {
  levels = [for l in google_access_context_manager_access_level.corp : l.name]
}

resource "google_access_context_manager_service_perimeter" "seat" {
  parent                    = "accessPolicies/${google_access_context_manager_access_policy.seat.name}"
  name                      = "accessPolicies/${google_access_context_manager_access_policy.seat.name}/servicePerimeters/${replace(var.prefix, "-", "_")}_seat"
  title                     = "${var.prefix} seat API perimeter"
  perimeter_type            = "PERIMETER_TYPE_REGULAR"
  use_explicit_dry_run_spec = var.dry_run

  dynamic "status" {
    for_each = var.dry_run ? [] : [1]
    content {
      resources           = ["projects/${var.seat_project_number}"]
      restricted_services = var.restricted_services
      access_levels       = local.levels
      dynamic "ingress_policies" {
        for_each = var.trusted_source_project_numbers
        content {
          ingress_from {
            identity_type = "ANY_IDENTITY"
            sources {
              resource = "projects/${ingress_policies.value}"
            }
          }
          ingress_to {
            resources = ["*"]
            operations {
              service_name = "businessaicode.googleapis.com"
              method_selectors {
                method = "*"
              }
            }
          }
        }
      }
    }
  }
  dynamic "spec" {
    for_each = var.dry_run ? [1] : []
    content {
      resources           = ["projects/${var.seat_project_number}"]
      restricted_services = var.restricted_services
      access_levels       = local.levels
      dynamic "ingress_policies" {
        for_each = var.trusted_source_project_numbers
        content {
          ingress_from {
            identity_type = "ANY_IDENTITY"
            sources {
              resource = "projects/${ingress_policies.value}"
            }
          }
          ingress_to {
            resources = ["*"]
            operations {
              service_name = "businessaicode.googleapis.com"
              method_selectors {
                method = "*"
              }
            }
          }
        }
      }
    }
  }
}

output "policy" { value = google_access_context_manager_access_policy.seat.name }
output "perimeter" { value = google_access_context_manager_service_perimeter.seat.name }
output "mode" { value = var.dry_run ? "dry_run" : "enforced" }
