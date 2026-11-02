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

# AGY user groups: developers and contractors. Either created here as Cloud Identity security groups (native Google)
# or existing groups are used (synced from Entra ID / AD, or created by hand) - the rest of the solution only uses the
# resulting group e-mails (seat users, gateway policy-group mapping, documentation).
variable "mode" {
  type = string # none | create | existing
}
variable "customer_id" {
  type    = string
  default = "" # Cloud Identity customer id (C0xxxxxxx), mode = create
}
variable "domain" {
  type    = string
  default = "" # primary domain for created groups, mode = create
}
variable "dev_group" {
  type    = string
  default = ""
}
variable "contractor_group" {
  type    = string
  default = ""
}
variable "prefix" { type = string }

locals {
  create = var.mode == "create"
  names = {
    dev        = local.create ? "${var.prefix}-developers@${var.domain}" : var.dev_group
    contractor = local.create ? "${var.prefix}-contractors@${var.domain}" : var.contractor_group
  }
}

resource "google_cloud_identity_group" "g" {
  for_each     = local.create ? local.names : {}
  display_name = each.key == "dev" ? "AGY developers" : "AGY contractors"
  description  = each.key == "dev" ? "Antigravity: developers (seat mode by default)" : "Antigravity: external developers (gateway mode, stricter policy)"
  parent       = "customers/${var.customer_id}"
  group_key { id = each.value }
  labels = {
    "cloudidentity.googleapis.com/groups.discussion_forum" = ""
    "cloudidentity.googleapis.com/groups.security"         = "" # security group: usable in IAM; can't be nested into non-security groups
  }
}

output "dev_group" { value = var.mode == "none" ? "" : local.names.dev }
output "contractor_group" { value = var.mode == "none" ? "" : local.names.contractor }
