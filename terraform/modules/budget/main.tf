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

# Per-persona billing budgets (alerts, not a hard stop). Vertex AI calls carry the label agy_persona=<persona>, set by
# the gateway from the authenticated device identity (billing_labels = true); each budget counts only that persona's
# spend in this project. Amounts are in the billing account's currency. Needs billing.budgets.* on the billing account
# (Billing Account Costs Manager or Billing Account Administrator).

variable "project_number" { type = string }
variable "billing_account" { type = string }
variable "prefix" { type = string }
variable "budgets" {
  type = map(object({
    amount     = number
    thresholds = list(number)
  }))
}
variable "notification_channels" { type = list(string) }

resource "google_billing_budget" "persona" {
  for_each        = var.budgets
  billing_account = var.billing_account
  display_name    = "${var.prefix}-${each.key}-monthly"

  budget_filter {
    projects               = ["projects/${var.project_number}"]
    calendar_period        = "MONTH"
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
    labels                 = { agy_persona = each.key }
  }

  amount {
    specified_amount {
      units = tostring(floor(each.value.amount))
    }
  }

  dynamic "threshold_rules" {
    for_each = each.value.thresholds
    content {
      threshold_percent = threshold_rules.value
      spend_basis       = "CURRENT_SPEND"
    }
  }

  all_updates_rule {
    monitoring_notification_channels = var.notification_channels
    disable_default_iam_recipients   = false
  }
}

output "budgets" {
  value = { for k, b in google_billing_budget.persona : k => b.name }
}
