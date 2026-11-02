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
variable "subnet_cidr" { type = string }
variable "egress_restricted" {
  type    = bool
  default = true
}
variable "enable_rdp" {
  type    = bool
  default = false
}

resource "google_compute_network" "vpc" {
  name                    = "${var.prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "ws" {
  name                     = "${var.prefix}-ws-${var.region}"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.vpc.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true # Google APIs + internal-ingress Cloud Run without public IP
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_router" "r" {
  name    = "${var.prefix}-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.vpc.id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.prefix}-nat"
  project                            = var.project_id
  region                             = var.region
  router                             = google_compute_router.r.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.ws.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Administrative access only via IAP TCP forwarding
resource "google_compute_firewall" "iap_ssh" {
  name          = "${var.prefix}-allow-iap-ssh"
  project       = var.project_id
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["agy-workstation"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# Persona desktop (xrdp) only via IAP TCP forwarding - same source range as SSH, no public exposure
resource "google_compute_firewall" "iap_rdp" {
  count         = var.enable_rdp ? 1 : 0
  name          = "${var.prefix}-allow-iap-rdp"
  project       = var.project_id
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["agy-workstation"]
  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_ingress" {
  name          = "${var.prefix}-deny-all-ingress"
  project       = var.project_id
  network       = google_compute_network.vpc.id
  direction     = "INGRESS"
  priority      = 65000
  source_ranges = ["0.0.0.0/0"]
  deny {
    protocol = "all"
  }
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

output "subnet_id" { value = google_compute_subnetwork.ws.id }
output "network_id" { value = google_compute_network.vpc.id }

# ----------------------------------------------------------------- egress: deny by default (all accounts on the VM)
# The device allowlist filters destinations per persona (FQDN); this VPC layer also covers administrator / system
# accounts and every non-web channel: only TCP 80/443 (web, Google APIs via Private Google Access, the internal
# gateway) and Windows activation leave the VPC; everything else is denied and logged. The metadata server
# (DNS, NTP, metadata) is always reachable and not affected by firewall rules.
resource "google_compute_firewall" "egress_web" {
  count              = var.egress_restricted ? 1 : 0
  name               = "${var.prefix}-allow-egress-web"
  project            = var.project_id
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "egress_internal" {
  count              = var.egress_restricted ? 1 : 0
  name               = "${var.prefix}-allow-egress-internal"
  project            = var.project_id
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = [var.subnet_cidr]
  allow { protocol = "all" }
}

resource "google_compute_firewall" "egress_windows_kms" {
  count              = var.egress_restricted ? 1 : 0
  name               = "${var.prefix}-allow-egress-windows-activation"
  project            = var.project_id
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["35.190.247.13/32"] # kms.windows.googlecloud.com (Windows licence activation on Compute Engine)
  allow {
    protocol = "tcp"
    ports    = ["1688"]
  }
}

resource "google_compute_firewall" "deny_egress" {
  count              = var.egress_restricted ? 1 : 0
  name               = "${var.prefix}-deny-all-egress"
  project            = var.project_id
  network            = google_compute_network.vpc.id
  direction          = "EGRESS"
  priority           = 65000
  destination_ranges = ["0.0.0.0/0"]
  deny { protocol = "all" }
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}
