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
variable "template_name_suffix" {
  description = "Optional suffix for the device certificate template ID (CAS template IDs cannot be reused after deletion)."
  type        = string
  default     = ""
}
variable "network_id" { type = string }
variable "subnet_id" { type = string }
variable "proxy_subnet_cidr" { type = string }
variable "cloud_run_service" { type = string }
variable "gateway_hostname" { type = string }
variable "dns_zone_domain" { type = string }
variable "lb_header_secret" {
  type      = string
  sensitive = true
}
variable "extra_device_requesters" {
  description = "Further workstation SAs that enrol their own device certificate (e.g. the gateway-mode Windows workstation): key -> SA e-mail."
  type        = map(string)
  default     = {}
}

variable "device_requester" {
  description = "Workstation SA that enrols its own device certificate (empty = no reference workstation)."
  type        = string
  default     = ""
}
variable "enable_fleet" {
  description = "Create the FLEET CA pool for certificate-only devices (laptops)."
  type        = bool
  default     = false
}
variable "fleet_issuers" {
  description = "Principals (MDM / enrolment service) allowed to request fleet device certificates."
  type        = list(string)
  default     = []
}
variable "fleet_cert_lifetime" {
  type    = string
  default = "2592000s"
}

# =============================================================================
# Device mTLS front door (production device-authentication pattern)
#   CAS root CA  ->  TrustConfig  ->  ServerTlsPolicy(REJECT_INVALID)
#   regional internal Application LB (HTTPS, private IP) -> serverless NEG -> Cloud Run gateway
#   LB injects verified client-certificate facts as request headers for the gateway
# =============================================================================

# ----------------------------------------------------------------- private PKI (Certificate Authority Service)
resource "google_privateca_ca_pool" "device" {
  project  = var.project_id
  name     = "${var.prefix}-device-pool-${var.suffix}"
  location = var.region
  tier     = "DEVOPS"
  publishing_options {
    publish_ca_cert = false
    publish_crl     = false
  }
  issuance_policy {
    maximum_lifetime = "2592000s" # 30 days
    allowed_key_types {
      elliptic_curve {
        signature_algorithm = "ECDSA_P256"
      }
    }
    # pool-level guardrail: ONLY device client certificates can ever be issued from this pool
    identity_constraints {
      allow_subject_passthrough           = true
      allow_subject_alt_names_passthrough = true
      cel_expression {
        title      = "device-spiffe-only"
        expression = "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.startsWith('spiffe://${var.project_id}.${var.dns_zone_domain}/device/'))"
      }
    }
    baseline_values {
      ca_options {
        is_ca = false
      }
      key_usage {
        base_key_usage {
          digital_signature = true
          key_agreement     = true
        }
        extended_key_usage {
          client_auth = true
        }
      }
    }
  }
}

resource "google_privateca_certificate_authority" "root" {
  project                                = var.project_id
  pool                                   = google_privateca_ca_pool.device.name
  certificate_authority_id               = "${var.prefix}-device-root"
  location                               = var.region
  type                                   = "SELF_SIGNED"
  lifetime                               = "315360000s" # 10 years
  deletion_protection                    = false
  skip_grace_period                      = true
  ignore_active_certificates_on_deletion = true
  key_spec {
    algorithm = "EC_P256_SHA256"
  }
  config {
    subject_config {
      subject {
        organization = "AGY POC"
        common_name  = "AGY Device Root CA"
      }
    }
    x509_config {
      ca_options {
        is_ca                  = true
        max_issuer_path_length = 0
      }
      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }
        extended_key_usage {}
      }
    }
  }
}

# ----------------------------------------------------------------- FLEET devices (certificate-only, e.g. laptops)
# Separate pool and root: the workstation SA has no rights here, so a VM can never mint a laptop identity.
# Pool policy only permits spiffe://<project>.<domain>/fleet/<device-id>; issuance by fleet_issuers (your MDM).
resource "google_privateca_ca_pool" "fleet" {
  count    = var.enable_fleet ? 1 : 0
  project  = var.project_id
  name     = "${var.prefix}-fleet-pool-${var.suffix}"
  location = var.region
  tier     = "DEVOPS"
  publishing_options {
    publish_ca_cert = false
    publish_crl     = false
  }
  issuance_policy {
    maximum_lifetime = var.fleet_cert_lifetime
    allowed_key_types {
      elliptic_curve {
        signature_algorithm = "ECDSA_P256"
      }
    }
    identity_constraints {
      allow_subject_passthrough           = true
      allow_subject_alt_names_passthrough = true
      cel_expression {
        title      = "fleet-spiffe-only"
        expression = "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.startsWith('spiffe://${var.project_id}.${var.dns_zone_domain}/fleet/'))"
      }
    }
    baseline_values {
      ca_options {
        is_ca = false
      }
      key_usage {
        base_key_usage {
          digital_signature = true
          key_agreement     = true
        }
        extended_key_usage {
          client_auth = true
        }
      }
    }
  }
}

resource "google_privateca_certificate_authority" "fleet_root" {
  count                                  = var.enable_fleet ? 1 : 0
  project                                = var.project_id
  pool                                   = google_privateca_ca_pool.fleet[0].name
  certificate_authority_id               = "${var.prefix}-fleet-root"
  location                               = var.region
  type                                   = "SELF_SIGNED"
  lifetime                               = "315360000s"
  deletion_protection                    = false
  skip_grace_period                      = true
  ignore_active_certificates_on_deletion = true
  key_spec {
    algorithm = "EC_P256_SHA256"
  }
  config {
    subject_config {
      subject {
        organization = "AGY POC"
        common_name  = "AGY Fleet Device Root CA"
      }
    }
    x509_config {
      ca_options {
        is_ca                  = true
        max_issuer_path_length = 0
      }
      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }
        extended_key_usage {}
      }
    }
  }
}

resource "google_privateca_ca_pool_iam_member" "fleet_issuer" {
  for_each = var.enable_fleet ? toset(var.fleet_issuers) : toset([])
  ca_pool  = google_privateca_ca_pool.fleet[0].id
  role     = "roles/privateca.certificateRequester"
  member   = each.value
}

# Device certificate template: clientAuth only, SPIFFE URI SAN spiffe://<project>.<internal-domain>/device/<instance>
# (trust domain must be an FQDN - RFC 5280 4.2.1.7 lint), max 30 days
resource "google_privateca_certificate_template" "device" {
  project          = var.project_id
  name             = var.template_name_suffix == "" ? "${var.prefix}-device-client" : "${var.prefix}-device-client-${var.template_name_suffix}"
  location         = var.region
  maximum_lifetime = "2592000s"
  predefined_values {
    key_usage {
      base_key_usage {
        digital_signature = true
        key_agreement     = true
      }
      extended_key_usage {
        client_auth = true
      }
    }
    ca_options {
      is_ca = false
    }
  }
  identity_constraints {
    allow_subject_passthrough           = true
    allow_subject_alt_names_passthrough = true
    cel_expression {
      expression = "subject_alt_names.all(san, san.type == URI && san.value.startsWith('spiffe://${var.project_id}.${var.dns_zone_domain}/device/'))"
      title      = "device-spiffe-only"
    }
  }
}

# ----------------------------------------------------------------- server PKI (separate pool + root: device and server trust are split)
resource "google_privateca_ca_pool" "server" {
  project  = var.project_id
  name     = "${var.prefix}-server-pool-${var.suffix}"
  location = var.region
  tier     = "DEVOPS"
  publishing_options {
    publish_ca_cert = false
    publish_crl     = false
  }
  issuance_policy {
    maximum_lifetime = "2592000s"
    allowed_key_types {
      elliptic_curve {
        signature_algorithm = "ECDSA_P256"
      }
    }
  }
  lifecycle {
    ignore_changes = [issuance_policy[0].baseline_values]
  }
}

resource "google_privateca_certificate_authority" "server_root" {
  project                                = var.project_id
  pool                                   = google_privateca_ca_pool.server.name
  certificate_authority_id               = "${var.prefix}-server-root"
  location                               = var.region
  type                                   = "SELF_SIGNED"
  lifetime                               = "315360000s"
  deletion_protection                    = false
  skip_grace_period                      = true
  ignore_active_certificates_on_deletion = true
  key_spec {
    algorithm = "EC_P256_SHA256"
  }
  config {
    subject_config {
      subject {
        organization = "AGY POC"
        common_name  = "AGY Internal Server Root CA"
      }
    }
    x509_config {
      ca_options {
        is_ca                  = true
        max_issuer_path_length = 0
      }
      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }
        extended_key_usage {}
      }
    }
  }
}

# ----------------------------------------------------------------- server certificate (Google-managed key, issued by the server pool)
resource "google_certificate_manager_certificate_issuance_config" "server" {
  project                    = var.project_id
  name                       = "${var.prefix}-gw-issuance-srv"
  location                   = var.region
  lifetime                   = "2592000s"
  rotation_window_percentage = 66
  key_algorithm              = "ECDSA_P256"
  certificate_authority_config {
    certificate_authority_service_config {
      ca_pool = google_privateca_ca_pool.server.id
    }
  }
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [google_privateca_certificate_authority.server_root, google_privateca_ca_pool_iam_member.certmgr]
}

data "google_project" "this" {
  project_id = var.project_id
}

resource "google_project_service_identity" "certmgr" {
  provider = google-beta
  project  = var.project_id
  service  = "certificatemanager.googleapis.com"
}

resource "google_privateca_ca_pool_iam_member" "certmgr" {
  ca_pool = google_privateca_ca_pool.server.id
  role    = "roles/privateca.certificateRequester"
  member  = "serviceAccount:${google_project_service_identity.certmgr.email}"
}

resource "google_certificate_manager_certificate" "server" {
  project  = var.project_id
  name     = "${var.prefix}-gw-server-srv"
  location = var.region
  lifecycle {
    create_before_destroy = true
  }
  managed {
    domains         = [var.gateway_hostname]
    issuance_config = google_certificate_manager_certificate_issuance_config.server.id
  }
}

# ----------------------------------------------------------------- client-certificate validation
resource "google_certificate_manager_trust_config" "device" {
  project  = var.project_id
  name     = "${var.prefix}-device-trust"
  location = var.region
  trust_stores {
    trust_anchors {
      pem_certificate = google_privateca_certificate_authority.root.pem_ca_certificates[0]
    }
    dynamic "trust_anchors" {
      for_each = var.enable_fleet ? [google_privateca_certificate_authority.fleet_root[0].pem_ca_certificates[0]] : []
      content {
        pem_certificate = trust_anchors.value
      }
    }
  }
}

resource "google_network_security_server_tls_policy" "mtls" {
  provider = google-beta
  project  = var.project_id
  name     = "${var.prefix}-gw-mtls"
  location = var.region
  lifecycle {
    # module depends_on defers the project-number data source -> spurious "forces replacement"
    # while the policy is attached to the proxy (API refuses). Trust config is immutable by name.
    ignore_changes = [mtls_policy[0].client_validation_trust_config]
  }
  mtls_policy {
    client_validation_mode         = "REJECT_INVALID"
    client_validation_trust_config = "projects/${data.google_project.this.number}/locations/${var.region}/trustConfigs/${google_certificate_manager_trust_config.device.name}"
  }
}

# ----------------------------------------------------------------- regional internal Application Load Balancer
resource "google_compute_subnetwork" "proxy_only" {
  project       = var.project_id
  name          = "${var.prefix}-proxy-only-${var.region}"
  region        = var.region
  network       = var.network_id
  ip_cidr_range = var.proxy_subnet_cidr
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

resource "google_compute_region_network_endpoint_group" "gw" {
  project               = var.project_id
  name                  = "${var.prefix}-gw-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"
  cloud_run {
    service = var.cloud_run_service
  }
}

resource "google_compute_region_backend_service" "gw" {
  project               = var.project_id
  name                  = "${var.prefix}-gw-backend"
  region                = var.region
  load_balancing_scheme = "INTERNAL_MANAGED"
  protocol              = "HTTPS"
  backend {
    group           = google_compute_region_network_endpoint_group.gw.id
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }
  log_config {
    enable      = true
    sample_rate = 1.0
  }
}

locals {
  # verified client-certificate facts injected by the LB (gateway binds them to the device token)
  mtls_headers = {
    "X-Client-Cert-Present"        = "{client_cert_present}"
    "X-Client-Cert-Chain-Verified" = "{client_cert_chain_verified}"
    "X-Client-Cert-Error"          = "{client_cert_error}"
    "X-Client-Cert-Hash"           = "{client_cert_sha256_fingerprint}"
    "X-Client-Cert-Serial"         = "{client_cert_serial_number}"
    "X-Client-Cert-URI-SANs"       = "{client_cert_uri_sans}"
    "X-Client-Cert-SPIFFE-ID"      = "{client_cert_spiffe_id}"
    "X-AGY-LB-Auth"                = var.lb_header_secret
  }
}

resource "google_compute_region_url_map" "gw" {
  project         = var.project_id
  name            = "${var.prefix}-gw-urlmap"
  region          = var.region
  default_service = google_compute_region_backend_service.gw.id
  host_rule {
    hosts        = ["*"]
    path_matcher = "gw"
  }
  path_matcher {
    name            = "gw"
    default_service = google_compute_region_backend_service.gw.id
    header_action {
      dynamic "request_headers_to_add" {
        for_each = local.mtls_headers
        content {
          header_name  = request_headers_to_add.key
          header_value = request_headers_to_add.value
          replace      = true # never trust client-supplied copies of these headers
        }
      }
    }
  }
}

resource "google_compute_region_target_https_proxy" "gw" {
  provider                         = google-beta
  project                          = var.project_id
  name                             = "${var.prefix}-gw-https-proxy"
  region                           = var.region
  url_map                          = google_compute_region_url_map.gw.id
  certificate_manager_certificates = [google_certificate_manager_certificate.server.id]
  server_tls_policy                = google_network_security_server_tls_policy.mtls.id
}

resource "google_compute_address" "gw" {
  project      = var.project_id
  name         = "${var.prefix}-gw-ilb-ip"
  region       = var.region
  subnetwork   = var.subnet_id
  address_type = "INTERNAL"
}

resource "google_compute_forwarding_rule" "gw" {
  project               = var.project_id
  name                  = "${var.prefix}-gw-ilb"
  region                = var.region
  load_balancing_scheme = "INTERNAL_MANAGED"
  network               = var.network_id
  subnetwork            = var.subnet_id
  ip_address            = google_compute_address.gw.address
  ip_protocol           = "TCP"
  port_range            = "443"
  target                = google_compute_region_target_https_proxy.gw.id
  depends_on            = [google_compute_subnetwork.proxy_only]
}

# ----------------------------------------------------------------- private DNS
resource "google_dns_managed_zone" "internal" {
  project    = var.project_id
  name       = "${var.prefix}-internal"
  dns_name   = "${var.dns_zone_domain}."
  visibility = "private"
  private_visibility_config {
    networks {
      network_url = var.network_id
    }
  }
}

resource "google_dns_record_set" "gw" {
  project      = var.project_id
  managed_zone = google_dns_managed_zone.internal.name
  name         = "${var.gateway_hostname}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_address.gw.address]
}

output "gateway_mtls_url" { value = "https://${var.gateway_hostname}" }
output "ilb_ip" { value = google_compute_address.gw.address }
output "ca_pool" { value = google_privateca_ca_pool.device.id }
output "ca_pool_name" { value = google_privateca_ca_pool.device.name }
output "device_template" { value = google_privateca_certificate_template.device.id }
output "root_ca_pem" { value = google_privateca_certificate_authority.root.pem_ca_certificates[0] }
output "server_root_pem" { value = google_privateca_certificate_authority.server_root.pem_ca_certificates[0] }
output "spiffe_prefix" { value = "spiffe://${var.project_id}.${var.dns_zone_domain}/device/" }

# Device enrolment: the workstation SA may request certificates from the DEVICE pool, whose issuance policy
# only permits device SPIFFE client certificates (IAM conditions on the template attribute were not matchable).
resource "google_privateca_certificate_template_iam_member" "device_user" {
  count                = var.device_requester == "" ? 0 : 1
  project              = var.project_id
  location             = var.region
  certificate_template = google_privateca_certificate_template.device.id
  role                 = "roles/privateca.templateUser"
  member               = "serviceAccount:${var.device_requester}"
}

resource "google_privateca_ca_pool_iam_member" "device_requester" {
  count   = var.device_requester == "" ? 0 : 1
  ca_pool = google_privateca_ca_pool.device.id
  role    = "roles/privateca.certificateRequester"
  member  = "serviceAccount:${var.device_requester}"
}

resource "google_privateca_certificate_template_iam_member" "device_user_extra" {
  for_each             = var.extra_device_requesters
  project              = var.project_id
  location             = var.region
  certificate_template = google_privateca_certificate_template.device.id
  role                 = "roles/privateca.templateUser"
  member               = "serviceAccount:${each.value}"
}

resource "google_privateca_ca_pool_iam_member" "device_requester_extra" {
  for_each = var.extra_device_requesters
  ca_pool  = google_privateca_ca_pool.device.id
  role     = "roles/privateca.certificateRequester"
  member   = "serviceAccount:${each.value}"
}

output "fleet_ca_pool" { value = var.enable_fleet ? google_privateca_ca_pool.fleet[0].id : "" }
output "fleet_ca_pool_name" { value = var.enable_fleet ? google_privateca_ca_pool.fleet[0].name : "" }
output "fleet_spiffe_prefix" { value = var.enable_fleet ? "spiffe://${var.project_id}.${var.dns_zone_domain}/fleet/" : "" }

# device enrolment bindings became optional (gateway-only profile): keep existing state addresses
moved {
  from = google_privateca_certificate_template_iam_member.device_user
  to   = google_privateca_certificate_template_iam_member.device_user[0]
}
moved {
  from = google_privateca_ca_pool_iam_member.device_requester
  to   = google_privateca_ca_pool_iam_member.device_requester[0]
}
