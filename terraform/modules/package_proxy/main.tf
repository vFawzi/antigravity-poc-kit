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

# Corporate package proxy: Artifact Registry remote repositories (EU region, CMEK) in front of the public registries.
# Workstations resolve packages only through these endpoints (client config via metadata agy-package-proxy); the
# public registry hosts leave the egress allowlist. NuGet has no Artifact Registry remote format: point
# nuget_feed_url at Azure Artifacts (EU org) or Nexus / Artifactory with a nuget.org proxy.

variable "project_id" { type = string }
variable "region" {
  description = "Artifact Registry location (EU residency), e.g. europe-west4."
  type        = string
}
variable "prefix" { type = string }
variable "kms_key" {
  description = "CMEK key for the repositories (null = Google-managed)."
  type        = string
  default     = null
}
variable "labels" { type = map(string) }
variable "formats" {
  description = "Remote repositories to create: any of npm, python, maven, go, docker."
  type        = list(string)
  default     = ["npm", "python", "maven", "go"]
  validation {
    condition     = alltrue([for f in var.formats : contains(["npm", "python", "maven", "go", "docker"], f)])
    error_message = "formats: npm, python, maven, go, docker."
  }
}
variable "reader_principals" {
  description = "Principals that may pull (e.g. group:developers@example.com). Grant to people / groups, not to workstation service accounts."
  type        = list(string)
  default     = []
}
variable "cleanup_keep_days" {
  description = "Cached packages not requested for this many days are deleted (bounded cache, re-fetched on demand)."
  type        = number
  default     = 90
}

locals {
  upstream = {
    npm    = { format = "NPM", block = "npm" }
    python = { format = "PYTHON", block = "python" }
    maven  = { format = "MAVEN", block = "maven" }
    go     = { format = "GO", block = "common" }
    docker = { format = "DOCKER", block = "docker" }
  }
  repos = { for f in var.formats : f => local.upstream[f] }
}

resource "google_artifact_registry_repository" "remote" {
  for_each      = local.repos
  project       = var.project_id
  location      = var.region
  repository_id = "${var.prefix}-${each.key}-proxy"
  description   = "Corporate ${each.key} proxy (remote repository, cached in ${var.region})"
  format        = each.value.format
  mode          = "REMOTE_REPOSITORY"
  kms_key_name  = var.kms_key
  labels        = var.labels

  remote_repository_config {
    description = "public ${each.key} registry"
    dynamic "npm_repository" {
      for_each = each.value.block == "npm" ? [1] : []
      content { public_repository = "NPMJS" }
    }
    dynamic "python_repository" {
      for_each = each.value.block == "python" ? [1] : []
      content { public_repository = "PYPI" }
    }
    dynamic "maven_repository" {
      for_each = each.value.block == "maven" ? [1] : []
      content { public_repository = "MAVEN_CENTRAL" }
    }
    dynamic "docker_repository" {
      for_each = each.value.block == "docker" ? [1] : []
      content { public_repository = "DOCKER_HUB" }
    }
    dynamic "common_repository" {
      for_each = each.value.block == "common" ? [1] : []
      content { uri = "https://proxy.golang.org" } # the only upstream Artifact Registry accepts for Go
    }
  }

  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "expire-unused-cache"
    action = "DELETE"
    condition {
      older_than = "${var.cleanup_keep_days * 86400}s"
    }
  }
}

resource "google_artifact_registry_repository_iam_member" "reader" {
  for_each   = { for pair in setproduct(keys(local.repos), var.reader_principals) : "${pair[0]}|${pair[1]}" => pair }
  project    = var.project_id
  location   = var.region
  repository = google_artifact_registry_repository.remote[each.value[0]].name
  role       = "roles/artifactregistry.reader"
  member     = each.value[1]
}

output "endpoints" {
  description = "Client endpoints per format (npm registry URL, pip index URL, Maven repo URL, GOPROXY URL, Docker host/path)."
  value = {
    for f, r in google_artifact_registry_repository.remote : f => (
      f == "npm" ? "https://${var.region}-npm.pkg.dev/${var.project_id}/${r.repository_id}/" :
      f == "python" ? "https://${var.region}-python.pkg.dev/${var.project_id}/${r.repository_id}/simple/" :
      f == "maven" ? "https://${var.region}-maven.pkg.dev/${var.project_id}/${r.repository_id}" :
      f == "go" ? "https://${var.region}-go.pkg.dev/${var.project_id}/${r.repository_id}" :
      "${var.region}-docker.pkg.dev/${var.project_id}/${r.repository_id}"
    )
  }
}

output "hosts" {
  description = "Hostnames the workstations need in their egress allowlist."
  value       = distinct([for f in keys(local.repos) : "${var.region}-${f}.pkg.dev"])
}
