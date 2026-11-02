#!/usr/bin/env python3
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

"""Check which permissions from install/permissions.txt the caller holds on a project.

Uses Resource Manager projects.testIamPermissions, which works on a project with NO APIs enabled.
Usage: install/check_permissions.py <project-id> [permissions-file]
Exit code: 0 = all granted, 1 = missing permissions (listed with the role to grant), 2 = error.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROLE_HINTS: dict[str, str] = {
    "serviceusage": "roles/serviceusage.serviceUsageAdmin", "resourcemanager": "roles/resourcemanager.projectIamAdmin",
    "iam.serviceAccounts": "roles/iam.serviceAccountAdmin + roles/iam.serviceAccountUser", "iam.roles": "roles/iam.roleAdmin", "iam.denypolicies": "roles/iam.denyAdmin (ORGANIZATION level only - run install/grant-installer.sh)", "resourcemanager.tag": "roles/resourcemanager.tagAdmin + roles/resourcemanager.tagUser", "orgpolicy": "roles/orgpolicy.policyViewer",
    "compute": "roles/compute.admin", "iap": "roles/iap.admin", "cloudkms.cryptoKeyVersions.useToEncrypt": "roles/cloudkms.cryptoKeyEncrypter", "cloudkms": "roles/cloudkms.admin", "privilegedaccessmanager": "roles/privilegedaccessmanager.admin",
    "storage": "roles/storage.admin", "secretmanager": "roles/secretmanager.admin",
    "artifactregistry": "roles/artifactregistry.admin", "cloudbuild": "roles/cloudbuild.builds.editor",
    "run": "roles/run.admin", "modelarmor": "roles/modelarmor.admin", "aiplatform": "roles/aiplatform.user",
    "privateca": "roles/privateca.admin", "certificatemanager": "roles/certificatemanager.owner",
    "networksecurity": "roles/networksecurity.admin", "dns": "roles/dns.admin",
    "logging": "roles/logging.admin", "monitoring": "roles/monitoring.editor", "bigquery": "roles/bigquery.admin",
}


def role_for(perm: str) -> str:
    for prefix in sorted(ROLE_HINTS, key=len, reverse=True):
        if perm.startswith(prefix):
            return ROLE_HINTS[prefix]
    return "(custom)"


# Bucket-level permissions: Owner/Editor hold these only via the legacy bucket convenience bindings
# (projectOwner/projectEditor -> roles/storage.legacyBucketOwner) on buckets they create, so the
# project-level testIamPermissions reports them as missing. Treated as satisfied for basic-role holders.
BUCKET_SCOPED: frozenset[str] = frozenset({
    "storage.buckets.get", "storage.buckets.update", "storage.buckets.setIamPolicy",
    "storage.objects.create", "storage.objects.get", "storage.objects.delete",
})
CRM = "https://cloudresourcemanager.googleapis.com/v1/projects"


def _post(url: str, body: dict, token: str, attempts: int = 5) -> dict:
    """POST with exponential backoff on 429/5xx."""
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    if not req.full_url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {req.full_url}")
    for n in range(attempts):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310 - https enforced (req.full_url)
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and n < attempts - 1:
                time.sleep(2 ** n)
                continue
            raise
    raise RuntimeError("unreachable")


def holds_basic_role(project: str, account: str, token: str) -> bool:
    """True if the caller is directly bound to roles/owner or roles/editor (groups are not expanded)."""
    try:
        policy = _post(f"{CRM}/{project}:getIamPolicy", {}, token)
    except urllib.error.HTTPError:
        return False
    members = {f"user:{account}", f"serviceAccount:{account}"}
    return any(b.get("role") in ("roles/owner", "roles/editor") and members & set(b.get("members", []))
               for b in policy.get("bindings", []))


def test(project: str, perms: list[str], token: str) -> tuple[set[str], list[str]]:
    """Return (granted, invalid). Splits batches to isolate permission names the API rejects."""
    try:
        return set(_post(f"{CRM}/{project}:testIamPermissions", {"permissions": perms}, token)
                   .get("permissions", [])), []
    except urllib.error.HTTPError as e:
        if e.code == 400 and len(perms) > 1:
            mid = len(perms) // 2
            g1, i1 = test(project, perms[:mid], token)
            g2, i2 = test(project, perms[mid:], token)
            return g1 | g2, i1 + i2
        if e.code == 400:
            return set(), perms
        raise


def main() -> int:
    project = sys.argv[1]
    pfile = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else pathlib.Path(__file__).with_name("permissions.txt"))
    perms = [l.strip() for l in pfile.read_text().splitlines() if l.strip() and not l.startswith("#")]
    token = subprocess.check_output(["gcloud", "auth", "print-access-token"], text=True).strip()
    granted: set[str] = set()
    invalid: list[str] = []
    try:
        for i in range(0, len(perms), 90):
            g, inv = test(project, perms[i:i + 90], token)
            granted |= g
            invalid += inv
    except urllib.error.HTTPError as e:
        print(f"ERROR: testIamPermissions failed ({e.code}): {e.read()[:300]!r}")
        return 2
    missing = [p for p in perms if p not in granted and p not in invalid]
    account = subprocess.check_output(["gcloud", "config", "get-value", "account"], text=True).strip()
    legacy: list[str] = []
    if any(p in BUCKET_SCOPED for p in missing) and "storage.buckets.create" in granted \
            and holds_basic_role(project, account, token):
        legacy = [p for p in missing if p in BUCKET_SCOPED]
        missing = [p for p in missing if p not in BUCKET_SCOPED]
    print(f"permissions checked: {len(perms)}  granted: {len(granted)}  "
          f"via-legacy-bucket-roles: {len(legacy)}  missing: {len(missing)}  unknown-names: {len(invalid)}")
    if legacy:
        print(f"  ~ {len(legacy)} bucket-level storage permissions satisfied via Owner/Editor legacy bucket roles")
    for p in invalid:
        print(f"  ? unknown permission name (update permissions.txt): {p}")
    if missing:
        roles = sorted({role_for(p) for p in missing})
        print("  missing permissions:")
        for p in missing:
            print(f"    ✗ {p}   -> {role_for(p)}")
        print("  ask a project admin to grant (least privilege, project scope):")
        for r in roles:
            for single in r.split(" + "):
                if single.startswith("roles/"):
                    print(f"    gcloud projects add-iam-policy-binding {project} --member=user:{account} --role={single}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
