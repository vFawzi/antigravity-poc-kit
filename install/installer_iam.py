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

"""Grant / revoke the permissions an installer identity needs - run by a project admin who delegates the setup.

  install/installer_iam.py grant  --project P --principal user:alice@example.com [--hours 8] [--no-evidence]
  install/installer_iam.py revoke --project P --principal user:alice@example.com [--keep-role]
  install/installer_iam.py show   --project P --principal user:alice@example.com

What grant does (least privilege, time-bound):
  * custom role  agyPocInstaller  = install/permissions.txt minus the few permissions Google does not allow in
    custom roles (looked up live), bound to the principal with an IAM condition  request.time < <expiry>
  * roles/iam.denyAdmin  (deny-policy permissions can't be in custom roles, and Google accepts this role ONLY on the
    organization - not on projects or folders): granted on the organization with the same expiry condition; only
    when prompt evidence is used (--no-evidence skips it)
  * no basic roles (Owner/Editor)
revoke removes exactly these bindings and deletes the custom role (soft delete, undeleted on the next grant).
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Any

ROLE_ID = "agyPocInstaller"
EXTRA_ROLES_EVIDENCE = ("roles/iam.denyAdmin",)
COND_PREFIX = "agy-installer"
ADMIN_NEEDS = ("resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy",
               "iam.roles.create", "iam.roles.update", "iam.roles.get", "iam.roles.delete", "iam.roles.undelete",
               "serviceusage.services.enable")
HELP_ORG = """Folder / organization level:
  * roles/iam.denyAdmin can only be granted on the ORGANIZATION. grant adds it there, time-bound (IAM condition), and
    revoke removes it. The admin needs organization setIamPolicy (roles/resourcemanager.organizationAdmin) - or an
    org admin runs grant/revoke. Use --no-evidence when prompt_logging is none/hash to skip it.
  * Nothing else is needed above the project. Org policies that block resources are reported by the preflight;
    creating the project / linking billing is out of scope (create the project first)."""

os.environ["CLOUDSDK_CORE_DISABLE_PROMPTS"] = "1"   # a hidden gcloud prompt (output captured) would hang the grant
BOOTSTRAP_APIS = ("cloudresourcemanager.googleapis.com", "iam.googleapis.com", "serviceusage.googleapis.com",
                  "orgpolicy.googleapis.com")   # Org Policy: the preflight reads run.managed.requireInvokerIam
BOOTSTRAP_WAIT_TRIES, BOOTSTRAP_WAIT_SECONDS = 12, 10   # ~2 min for a freshly enabled API to answer
SLEEP = time.sleep

if sys.platform == "darwin" and not os.environ.get("SSL_CERT_FILE") and os.path.exists("/etc/ssl/cert.pem"):
    os.environ["SSL_CERT_FILE"] = "/etc/ssl/cert.pem"


def token() -> str:
    return subprocess.check_output(["gcloud", "auth", "print-access-token", "--quiet"], text=True,
                                   stdin=subprocess.DEVNULL, timeout=120).strip()


def enable_bootstrap_apis(project: str) -> None:
    """Greenfield projects: Cloud Resource Manager / IAM / Service Usage are off, and every later call needs them.
    Enabled as the admin with gcloud (works before any API of the project is on), then wait until they answer."""
    print(f"[grant] enabling bootstrap APIs on {project} (Cloud Resource Manager, IAM, Service Usage, Org Policy)")
    cmd = ["gcloud", "services", "enable", *BOOTSTRAP_APIS, "--project", project, "--quiet"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=600)
        rc, err = r.returncode, (r.stderr or r.stdout).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        rc, err = 1, str(e)
    if rc != 0:
        raise SystemExit(f"cannot enable the bootstrap APIs on {project}: {err[-400:]}\n"
                         f"  Ask someone with roles/serviceusage.serviceUsageAdmin on the project (and a linked billing\n"
                         f"  account) to run:\n    {' '.join(cmd[:-1])}\n  then re-run this command.")
    for i in range(1, BOOTSTRAP_WAIT_TRIES + 1):
        try:
            api("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions", project,
                {"permissions": ["resourcemanager.projects.get"]}, attempts=1)
            return
        except SystemExit as e:
            if i == BOOTSTRAP_WAIT_TRIES or not any(k in str(e) for k in ("SERVICE_DISABLED", "has not been used", "it is disabled")):
                raise
            print(f"[grant] APIs not ready yet on {project} (enablement propagating) - retry {i}/{BOOTSTRAP_WAIT_TRIES}")
            SLEEP(BOOTSTRAP_WAIT_SECONDS)


def api(method: str, url: str, project: str, body: dict[str, Any] | None = None, attempts: int = 5) -> dict[str, Any]:
    """REST call with backoff on 429/5xx and IAM etag conflicts (409)."""
    for n in range(attempts):
        req = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json",
                                              "X-Goog-User-Project": project})
        try:
            if not req.full_url.startswith("https://"):
                raise ValueError(f"refusing non-https URL: {req.full_url}")
            with urllib.request.urlopen(req, timeout=60) as r:  # nosec B310 - https enforced above
                raw = r.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code in (409, 429, 500, 502, 503, 504) and n < attempts - 1:
                time.sleep(2 ** n)
                continue
            raise SystemExit(f"ERROR {e.code} {method} {url.split('?')[0]}: {e.read()[:400].decode(errors='replace')}")
    raise SystemExit("unreachable")


def deny_scope(project: str, override: str | None) -> str:
    """roles/iam.denyAdmin is grantable ONLY on the organization (verified: project and folder reject it)."""
    if override:
        return override
    anc = api("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getAncestry", project, {})
    ids = [a["resourceId"] for a in anc.get("ancestor", [])]
    for i in ids:
        if i["type"] == "organization":
            return f"{i['type']}s/{i['id']}"
    raise SystemExit("project has no organization: roles/iam.denyAdmin can't be granted (use --no-evidence)")


def scope_policy(scope: str, project: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    base = f"https://cloudresourcemanager.googleapis.com/v3/{scope}"
    if policy is None:
        return api("POST", f"{base}:getIamPolicy", project, {"options": {"requestedPolicyVersion": 3}})
    policy["version"] = 3
    return api("POST", f"{base}:setIamPolicy", project, {"policy": policy, "updateMask": "bindings,etag"})


def check_scope_admin(scope: str, project: str) -> None:
    perm = "resourcemanager.folders.setIamPolicy" if scope.startswith("folders/") else "resourcemanager.organizations.setIamPolicy"
    r = api("POST", f"https://cloudresourcemanager.googleapis.com/v3/{scope}:testIamPermissions", project, {"permissions": [perm]})
    if perm not in r.get("permissions", []):
        raise SystemExit(f"you (the admin) lack {perm} on {scope} - needed to grant roles/iam.denyAdmin there.\n"
                         f"  Ask a folder/org admin, or re-run with --no-evidence (prompt_logging none/hash).")


def check_admin(project: str) -> None:
    r = api("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:testIamPermissions", project,
            {"permissions": list(ADMIN_NEEDS)})
    missing = sorted(set(ADMIN_NEEDS) - set(r.get("permissions", [])))
    if missing:
        raise SystemExit("you (the admin) lack: " + ", ".join(missing) +
                         "\n  -> needs roles/resourcemanager.projectIamAdmin + roles/iam.roleAdmin + roles/serviceusage.serviceUsageAdmin")


def wanted_permissions(project: str) -> tuple[list[str], list[str]]:
    """(custom-role permissions, permissions only available through predefined roles)."""
    mine = [l.strip() for l in pathlib.Path(__file__).with_name("permissions.txt").read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    support: dict[str, str] = {}
    page = None
    while True:
        body: dict[str, Any] = {"fullResourceName": f"//cloudresourcemanager.googleapis.com/projects/{project}", "pageSize": 1000}
        if page:
            body["pageToken"] = page
        r = api("POST", "https://iam.googleapis.com/v1/permissions:queryTestablePermissions", project, body)
        support.update({p["name"]: p.get("customRolesSupportLevel", "SUPPORTED") for p in r.get("permissions", [])})
        page = r.get("nextPageToken")
        if not page:
            break
    ok = [p for p in mine if support.get(p, "SUPPORTED") != "NOT_SUPPORTED" and p in support]
    other = [p for p in mine if p not in ok]
    return sorted(set(ok)), sorted(set(other))


def upsert_role(project: str, perms: list[str]) -> str:
    name = f"projects/{project}/roles/{ROLE_ID}"
    base = "https://iam.googleapis.com/v1/"
    role = {"title": "AGY POC installer (temporary)", "stage": "GA", "includedPermissions": perms,
            "description": "Least-privilege installer role generated from install/permissions.txt. Remove after setup."}
    try:
        cur = api("GET", base + name, project, attempts=1)
    except SystemExit as e:
        if "404" not in str(e):
            raise
        cur = {}
    if not cur:
        api("POST", f"{base}projects/{project}/roles", project, {"roleId": ROLE_ID, "role": role})
        print(f"  + custom role {ROLE_ID} created ({len(perms)} permissions)")
    else:
        if cur.get("deleted"):
            api("POST", f"{base}{name}:undelete", project, {"etag": cur.get("etag")})
            print(f"  ~ custom role {ROLE_ID} undeleted")
        api("PATCH", f"{base}{name}?updateMask=title,description,includedPermissions,stage", project, role)
        print(f"  ~ custom role {ROLE_ID} updated ({len(perms)} permissions)")
    return name


def get_policy(project: str) -> dict[str, Any]:
    return api("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy", project,
               {"options": {"requestedPolicyVersion": 3}})


def set_policy(project: str, policy: dict[str, Any]) -> None:
    policy["version"] = 3
    api("POST", f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:setIamPolicy", project,
        {"policy": policy, "updateMask": "bindings,etag"})


def ours(b: dict[str, Any], project: str) -> bool:
    return b.get("role") in (f"projects/{project}/roles/{ROLE_ID}", *EXTRA_ROLES_EVIDENCE) and \
        str(b.get("condition", {}).get("title", "")).startswith(COND_PREFIX)


def grant(a: argparse.Namespace) -> None:
    enable_bootstrap_apis(a.project)   # before any project call (greenfield: Cloud Resource Manager is off)
    check_admin(a.project)
    perms, other = wanted_permissions(a.project)
    print(f"project {a.project}: {len(perms)} permissions in the custom role; via predefined role: {', '.join(other) or '-'}")
    role = upsert_role(a.project, perms)
    expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=a.hours)).replace(microsecond=0)
    cond = {"title": f"{COND_PREFIX}-until-{expiry:%Y%m%dT%H%MZ}",
            "description": "Temporary installer access (install/installer_iam.py); revoke after setup.",
            "expression": f'request.time < timestamp("{expiry.isoformat().replace("+00:00", "Z")}")'}
    scope = None if a.no_evidence else deny_scope(a.project, a.deny_scope)
    if scope:
        check_scope_admin(scope, a.project)
    pol = get_policy(a.project)
    pol["bindings"] = [b for b in pol.get("bindings", []) if not (ours(b, a.project) and a.principal in b.get("members", []))]
    pol["bindings"].append({"role": role, "members": [a.principal], "condition": cond})
    set_policy(a.project, pol)
    print(f"  + {a.principal} -> {role} on projects/{a.project}  (until {expiry:%Y-%m-%d %H:%M} UTC)")
    if scope:
        sp = scope_policy(scope, a.project)
        sp["bindings"] = [b for b in sp.get("bindings", []) if not (ours(b, a.project) and a.principal in b.get("members", []))]
        sp["bindings"] += [{"role": r, "members": [a.principal], "condition": cond} for r in EXTRA_ROLES_EVIDENCE]
        scope_policy(scope, a.project, sp)
        for r in EXTRA_ROLES_EVIDENCE:
            print(f"  + {a.principal} -> {r} on {scope}  (until {expiry:%Y-%m-%d %H:%M} UTC; folder/org role)")
    print(f"\nThe installer identity can now run ./install.sh (IAM propagation: allow ~2 min).\n"
          f"After the setup:  install/revoke-installer.sh --project {a.project} --principal {a.principal}")


def revoke(a: argparse.Namespace) -> None:
    check_admin(a.project)
    pol = get_policy(a.project)
    before = len(pol.get("bindings", []))
    removed = [b["role"] for b in pol.get("bindings", []) if ours(b, a.project) and a.principal in b.get("members", [])]
    for b in pol.get("bindings", []):
        if ours(b, a.project) and a.principal in b.get("members", []):
            b["members"] = [m for m in b["members"] if m != a.principal]
    pol["bindings"] = [b for b in pol.get("bindings", []) if b.get("members")]
    if removed:
        set_policy(a.project, pol)
    print(f"removed {len(removed)} installer binding(s) for {a.principal} on projects/{a.project}: {', '.join(removed) or '-'} "
          f"({before} -> {len(pol['bindings'])} bindings)")
    try:
        scope = deny_scope(a.project, a.deny_scope)
        sp = scope_policy(scope, a.project)
        gone = [b["role"] for b in sp.get("bindings", []) if ours(b, a.project) and a.principal in b.get("members", [])]
        if gone:
            check_scope_admin(scope, a.project)
            for b in sp["bindings"]:
                if ours(b, a.project):
                    b["members"] = [m for m in b["members"] if m != a.principal]
            sp["bindings"] = [b for b in sp["bindings"] if b.get("members")]
            scope_policy(scope, a.project, sp)
        print(f"removed {len(gone)} installer binding(s) on {scope}: {', '.join(gone) or '-'}")
    except SystemExit as e:
        print(f"  (folder/org bindings not changed: {str(e)[:160]})")
    still = [b for b in pol["bindings"] if ours(b, a.project)]
    if not a.keep_role and not still:
        try:
            api("DELETE", f"https://iam.googleapis.com/v1/projects/{a.project}/roles/{ROLE_ID}", a.project, attempts=1)
            print(f"  - custom role {ROLE_ID} deleted (soft delete; restored automatically by the next grant)")
        except SystemExit as e:
            print(f"  (custom role not deleted: {str(e)[:120]})")
    show(a, header="remaining project-level roles")


def show(a: argparse.Namespace, header: str = "project-level roles") -> None:
    pol = get_policy(a.project)
    mine = [(b["role"], b.get("condition", {}).get("title", "")) for b in pol.get("bindings", []) if a.principal in b.get("members", [])]
    print(f"\n{header} of {a.principal}:")
    for r, c in mine or [("(none)", "")]:
        print(f"  {r}{'  [' + c + ']' if c else ''}")
    print("Note: runtime access granted by Terraform to operator_principals / investigators (IAP tunnel, OS Admin Login,\n"
          "persona secrets, PAM eligibility) is resource-level and intentionally kept; change those in install.conf.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], epilog=HELP_ORG,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("grant", "revoke", "show"):
        s = sub.add_parser(name)
        s.add_argument("--project", required=True)
        s.add_argument("--principal", required=True, help="user:… | group:… | serviceAccount:…")
        if name == "grant":
            s.add_argument("--hours", type=int, default=8, help="access expires automatically (1-72, default 8)")
            s.add_argument("--no-evidence", action="store_true", help="skip roles/iam.denyAdmin (prompt_logging none/hash)")
        if name == "revoke":
            s.add_argument("--keep-role", action="store_true", help="don't delete the custom role")
        if name in ("grant", "revoke"):
            s.add_argument("--deny-scope", help="organizations/ID for roles/iam.denyAdmin (default: the project's organization)")
    a = ap.parse_args()
    if not a.principal.split(":", 1)[0] in ("user", "group", "serviceAccount") or "@" not in a.principal:
        raise SystemExit("principal must be user:…, group:… or serviceAccount:…")
    if a.cmd == "grant" and not 1 <= a.hours <= 72:
        raise SystemExit("--hours must be 1..72")
    {"grant": grant, "revoke": revoke, "show": show}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
