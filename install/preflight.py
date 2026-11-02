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

"""Read-only preflight for the AGY POC installer. Creates nothing.

Checks: tools, auth (gcloud + ADC), project, permissions, billing, org-policy constraints, region, quotas.
Usage: install/preflight.py --project P --region R --zone Z [--mtls] [--report preflight-report.md]
Exit code: 0 = no blocking failures, 1 = blocking failures, 2 = internal error.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.error

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import check_permissions as cp  # noqa: E402

CRM = "https://cloudresourcemanager.googleapis.com/v1/projects"
# APIs the stack enables (kept in sync with terraform/modules/security api list)
REQUIRED_SERVICES: tuple[str, ...] = (
    "aiplatform", "artifactregistry", "bigquery", "certificatemanager", "cloudbuild", "cloudkms",
    "cloudresourcemanager", "compute", "dns", "iam", "iap", "logging", "modelarmor", "monitoring",
    "networksecurity", "oslogin", "privateca", "run", "secretmanager", "serviceusage", "storage",
)
MIN_CPUS = 4  # e2-standard-4 workstation; Cloud Run/LB do not use regional CPU quota


@dataclasses.dataclass
class Result:
    check: str
    status: str  # PASS | WARN | FAIL | INFO
    detail: str


RESULTS: list[Result] = []


def add(check: str, status: str, detail: str) -> None:
    RESULTS.append(Result(check, status, detail))
    colour = {"PASS": "32", "WARN": "33", "FAIL": "31", "INFO": "36"}[status]
    print(f"\033[1;{colour}m[{status}]\033[0m {check}: {detail}")


def run(cmd: list[str]) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return p.returncode, (p.stdout or p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, str(e)


def get_json(url: str, token: str, user_project: str | None = None) -> dict:
    import urllib.request
    headers = {"Authorization": f"Bearer {token}"}
    if user_project:
        headers["X-Goog-User-Project"] = user_project
    if not url.startswith("https://"):
        raise ValueError(f"refusing non-https URL: {url}")
    import random, time, urllib.error
    for attempt in range(5):   # Google APIs rate-limit bursts (429) - bounded retry with exponential backoff + jitter
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as r:  # nosec B310 - https enforced above
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503, 504) or attempt == 4:
                raise
            time.sleep(min(16.0, 2 ** attempt) + random.uniform(0, 0.5))
    raise RuntimeError("unreachable")


# ----------------------------------------------------------------------------- checks
def check_tools() -> None:
    for tool in ("gcloud", "python3", "curl", "make", "ssh"):
        add(f"tool {tool}", "PASS" if shutil.which(tool) else "FAIL",
            shutil.which(tool) or "not found in PATH")
    if not (shutil.which("shasum") or shutil.which("sha256sum")):
        add("tool shasum/sha256sum", "FAIL", "not found")
    # plain text output: some distributions (e.g. Cloud Shell) print notices around the JSON form
    rc, out = run(["terraform", "version"]) if shutil.which("terraform") else (1, "")
    m = re.search(r"Terraform v(\d+)\.(\d+)\.(\d+)", out)
    if rc != 0 or not m:
        add("tool terraform", "FAIL", "not found or unreadable version (need >= 1.5) - "
            "https://developer.hashicorp.com/terraform/install" + (f" [{out[:80]}]" if out else ""))
    else:
        major, minor = int(m.group(1)), int(m.group(2))
        add("tool terraform", "PASS" if (major, minor) >= (1, 5) else "FAIL", f"v{'.'.join(m.groups())} (need >= 1.5)")
    add("python", "PASS" if sys.version_info >= (3, 9) else "FAIL", sys.version.split()[0] + " (need >= 3.9)")
    rdp = shutil.which("remmina") or shutil.which("xfreerdp")
    add("RDP client (desktop access)", "PASS" if rdp else "INFO",
        rdp or "remmina/xfreerdp not found - only needed on the machine you connect from (make desktop)")


def check_auth() -> tuple[str, str]:
    rc, token = run(["gcloud", "auth", "print-access-token"])
    if rc != 0:
        add("gcloud auth", "FAIL", "not signed in - run: gcloud auth login")
        return "", ""
    _, account = run(["gcloud", "config", "get-value", "account"])
    add("gcloud auth", "PASS", account)
    rc, _ = run(["gcloud", "auth", "application-default", "print-access-token"])
    cloud_shell = os.environ.get("CLOUD_SHELL") == "true"
    add("ADC (Terraform)", "PASS" if rc == 0 or cloud_shell else "FAIL",
        "ok" if rc == 0 else ("Cloud Shell built-in credentials" if cloud_shell
                              else "missing - run: gcloud auth application-default login"))
    return token, account


def check_project(project: str, token: str) -> bool:
    try:
        p = get_json(f"{CRM}/{project}", token)
    except urllib.error.HTTPError as e:
        add("project", "FAIL", f"{project} not accessible ({e.code}) - check the ID and your access")
        return False
    state = p.get("lifecycleState")
    add("project", "PASS" if state == "ACTIVE" else "FAIL",
        f"{project} #{p.get('projectNumber')} state={state} parent={p.get('parent', {}).get('type')}")
    return state == "ACTIVE"


def check_permissions(project: str, token: str, account: str, no_evidence: bool = False) -> None:
    perms = [l.strip() for l in pathlib.Path(__file__).with_name("permissions.txt").read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    if no_evidence:   # prompt logging none/hash: no evidence store, no deny policy (= grant-installer.sh --no-evidence)
        perms = [p for p in perms if not p.startswith("iam.denypolicies.")]
    granted: set[str] = set()
    invalid: list[str] = []
    for i in range(0, len(perms), 90):
        g, inv = cp.test(project, perms[i:i + 90], token)
        granted |= g
        invalid += inv
    missing = [p for p in perms if p not in granted and p not in invalid]
    if any(p in cp.BUCKET_SCOPED for p in missing) and "storage.buckets.create" in granted \
            and cp.holds_basic_role(project, account, token):
        missing = [p for p in missing if p not in cp.BUCKET_SCOPED]
    if missing:
        roles = sorted({r for p in missing for r in cp.role_for(p).split(" + ")})
        add("permissions", "FAIL", f"{len(missing)}/{len(perms)} missing: {', '.join(missing[:8])}"
            f"{' ...' if len(missing) > 8 else ''} -> grant: {', '.join(roles)} (python3 install/check_permissions.py {project})")
    else:
        add("permissions", "PASS", f"{len(perms)}/{len(perms)} required permissions held")
    if invalid:
        add("permissions list", "WARN", f"unknown names in permissions.txt: {', '.join(invalid)}")


INFERENCE_PERMS = ["iam.roles.create", "iam.roles.get", "iam.roles.update", "iam.roles.delete",
                   "resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"]


def check_inference_project(project: str, token: str) -> None:
    """Optional separate project for model-call billing/quota (terraform inference_project)."""
    if not check_project(project, token):
        return
    g, _ = cp.test(project, INFERENCE_PERMS, token)
    missing = [p for p in INFERENCE_PERMS if p not in g]
    add("inference project permissions", "FAIL" if missing else "PASS",
        f"{project}: missing {', '.join(missing)} (custom role + binding for the gateway SA)" if missing
        else f"{project}: can create the gateway's generate-only role and binding")
    try:
        s = get_json(f"https://serviceusage.googleapis.com/v1/projects/{project}/services/aiplatform.googleapis.com", token)
        on = s.get("state") == "ENABLED"
        add("inference project API", "PASS" if on else "FAIL",
            "aiplatform.googleapis.com enabled" if on else f"enable aiplatform.googleapis.com in {project}")
    except urllib.error.HTTPError as e:
        add("inference project API", "WARN", f"cannot read service state ({e.code})")


SEAT_PERMS = ["logging.sinks.create", "logging.sinks.get", "logging.sinks.delete", "iam.roles.create", "iam.roles.get",
              "iam.roles.delete", "resourcemanager.projects.getIamPolicy", "resourcemanager.projects.setIamPolicy"]


def check_seat(project: str, seat_project: str, location: str, vpc_sc: bool, org_id: str, token: str) -> None:
    """Seat client mode: licences, APIs and rights in the licence project; ACM rights for the perimeter."""
    if seat_project != project and not check_project(seat_project, token):
        return
    host = "discoveryengine.googleapis.com" if location == "global" else f"{location}-discoveryengine.googleapis.com"
    base = f"https://{host}/v1alpha/projects/{seat_project}/locations/{location}"
    try:
        cfgs = get_json(f"{base}/licenseConfigs", token, seat_project).get("licenseConfigs", [])
        active = [c for c in cfgs if c.get("state") == "ACTIVE"]
        add("seat licences", "PASS" if active else "FAIL",
            f"{seat_project}/{location}: " + (", ".join(f"{c.get('subscriptionTier', '?')} x{c.get('licenseCount', '?')}"
                                                     for c in active) if active else "no active Gemini Enterprise subscription"))
        users = get_json(f"{base}/userStores/default_user_store/userLicenses", token, seat_project).get("userLicenses", [])
        n = sum(1 for u in users if u.get("licenseAssignmentState") == "ASSIGNED")
        add("seat users", "PASS" if n else "WARN", f"{n} user(s) with an assigned licence in {location}"
            + ("" if n else " - assign licences before testing"))
    except urllib.error.HTTPError as e:
        add("seat licences", "WARN", f"cannot read licences in {seat_project}/{location} ({e.code})")
    for api in ("businessaicode.googleapis.com", "discoveryengine.googleapis.com"):
        try:
            s = get_json(f"https://serviceusage.googleapis.com/v1/projects/{seat_project}/services/{api}", token)
            on = s.get("state") == "ENABLED"
            add(f"seat API {api.split('.')[0]}", "PASS" if on else "FAIL", "enabled" if on else f"enable {api} in {seat_project}")
        except urllib.error.HTTPError as e:
            add(f"seat API {api.split('.')[0]}", "WARN", f"cannot read ({e.code})")
    if seat_project != project:
        g, _ = cp.test(seat_project, SEAT_PERMS, token)
        missing = [p for p in SEAT_PERMS if p not in g]
        add("seat project permissions", "FAIL" if missing else "PASS",
            f"{seat_project}: missing {', '.join(missing)} (log sinks + containment role)" if missing else
            f"{seat_project}: log sinks and containment role can be created")
    if vpc_sc:
        try:
            r = cp._post(f"https://cloudresourcemanager.googleapis.com/v1/organizations/{org_id}:testIamPermissions",
                         {"permissions": ["accesscontextmanager.policies.create", "accesscontextmanager.servicePerimeters.create",
                                          "accesscontextmanager.accessLevels.create"]}, token)
            held = set(r.get("permissions", []))
            add("seat perimeter rights", "PASS" if len(held) == 3 else "FAIL",
                f"organizations/{org_id}: " + ("Access Context Manager policy admin rights held" if len(held) == 3 else
                                               "needs roles/accesscontextmanager.policyAdmin at organisation level"))
        except urllib.error.HTTPError as e:
            add("seat perimeter rights", "FAIL", f"cannot test organisation permissions ({e.code})")
    add("seat admin checklist", "INFO", "In Gemini Enterprise > Settings > AI developer tools: turn ON prompt and metadata "
        "logging (needed by the inspector); in Workspace API controls: block the consumer Antigravity OAuth client "
        "(see DEPLOYMENT.md, seat mode)")


def check_stale_guard(project: str, token: str) -> None:
    """A preserved evidence deny policy that still lists a deleted gateway SA blocks evidence for the new gateway."""
    import urllib.parse
    parent = urllib.parse.quote(f"cloudresourcemanager.googleapis.com/projects/{project}", safe="")
    base = "https://iam.googleapis.com/v2"
    stale: list[str] = []
    for ref in get_json(f"{base}/policies/{parent}/denypolicies", token).get("policies", []):
        pol = get_json(f"{base}/{ref['name']}", token)
        if any(e.startswith("deleted:principal://iam.googleapis.com/projects/-/serviceAccounts/")
               and f"-gateway@{project}.iam.gserviceaccount.com?uid=" in e
               for r in pol.get("rules", []) for e in r.get("denyRule", {}).get("exceptionPrincipals", [])):
            stale.append(ref["name"].rsplit("/", 1)[-1])
    if stale:
        add("preserved evidence guard", "WARN",
            f"{', '.join(stale)} still lists a deleted gateway service account and will block prompt evidence "
            "(HTTP 403) for the new gateway - after the install run: make adopt-evidence-guard")
    else:
        add("preserved evidence guard", "PASS", "no deny policy references a deleted gateway service account")


def check_billing(project: str, token: str) -> None:
    for up in (project, None):
        try:
            b = get_json(f"https://cloudbilling.googleapis.com/v1/projects/{project}/billingInfo", token, up)
            ok = b.get("billingEnabled", False)
            add("billing", "PASS" if ok else "FAIL",
                f"linked to {b.get('billingAccountName')}" if ok else "no active billing account linked")
            return
        except urllib.error.HTTPError:
            continue
    add("billing", "WARN", "cannot read (Cloud Billing API not enabled / no billing.viewer) - "
        "verified implicitly when the bootstrap enables Compute (fails fast without billing)")


def effective_policy(project: str, constraint: str, token: str) -> dict:
    return cp._post(f"{CRM}/{project}:getEffectiveOrgPolicy", {"constraint": f"constraints/{constraint}"}, token)


def list_values(pol: dict) -> tuple[str, list[str], list[str]]:
    lp = pol.get("listPolicy", {})
    return lp.get("allValues", ""), lp.get("allowedValues", []), lp.get("deniedValues", [])


def check_org_policies(project: str, region: str, mtls: bool, token: str) -> None:
    def get(c: str) -> dict | None:
        try:
            return effective_policy(project, c, token)
        except urllib.error.HTTPError as e:
            add(f"org policy {c}", "WARN", f"cannot read effective policy ({e.code})")
            return None

    if (p := get("gcp.resourceLocations")) is not None:
        allv, allowed, denied = list_values(p)
        if allv == "DENY":
            add("org policy gcp.resourceLocations", "FAIL", "all locations denied")
        elif allowed:
            ok = any(region in v or v in ("in:eu-locations", "in:europe-locations") for v in allowed)
            add("org policy gcp.resourceLocations", "PASS" if ok else "FAIL",
                f"allowed={allowed}" + ("" if ok else f" - {region} not allowed"))
        elif any(region in v for v in denied):
            add("org policy gcp.resourceLocations", "FAIL", f"{region} denied ({denied})")
        else:
            add("org policy gcp.resourceLocations", "PASS", "no restriction affecting " + region)

    if mtls and (p := get("compute.restrictLoadBalancerCreationForTypes")) is not None:
        allv, allowed, denied = list_values(p)
        need = "INTERNAL_MANAGED_HTTP_HTTPS"
        blocked = allv == "DENY" or need in denied or any(d in ("in:INTERNAL", "in:MANAGED") for d in denied) \
            or (allowed and not any(need in a or a in ("in:INTERNAL", "in:MANAGED") for a in allowed))
        add("org policy compute.restrictLoadBalancerCreationForTypes", "FAIL" if blocked else "PASS",
            f"{need} {'blocked' if blocked else 'allowed'} (needed for the mTLS internal ALB)")

    if (p := get("gcp.restrictNonCmekServices")) is not None:
        _, _, denied = list_values(p)
        add("org policy gcp.restrictNonCmekServices", "WARN" if denied else "PASS",
            f"CMEK required for {denied} - installer uses CMEK (enable_cmek=true); verify any non-CMEK-capable "
            "service is not listed" if denied else "no restriction")

    if (p := get("gcp.restrictServiceUsage")) is not None:
        allv, allowed, denied = list_values(p)
        bad = [s for s in REQUIRED_SERVICES if f"{s}.googleapis.com" in denied
               or (allowed and f"{s}.googleapis.com" not in allowed)] if allv != "ALLOW" else []
        add("org policy gcp.restrictServiceUsage", "FAIL" if bad or allv == "DENY" else "PASS",
            f"blocked services: {bad}" if bad else "required services allowed")

    if (p := get("run.allowedIngress")) is not None:
        allv, allowed, denied = list_values(p)
        ok = allv != "DENY" and "internal" not in denied and (not allowed or "internal" in allowed)
        add("org policy run.allowedIngress", "PASS" if ok else "FAIL",
            "internal ingress allowed" if ok else f"internal ingress blocked (allowed={allowed})")

    if (p := get("iam.allowedPolicyMemberDomains")) is not None:
        allv, allowed, _ = list_values(p)
        add("org policy iam.allowedPolicyMemberDomains", "WARN" if allowed else "PASS",
            f"restricted to {allowed} - operator principals must belong to these customers" if allowed
            else "no restriction")

    info = {"compute.requireOsLogin": "POC uses OS Login (compatible either way)",
            "compute.vmExternalIpAccess": "POC uses no external IPs (compatible either way)",
            "iam.disableServiceAccountKeyCreation": "POC creates no SA keys (compatible either way)"}
    for c, why in info.items():
        if (p := get(c)) is not None:
            state = p.get("booleanPolicy", {}).get("enforced", list_values(p)[0] or "restricted")
            add(f"org policy {c}", "PASS", f"{state} - {why}")


def check_region(region: str, zone: str) -> None:
    eu = region.startswith("europe-") and region not in ("europe-west2", "europe-west6")  # London, Zurich: non-EU
    add("region", "PASS" if eu else "WARN",
        f"{region} (EU)" if eu else f"{region} is not an EU region - BIO/EU data-residency requirement")
    add("zone", "PASS" if zone.startswith(region + "-") else "FAIL", f"{zone} in {region}")


def check_quota(project: str, region: str, token: str) -> None:
    try:
        r = get_json(f"https://compute.googleapis.com/compute/v1/projects/{project}/regions/{region}", token)
    except urllib.error.HTTPError as e:
        add("quota CPUS", "INFO", "Compute API not enabled yet - checked after bootstrap" if e.code == 403
            else f"cannot read ({e.code})")
        return
    for q in r.get("quotas", []):
        if q["metric"] == "CPUS":
            free = q["limit"] - q["usage"]
            add("quota CPUS", "PASS" if free >= MIN_CPUS else "FAIL", f"{free:.0f} free in {region} (need {MIN_CPUS})")


# ----------------------------------------------------------------------------- report
def write_report(path: pathlib.Path, args: argparse.Namespace, account: str) -> None:
    icon = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌", "INFO": "ℹ️"}
    lines = [f"# AGY POC preflight report", "",
             f"- Date: {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC}",
             f"- Project: `{args.project}`  Region: `{args.region}`  Zone: `{args.zone}`",
             f"- Installer identity: `{account}`", "",
             "| Status | Check | Detail |", "|---|---|---|"]
    lines += [f"| {icon[r.status]} {r.status} | {r.check} | {r.detail.replace('|', '/')} |" for r in RESULTS]
    fails = sum(r.status == "FAIL" for r in RESULTS)
    lines += ["", f"**Result: {'BLOCKED - fix the ❌ items' if fails else 'READY'}** "
              f"({fails} blocking, {sum(r.status == 'WARN' for r in RESULTS)} warnings)", ""]
    path.write_text("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", required=True)
    ap.add_argument("--region", default="europe-west4")
    ap.add_argument("--zone", default="europe-west4-a")
    ap.add_argument("--mtls", action="store_true", help="mTLS front door enabled (checks LB org policy)")
    ap.add_argument("--inference-project", default="", help="separate project for model-call billing/quota")
    ap.add_argument("--seat-project", default="", help="seat client mode: Gemini Enterprise licence project")
    ap.add_argument("--seat-location", default="eu")
    ap.add_argument("--seat-vpc-sc", action="store_true", help="seat perimeter requested (checks org ACM rights)")
    ap.add_argument("--org-id", default="")
    ap.add_argument("--no-evidence", action="store_true",
                    help="prompt logging none/hash: skip the deny-policy permissions and the evidence guard check")
    ap.add_argument("--report", default=str(pathlib.Path(__file__).resolve().parent.parent / "preflight-report.md"))
    args = ap.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", args.project):
        add("project id", "FAIL", f"'{args.project}' is not a valid project ID")
        return 1

    def guarded(name: str, fn, *a):  # one broken check never hides the others or the report
        try:
            return fn(*a)
        except Exception as e:  # noqa: BLE001
            add(name, "FAIL", f"check crashed: {e!r} - please report")
            return None

    token, account = "", ""
    try:
        guarded("tools", check_tools)
        token, account = guarded("auth", check_auth) or ("", "")
        if token and guarded("project", check_project, args.project, token):
            guarded("permissions", check_permissions, args.project, token, account, args.no_evidence)
            guarded("billing", check_billing, args.project, token)
            guarded("org policies", check_org_policies, args.project, args.region, args.mtls, token)
            guarded("quota", check_quota, args.project, args.region, token)
            if args.no_evidence:
                add("preserved evidence guard", "INFO", "prompt logging none/hash: no evidence store - not applicable")
            else:
                guarded("preserved evidence guard", check_stale_guard, args.project, token)
            if args.inference_project and args.inference_project != args.project:
                guarded("inference project", check_inference_project, args.inference_project, token)
            if args.seat_project:
                guarded("seat mode", check_seat, args.project, args.seat_project, args.seat_location, args.seat_vpc_sc,
                        args.org_id, token)
        guarded("region", check_region, args.region, args.zone)
    finally:
        write_report(pathlib.Path(args.report), args, account)
    fails = [r for r in RESULTS if r.status == "FAIL"]
    print(f"\nreport: {args.report}  ->  {'BLOCKED (' + str(len(fails)) + ' blocking)' if fails else 'READY'}")
    return 1 if fails else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001 - report, never traceback at the user
        print(f"preflight internal error: {e!r}", file=sys.stderr)
        sys.exit(2)
