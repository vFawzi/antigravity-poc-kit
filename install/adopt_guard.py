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

"""Re-point preserved evidence deny policies at the current gateway service account.

After `--destroy` with preserved evidence, the old evidence deny policy stays in place (it still protects the
old evidence). Its exceptions reference the deleted gateway service account (`deleted:...?uid=`), and its
unconditional `dlp.googleapis.com/kms.encrypt` rule then blocks the re-created gateway project-wide, so prompt
evidence fails with HTTP 403. This tool replaces those deleted gateway principals with the live one. Nothing
else changes: denied principals, permissions, conditions and the other exceptions are kept as they are.

  adopt_guard.py --project P --gateway-sa SA_EMAIL [--apply]     (dry run without --apply)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

IAM = "https://iam.googleapis.com/v2"
SA_PREFIX = "principal://iam.googleapis.com/projects/-/serviceAccounts/"


def token() -> str:
    return subprocess.run(["gcloud", "auth", "print-access-token"], capture_output=True, text=True,
                          check=True).stdout.strip()


def call(method: str, url: str, tok: str, body: dict | None = None, attempts: int = 5) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    for i in range(attempts):
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
        if not url.startswith("https://"):
            raise ValueError(f"refusing non-https URL: {url}")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:  # nosec B310 - https enforced above
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and i < attempts - 1:
                time.sleep(2 ** i)
                continue
            raise RuntimeError(f"{method} {url}: HTTP {e.code} {e.read()[:300]!r}") from e
    raise RuntimeError("unreachable")


def stale_guards(project: str, gateway_sa: str, tok: str) -> list[tuple[dict, int]]:
    """Deny policies whose exceptions list a deleted copy of gateway_sa: (policy, number of stale entries)."""
    parent = urllib.parse.quote(f"cloudresourcemanager.googleapis.com/projects/{project}", safe="")
    stale_prefix = f"deleted:{SA_PREFIX}{gateway_sa}?uid="
    out: list[tuple[dict, int]] = []
    for ref in call("GET", f"{IAM}/policies/{parent}/denypolicies", tok).get("policies", []):
        pol = call("GET", f"{IAM}/{ref['name']}", tok)
        n = sum(1 for r in pol.get("rules", []) for p in r.get("denyRule", {}).get("exceptionPrincipals", [])
                if p.startswith(stale_prefix))
        if n:
            out.append((pol, n))
    return out


def adopt(pol: dict, gateway_sa: str) -> dict:
    live = f"{SA_PREFIX}{gateway_sa}"
    stale_prefix = f"deleted:{live}?uid="
    for r in pol.get("rules", []):
        d = r.get("denyRule", {})
        exc = [live if p.startswith(stale_prefix) else p for p in d.get("exceptionPrincipals", [])]
        d["exceptionPrincipals"] = list(dict.fromkeys(exc))  # de-dup, keep order
    return pol


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--project", required=True)
    ap.add_argument("--gateway-sa", required=True)
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    tok = token()
    found = stale_guards(a.project, a.gateway_sa, tok)
    if not found:
        print("no deny policy references a deleted gateway service account - nothing to do")
        return 0
    for pol, n in found:
        name = pol["name"].rsplit("/", 1)[-1]
        if not a.apply:
            print(f"[dry-run] {name}: {n} stale gateway exception(s) would be re-pointed to {a.gateway_sa}")
            continue
        body = adopt(pol, a.gateway_sa)
        call("PUT", f"{IAM}/{pol['name']}", tok, {k: body[k] for k in ("name", "etag", "rules", "displayName")
                                                    if k in body})
        print(f"[applied] {name}: {n} stale gateway exception(s) re-pointed to {a.gateway_sa}")
    if not a.apply:
        print("re-run with --apply to update (deny-policy changes are recorded in Cloud Audit Logs)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"adopt_guard: {e}", file=sys.stderr)
        sys.exit(2)
