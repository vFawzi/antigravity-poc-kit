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
"""AGY version support matrix (compat/agy-versions.json): validate, resolve a deployment policy, render the docs table.

  python3 scripts/agy_versions.py check
  python3 scripts/agy_versions.py resolve cli windows_amd64 latest-tested     # -> JSON of the release to deploy
  python3 scripts/agy_versions.py table                                       # -> markdown for the docs
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

MATRIX = pathlib.Path(__file__).resolve().parents[1] / "compat" / "agy-versions.json"
STATUSES = ("supported", "deprecated", "candidate", "blocked")
PLATFORMS = {"cli": ("windows_amd64", "linux_amd64"), "desktop": ("windows_x64",)}
URL_PREFIX = "https://storage.googleapis.com/antigravity-public/"
VER = re.compile(r"^\d+\.\d+\.\d+$")


def vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def load(path: pathlib.Path = MATRIX) -> dict[str, Any]:
    return json.loads(path.read_text())


def errors(m: dict[str, Any]) -> list[str]:
    """Schema and consistency problems (empty list = valid)."""
    out: list[str] = []
    if m.get("schema") != 1:
        out.append("schema must be 1")
    if not VER.match(str(m.get("package", ""))):
        out.append("package must be x.y.z")
    seen: set[tuple[str, str, str]] = set()
    for i, r in enumerate(m.get("releases", [])):
        where = f"releases[{i}] {r.get('component')} {r.get('version')} {r.get('platform')}"
        comp, plat, ver, st = r.get("component"), r.get("platform"), str(r.get("version", "")), r.get("status")
        if comp not in PLATFORMS or plat not in PLATFORMS.get(comp, ()):
            out.append(f"{where}: unknown component/platform")
            continue
        if not VER.match(ver):
            out.append(f"{where}: version must be x.y.z")
        if st not in STATUSES:
            out.append(f"{where}: status must be one of {STATUSES}")
        if (comp, plat, ver) in seen:
            out.append(f"{where}: duplicate")
        seen.add((comp, plat, ver))
        digest, n = ("sha512", 128) if comp == "cli" else ("sha256", 64)
        if not re.fullmatch(rf"[a-f0-9]{{{n}}}", str(r.get(digest, ""))):
            out.append(f"{where}: {digest} missing or malformed")
        url = str(r.get("url", ""))
        if url and not url.startswith(URL_PREFIX):
            out.append(f"{where}: url must start with {URL_PREFIX}")
        if st == "supported" and not (url and r.get("tested") and r.get("evidence")):
            out.append(f"{where}: supported needs url, tested date and evidence")
    for comp, plats in m.get("minimum", {}).items():
        for plat, ver in plats.items():
            if plat not in PLATFORMS.get(comp, ()) or not VER.match(str(ver)):
                out.append(f"minimum {comp} {plat}: invalid")
    return out


def resolve(m: dict[str, Any], component: str, platform: str, policy: str) -> dict[str, Any] | None:
    """Release to deploy for a policy: latest-tested (highest supported), pinned:<x.y.z> (in the matrix, not blocked,
    >= minimum). None = no deployable release (keep what is installed; V84 reports it). 'latest' (manifest) is resolved
    by the endpoint, which then checks the version with allowed()."""
    rel = [r for r in m["releases"] if r["component"] == component and r["platform"] == platform]
    if policy == "latest-tested":
        ok = [r for r in rel if r["status"] == "supported" and r.get("url")]
        return max(ok, key=lambda r: vkey(r["version"])) if ok else None
    if policy.startswith("pinned:"):
        want = policy.split(":", 1)[1]
        hit = [r for r in rel if r["version"] == want and r.get("url")]
        return hit[0] if hit and allowed(m, component, platform, want) else None
    raise ValueError(f"unknown policy {policy}")


def allowed(m: dict[str, Any], component: str, platform: str, version: str) -> bool:
    """A version may run: not blocked and not below the minimum (untested newer versions are allowed with a warning)."""
    if not VER.match(version):
        return False
    minimum = m.get("minimum", {}).get(component, {}).get(platform)
    if minimum and vkey(version) < vkey(minimum):
        return False
    return not any(r["component"] == component and r["platform"] == platform and r["version"] == version
                   and r["status"] == "blocked" for r in m["releases"])


def table(m: dict[str, Any]) -> str:
    lines = [f"Supported AGY versions for package {m['package']} (generated from compat/agy-versions.json).", "",
             "| Component | Platform | Version | Status | Tested | Notes |", "|---|---|---|---|---|---|"]
    rows = sorted(m["releases"], key=lambda r: (r["component"], r["platform"], [-x for x in vkey(r["version"])]))
    for r in rows:
        rec = resolve(m, r["component"], r["platform"], "latest-tested")
        mark = " (recommended)" if rec is r else ""
        lines.append(f"| {r['component']} | {r['platform']} | {r['version']}{mark} | {r['status']} | "
                     f"{r.get('tested') or '-'} | {r.get('notes') or ''} |")
    mins = "; ".join(f"{c} {p} {v}" for c, ps in m.get("minimum", {}).items() for p, v in ps.items())
    lines += ["", f"Minimum versions: {mins}."]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    m = load()
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "check":
        errs = errors(m)
        print("\n".join(errs) if errs else f"agy-versions: OK - {len(m['releases'])} releases, package {m['package']}")
        return 1 if errs else 0
    if cmd == "resolve" and len(argv) == 5:
        r = resolve(m, argv[2], argv[3], argv[4])
        print(json.dumps(r or {}))
        return 0 if r else 2
    if cmd == "table":
        sys.stdout.write(table(m))
        return 0
    print(__doc__)
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))
