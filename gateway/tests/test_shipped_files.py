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

"""Every helper the installer and the POC scripts call must exist in this tree (also in the published trees)."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CALLERS = ["install.sh", "poc/poc-gateway.sh", "install/grant-installer.sh", "install/revoke-installer.sh"]
REF = re.compile(r"(?:\$ROOT|\$\(dirname \"\$0\"\)|\"\$\(dirname \"\$0\"\)\")/((?:install|poc|scripts)/[A-Za-z0-9_.-]+\.(?:py|sh))")


def test_every_called_helper_exists() -> None:
    missing: list[str] = []
    for caller in CALLERS:
        f = ROOT / caller
        if not f.is_file():
            continue
        for rel in sorted(set(REF.findall(f.read_text()))):
            if not (ROOT / rel).is_file():
                missing.append(f"{caller} -> {rel}")
    assert not missing, "helpers referenced but not shipped: " + ", ".join(missing)


def test_reference_pattern_finds_the_known_helpers() -> None:
    refs = set(REF.findall((ROOT / "install.sh").read_text()))
    assert {"install/preflight.py", "install/state-bootstrap.sh", "install/adopt_leftovers.py"} <= refs


def test_poc_outputs_are_git_ignored() -> None:
    gi = ROOT / ".gitignore"
    if not (ROOT / "poc" / "poc-gateway.sh").is_file() or not gi.is_file():
        return   # trees without the POC kit or without a .gitignore (the source tree uses its own)
    text = gi.read_text()
    if "poc-kit/" not in text:   # only the published POC repository carries the POC block
        return
    for entry in ("poc/.state/", "poc-kit/", "poc/devices.csv", "terraform/poc.auto.tfvars", "*.key"):
        assert entry in text, entry
