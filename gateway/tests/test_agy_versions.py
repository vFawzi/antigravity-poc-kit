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
"""AGY version support matrix: schema, deployment-policy resolution, docs table."""
from __future__ import annotations

import copy
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("agy_versions", ROOT / "scripts" / "agy_versions.py")
av = importlib.util.module_from_spec(spec)
spec.loader.exec_module(av)  # type: ignore[union-attr]
M = av.load()


def test_matrix_valid() -> None:
    assert av.errors(M) == []


def test_package_version_format() -> None:
    assert av.VER.match(M["package"])


def test_latest_tested_picks_highest_supported() -> None:
    assert av.resolve(M, "cli", "windows_amd64", "latest-tested")["version"] == "1.4.11"
    assert av.resolve(M, "desktop", "windows_x64", "latest-tested")["version"] == "2.24.0"   # 2.28.1 is a candidate
    assert av.resolve(M, "cli", "linux_amd64", "latest-tested")["version"] == "1.4.11"      # qualified 2026-10-30


def test_pinned_and_blocked() -> None:
    m = copy.deepcopy(M)
    assert av.resolve(m, "cli", "windows_amd64", "pinned:1.4.11")["version"] == "1.4.11"
    assert av.resolve(m, "cli", "windows_amd64", "pinned:1.4.10") is None        # no URL recorded -> not deployable
    assert av.resolve(m, "cli", "windows_amd64", "pinned:9.9.9") is None
    m["releases"][0]["status"] = "blocked"
    assert av.resolve(m, "cli", "windows_amd64", "pinned:1.4.11") is None
    assert not av.allowed(m, "cli", "windows_amd64", "1.4.11")
    assert av.allowed(m, "cli", "windows_amd64", "1.5.0")                       # newer untested: allowed (WARN)
    assert not av.allowed(m, "cli", "windows_amd64", "1.4.9")                   # below minimum


def test_schema_rejects_bad_entries() -> None:
    m = copy.deepcopy(M)
    m["releases"].append({"component": "cli", "version": "2.0.0", "platform": "windows_amd64", "status": "supported",
                          "url": "https://evil.example/agy.exe", "sha512": "00", "tested": "", "evidence": ""})
    errs = " ".join(av.errors(m))
    assert "sha512 missing or malformed" in errs and "url must start with" in errs and "supported needs" in errs


def test_table_marks_recommended() -> None:
    t = av.table(M)
    assert "| cli | windows_amd64 | 1.4.11 (recommended) | supported |" in t
    assert "| desktop | windows_x64 | 2.28.1 | candidate |" in t
