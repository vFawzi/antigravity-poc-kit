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
"""Add (or check) Apache-2.0 licence headers on source files.

  license_headers.py [--check] [ROOT]      default ROOT = repository root

Covers *.py, *.sh, *.tf and Dockerfile. Idempotent: files that already carry
"Licensed under the Apache License" or an SPDX identifier are left alone.
A shebang line (and a following coding line) stays first.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

HOLDER = "Google LLC"
YEAR = "2026"
HEADER = f"""# Copyright {YEAR} {HOLDER}
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
"""
SUFFIXES = {".py", ".sh", ".tf"}
NAMES = {"Dockerfile"}
SKIP_DIRS = {".git", ".terraform", "release", "__pycache__", "node_modules", ".venv"}
MARKERS = ("Licensed under the Apache License", "SPDX-License-Identifier")


def candidates(root: pathlib.Path) -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        if p.suffix in SUFFIXES or p.name in NAMES:
            out.append(p)
    return out


def has_header(text: str) -> bool:
    return any(m in text[:2000] for m in MARKERS)


def add_header(text: str) -> str:
    lines = text.splitlines(keepends=True)
    head: list[str] = []
    if lines and lines[0].startswith("#!"):
        head.append(lines.pop(0))
        if lines and "coding" in lines[0] and lines[0].startswith("#"):
            head.append(lines.pop(0))
    return "".join(head) + HEADER + ("\n" if lines and lines[0].strip() else "") + "".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if any file lacks a header (CI)")
    ap.add_argument("root", nargs="?", default=str(pathlib.Path(__file__).resolve().parent.parent))
    a = ap.parse_args()
    root = pathlib.Path(a.root).resolve()
    missing: list[pathlib.Path] = []
    for p in candidates(root):
        text = p.read_text(encoding="utf-8")
        if has_header(text):
            continue
        missing.append(p)
        if not a.check:
            p.write_text(add_header(text), encoding="utf-8")
    verb = "missing a licence header" if a.check else "header added"
    for p in missing:
        print(f"{verb}: {p.relative_to(root)}")
    if a.check and missing:
        return 1
    print(f"ok: {len(candidates(root)) - (len(missing) if a.check else 0)} file(s) carry a licence header")
    return 0


if __name__ == "__main__":
    sys.exit(main())
