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

"""Print Google-owned IPv4 ranges minus Google Cloud customer ranges, comma-separated (seat sign-in window)."""
from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import time

GOOG = "https://www.gstatic.com/ipranges/goog.json"
CLOUD = "https://www.gstatic.com/ipranges/cloud.json"


def fetch(url: str, attempts: int = 4) -> list[ipaddress.IPv4Network]:
    for i in range(attempts):
        try:
            # curl uses the OS trust store (python.org builds on macOS ship without CA certificates)
            raw = subprocess.run(["curl", "-fsS", "--max-time", "20", url], capture_output=True, check=True).stdout  # noqa: S603,S607
            data = json.loads(raw)
            return [ipaddress.ip_network(p["ipv4Prefix"]) for p in data.get("prefixes", []) if "ipv4Prefix" in p]
        except (OSError, ValueError, subprocess.CalledProcessError):
            if i == attempts - 1:
                raise
            time.sleep(2 ** i)
    return []


def subtract(goog: list[ipaddress.IPv4Network], cloud: list[ipaddress.IPv4Network]) -> list[ipaddress.IPv4Network]:
    out = list(goog)
    for c in cloud:
        nxt: list[ipaddress.IPv4Network] = []
        for g in out:
            if c.subnet_of(g):
                nxt.extend(g.address_exclude(c))
            elif not g.subnet_of(c):
                nxt.append(g)
        out = nxt
    return list(ipaddress.collapse_addresses(out))


def main() -> int:
    nets = subtract(fetch(GOOG), fetch(CLOUD))
    if not nets:
        return 1
    print(",".join(str(n) for n in nets))
    return 0


if __name__ == "__main__":
    sys.exit(main())
