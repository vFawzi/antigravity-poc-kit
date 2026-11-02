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

"""Seat sign-in window: Google ranges minus Google Cloud customer ranges (scripts/google_ranges.py), offline."""
from __future__ import annotations

import importlib.util
import ipaddress
import pathlib

SRC = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "google_ranges.py"
spec = importlib.util.spec_from_file_location("google_ranges", SRC)
gr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gr)  # type: ignore[union-attr]
N = ipaddress.ip_network


def covered(nets: list, ip: str) -> bool:
    return any(ipaddress.ip_address(ip) in n for n in nets)


def test_cloud_customer_ranges_are_removed() -> None:
    out = gr.subtract([N("34.0.0.0/15"), N("142.250.0.0/15")], [N("34.1.0.0/16")])
    assert covered(out, "34.0.1.1") and not covered(out, "34.1.2.3") and covered(out, "142.250.153.100")


def test_google_prefix_fully_inside_cloud_is_dropped() -> None:
    assert gr.subtract([N("35.204.0.0/16")], [N("35.192.0.0/12")]) == []


def test_unrelated_cloud_ranges_change_nothing() -> None:
    assert gr.subtract([N("172.217.0.0/16")], [N("34.64.0.0/10")]) == [N("172.217.0.0/16")]
