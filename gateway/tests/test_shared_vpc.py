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

"""Shared VPC mode (network_mode = shared): Terraform wiring, module registration, preflight checks
(subnet use, proxy-only subnet, org policies) and the run.managed.requireInvokerIam check (all modes)."""
from __future__ import annotations

import io
import re
import sys
import urllib.error
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "terraform"
sys.path.insert(0, str(ROOT / "install"))
sys.path.insert(0, str(ROOT / "poc"))

import poc_kit  # noqa: E402
import preflight  # noqa: E402

MAIN = (TF / "main.tf").read_text()
VARS = (TF / "variables.tf").read_text()
OUTS = (TF / "outputs.tf").read_text()
MTLS = (TF / "modules" / "mtls" / "main.tf").read_text()
NEW_VARS = ("network_mode", "shared_vpc_host_project", "shared_vpc_network", "shared_vpc_subnet",
            "gateway_ilb_ip", "ilb_global_access")


def var_block(name: str) -> str:
    m = re.search(rf'variable "{name}" \{{.*?\n\}}', VARS, re.S)
    assert m, name
    return m.group(0)


# ----------------------------------------------------------------------------- Terraform: defaults unchanged
def test_default_is_create_mode_and_global_access_off() -> None:
    assert 'default     = "create"' in var_block("network_mode")
    assert 'contains(["create", "shared"], var.network_mode)' in var_block("network_mode")
    assert "default     = false" in var_block("ilb_global_access")
    for v in ("shared_vpc_host_project", "shared_vpc_network", "shared_vpc_subnet", "gateway_ilb_ip"):
        assert 'default     = ""' in var_block(v), v


def test_create_mode_keeps_own_network_and_state_addresses() -> None:
    assert re.search(r'module "network" \{\n  count\s+= local\.shared_vpc \? 0 : 1', MAIN)
    assert 'shared_vpc = var.network_mode == "shared"' in MAIN
    # existing installs: state moves instead of destroy/create
    assert re.search(r"moved \{\n  from = module\.network\n  to   = module\.network\[0\]\n\}", MAIN)
    for res in ("google_compute_subnetwork.proxy_only", "google_dns_managed_zone.internal", "google_dns_record_set.gw"):
        assert re.search(rf"moved \{{\n  from = {re.escape(res)}\n  to   = {re.escape(res)}\[0\]\n\}}", MTLS), res
    # proxy-only subnet and DNS zone stay on by default
    assert re.search(r'variable "create_proxy_subnet" \{[^}]*default\s+= true', MTLS)
    assert re.search(r'variable "create_dns_zone" \{[^}]*default\s+= true', MTLS)


def test_no_direct_network_module_references_left() -> None:
    for path in [*TF.glob("*.tf")]:
        refs = re.findall(r"module\.network\.[a-z_]+", path.read_text())
        assert not refs, f"{path.name}: {refs} (use local.network_id / local.subnet_id)"
    assert "local.network_id" in MAIN and "local.subnet_id" in MAIN
    assert "one(module.network[*].network_id)" in MAIN and "one(data.google_compute_subnetwork.shared[*].network)" in MAIN


# ----------------------------------------------------------------------------- Terraform: shared mode wiring
def test_shared_mode_uses_host_subnet_read_only() -> None:
    m = re.search(r'data "google_compute_subnetwork" "shared" \{.*?\n\}\n', MAIN, re.S)
    assert m
    ds = m.group(0)
    assert "count   = local.shared_vpc ? 1 : 0" in ds
    assert "project = var.shared_vpc_host_project" in ds and "region  = var.region" in ds and "name    = var.shared_vpc_subnet" in ds
    assert "basename(self.network) == var.shared_vpc_network" in ds
    # never manage anything in the host project
    assert not re.search(r'resource "google_compute_(subnetwork|network|shared_vpc\w*)"[^\n]*\n[^}]*shared_vpc_host_project', MAIN)
    assert "google_compute_shared_vpc" not in MAIN + MTLS


def test_mtls_module_wiring_for_both_modes() -> None:
    assert "create_proxy_subnet     = !local.shared_vpc" in MAIN
    assert "create_dns_zone         = !local.shared_vpc" in MAIN
    assert "ilb_ip                  = var.gateway_ilb_ip" in MAIN
    assert "global_access           = var.ilb_global_access" in MAIN
    assert re.search(r'resource "google_compute_subnetwork" "proxy_only" \{\n  count\s+= var\.create_proxy_subnet \? 1 : 0', MTLS)
    assert re.search(r'resource "google_dns_managed_zone" "internal" \{\n  count\s+= var\.create_dns_zone \? 1 : 0', MTLS)
    fr = re.search(r'resource "google_compute_forwarding_rule" "gw" \{.*?\n\}', MTLS, re.S).group(0)  # type: ignore[union-attr]
    assert "allow_global_access   = var.global_access" in fr and "network               = var.network_id" in fr
    addr = re.search(r'resource "google_compute_address" "gw" \{.*?\n\}', MTLS, re.S).group(0)  # type: ignore[union-attr]
    assert 'address      = var.ilb_ip == "" ? null : var.ilb_ip' in addr and "subnetwork   = var.subnet_id" in addr


def test_validation_messages() -> None:
    guard = re.search(r'resource "terraform_data" "network_guard" \{.*?\n\}\n', MAIN, re.S).group(0)  # type: ignore[union-attr]
    assert "needs shared_vpc_host_project, shared_vpc_network and shared_vpc_subnet" in guard
    assert "supports the gateway profile only" in guard
    assert "var.deploy_workstation || var.deploy_windows_workstation || var.enable_windows_image_pipeline" in guard
    assert "not this (service) project" in guard
    assert "enable_mtls = true" in guard
    assert "must be an IPv4 address" in var_block("gateway_ilb_ip")
    assert "not a URL" in var_block("shared_vpc_subnet") and "not a URL" in var_block("shared_vpc_network")


def test_network_output_for_status_and_handoff() -> None:
    m = re.search(r'output "network" \{.*?\n\}\n', OUTS, re.S)
    assert m
    for k in ("mode", "host_project", "network", "subnet", "gateway_ip", "port", "global_access", "private_dns"):
        assert re.search(rf"\b{k}\s+=", m.group(0)), k


def test_new_variables_registered_in_modules() -> None:
    if not (ROOT / "modules").is_dir():   # the trimmed POC kit repository ships no module catalogue
        pytest.skip("no modules/ catalogue in this tree")
    owners: dict[str, list[str]] = {}
    binds: set[str] = set()
    for f in (ROOT / "modules").glob("*/module.yaml"):
        doc = yaml.safe_load(f.read_text())
        for v in doc.get("cloud", {}).get("terraform", {}).get("variables", []) or []:
            owners.setdefault(v, []).append(doc["id"])
        text = f.read_text()
        binds |= set(re.findall(r"tfvar: (\w+)", text))
    for v in NEW_VARS:
        assert len(owners.get(v, [])) == 1, f"{v}: owners {owners.get(v)}"
        assert v in binds, f"{v}: no bind: tfvar entry"
        assert re.search(rf'^variable "{v}"', VARS, re.M), v


# ----------------------------------------------------------------------------- poc_kit: question 7 -> tfvars
def test_poc_tfvars_network_default_renders_nothing() -> None:
    assert poc_kit.render_network(poc_kit.Network()) == []


def test_poc_tfvars_shared_network() -> None:
    lines = poc_kit.render_network(poc_kit.Network("shared", "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "10.70.0.10", True))
    text = "\n".join(lines)
    assert 'network_mode            = "shared"' in text and 'shared_vpc_host_project = "agy-host-01"' in text
    assert 'shared_vpc_subnet       = "lab-agy-euw3"' in text and 'gateway_ilb_ip          = "10.70.0.10"' in text
    assert "ilb_global_access       = true" in text


@pytest.mark.parametrize("net,needle", [
    (poc_kit.Network("shared", "", "n", "s"), "host project"),
    (poc_kit.Network("shared", "agy-host-01", "projects/x/global/networks/n", "s"), "not a URL"),
    (poc_kit.Network("create", gateway_ip="10.0.0.300"), "IPv4"),
    (poc_kit.Network("hybrid"), "create or shared"),
])
def test_poc_tfvars_network_rejects_bad_values(net: poc_kit.Network, needle: str) -> None:
    with pytest.raises(poc_kit.KitError, match=needle):
        poc_kit.render_network(net)


# ----------------------------------------------------------------------------- preflight (mocked HTTP)
def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b"{}"))  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def _reset_results() -> None:
    preflight.RESULTS.clear()
    preflight.NOTES.clear()


def statuses() -> dict[str, str]:
    return {r.check: r.status for r in preflight.RESULTS}


def test_invoker_iam_enforced_fails_with_exception_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "get_json", lambda url, token, up=None: {"spec": {"rules": [{"enforce": True}]}})
    preflight.check_invoker_iam("agy-service-01", "t")
    assert statuses()["org policy run.managed.requireInvokerIam"] == "FAIL"
    note = preflight.NOTES[0]
    assert "name: projects/agy-service-01/policies/run.managed.requireInvokerIam" in note
    assert "- enforce: false" in note and "gcloud org-policies set-policy" in note
    assert "Organization Policy Administrator" in note
    for control in ("internal only", "valid device certificate", "secret header", "device registry", "allUsers"):
        assert control in note, control
    assert "identity tokens" in note


@pytest.mark.parametrize("pol", [{}, {"spec": {"rules": [{"enforce": False}]}},
                                 {"spec": {"rules": [{"enforce": True, "condition": {"expression": "x"}}]}}])
def test_invoker_iam_not_enforced_passes(monkeypatch: pytest.MonkeyPatch, pol: dict[str, Any]) -> None:
    monkeypatch.setattr(preflight, "get_json", lambda url, token, up=None: pol)
    preflight.check_invoker_iam("agy-service-01", "t")
    assert statuses()["org policy run.managed.requireInvokerIam"] == "PASS" and not preflight.NOTES


def test_invoker_iam_unreadable_warns_and_404_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(url: str, token: str, up: str | None = None) -> dict[str, Any]:
        raise http_error(403)
    monkeypatch.setattr(preflight, "get_json", deny)
    preflight.check_invoker_iam("agy-service-01", "t")
    assert statuses()["org policy run.managed.requireInvokerIam"] == "WARN"
    d = next(r.detail for r in preflight.RESULTS if r.check == "org policy run.managed.requireInvokerIam")
    assert "could not read (403; Org Policy API disabled or no permission)" in d
    assert "the gateway deploy will fail" in d and "--effective --project agy-service-01" in d and "fix: see the section" in d
    assert "gcloud org-policies set-policy" in preflight.NOTES[0] and "only needed if it is enforced" in preflight.NOTES[0]
    preflight.RESULTS.clear()
    preflight.NOTES.clear()

    def missing(url: str, token: str, up: str | None = None) -> dict[str, Any]:
        raise http_error(404)
    monkeypatch.setattr(preflight, "get_json", missing)
    preflight.check_invoker_iam("agy-service-01", "t")
    assert statuses()["org policy run.managed.requireInvokerIam"] == "PASS"


def test_invoker_iam_runs_in_every_mode() -> None:
    src = (ROOT / "install" / "preflight.py").read_text()
    main = src[src.index("def main()"):]
    i = main.index("check_invoker_iam")
    assert main.index('if args.network_mode == "shared"') > i   # not inside the shared-only branch


HOST, NET, SUB, REGION, PROJ = "agy-host-01", "lab-shared-vpc", "lab-agy-euw3", "europe-west3", "agy-service-01"
SUB_URL = f"https://www.googleapis.com/compute/v1/projects/{HOST}/global/networks/{NET}"


USABLE_ITEM = {"subnetwork": f"https://www.googleapis.com/compute/v1/projects/{HOST}/regions/{REGION}/subnetworks/{SUB}",
               "network": SUB_URL, "ipCidrRange": "10.70.0.0/24"}


def fake_gcp(*, usable: list[dict[str, Any]] | int | None = None, use: bool | int = True, subnet: dict[str, Any] | int | None = None, proxies: list[dict[str, Any]] | int | None = None,
             xpn: dict[str, Any] | int | None = None, policies: dict[str, dict[str, Any]] | None = None):  # noqa: ANN202
    sub = {"network": SUB_URL, "ipCidrRange": "10.70.0.0/24", "purpose": "PRIVATE"} if subnet is None else subnet
    prox = [{"name": "lab-proxy-euw3", "network": SUB_URL, "role": "ACTIVE", "ipCidrRange": "10.70.255.0/26"}] \
        if proxies is None else proxies
    xp = {"name": HOST} if xpn is None else xpn
    lu = {"items": [USABLE_ITEM]} if usable is None else ({"items": usable} if isinstance(usable, list) else usable)

    def get_json(url: str, token: str, up: str | None = None) -> dict[str, Any]:
        if "/aggregated/subnetworks/listUsable" in url:
            assert f"projects/{HOST}/aggregated/" in url   # asked on the HOST project
        for key, val in (("/aggregated/subnetworks/listUsable", lu), ("getXpnHost", xp), ("subnetworks?filter=", {"items": prox} if isinstance(prox, list) else prox),
                         (f"subnetworks/{SUB}", sub)):
            if key in url:
                if isinstance(val, int):
                    raise http_error(val)
                return val  # type: ignore[return-value]
        raise AssertionError(url)

    def post(url: str, body: dict[str, Any], token: str, attempts: int = 5) -> dict[str, Any]:
        if url.endswith("/testIamPermissions"):
            assert f"projects/{HOST}/regions/{REGION}/subnetworks/{SUB}/" in url
            if isinstance(use, int) and not isinstance(use, bool):
                raise http_error(use)
            return {"permissions": ["compute.subnetworks.use", "compute.subnetworks.get"] if use else ["compute.subnetworks.get"]}
        if url.endswith(":getEffectiveOrgPolicy"):
            c = body["constraint"].removeprefix("constraints/")
            return (policies or {}).get(c, {})
        raise AssertionError(url)
    return get_json, post


def run_shared(monkeypatch: pytest.MonkeyPatch, **kw: Any) -> dict[str, str]:
    g, p = fake_gcp(**kw)
    monkeypatch.setattr(preflight, "get_json", g)
    monkeypatch.setattr(preflight.cp, "_post", p)
    preflight.check_shared_vpc(PROJ, REGION, HOST, NET, SUB, "t")
    return statuses()


def test_shared_vpc_all_good(monkeypatch: pytest.MonkeyPatch) -> None:
    st = run_shared(monkeypatch)
    assert st["shared subnet: installer may use it"] == "PASS"
    assert st["shared subnet: network and region"] == "PASS"
    assert st["shared VPC: proxy-only subnet"] == "PASS"
    assert st["shared VPC: project attached"] == "PASS"
    assert st["org policy compute.restrictSharedVpcHostProjects"] == "PASS"
    assert st["org policy compute.restrictSharedVpcSubnetworks"] == "PASS"
    assert "FAIL" not in st.values()


def use_detail() -> str:
    return next(r.detail for r in preflight.RESULTS if r.check == "shared subnet: installer may use it")


def test_subnet_usable_decided_by_list_usable_even_when_test_iam_is_403(monkeypatch: pytest.MonkeyPatch) -> None:
    # subnet-level Compute Network User: testIamPermissions on the subnet answers 403, listUsable lists the subnet
    st = run_shared(monkeypatch, use=403)
    assert st["shared subnet: installer may use it"] == "PASS" and "listUsable" in use_detail()


def test_subnet_absent_from_list_usable_fails_with_network_team_request(monkeypatch: pytest.MonkeyPatch) -> None:
    other = {**USABLE_ITEM, "subnetwork": USABLE_ITEM["subnetwork"].replace(SUB, "other-subnet")}
    st = run_shared(monkeypatch, usable=[other])
    assert st["shared subnet: installer may use it"] == "FAIL"
    d = use_detail()
    assert "not shared with you / no Compute Network User on it" in d and "roles/compute.networkUser" in d


@pytest.mark.parametrize("use,expected", [(True, "PASS"), (False, "FAIL"), (403, "WARN")])
def test_list_usable_error_falls_back_to_test_iam(monkeypatch: pytest.MonkeyPatch, use: bool | int, expected: str) -> None:
    st = run_shared(monkeypatch, usable=403, use=use)
    assert st["shared subnet: installer may use it"] == expected
    if expected == "WARN":
        assert "cannot confirm (listUsable 403, testIamPermissions 403)" in use_detail()


def test_list_usable_follows_pages(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {"": {"items": [], "nextPageToken": "p2"}, "p2": {"items": [USABLE_ITEM]}}
    seen: list[str] = []

    def get_json(url: str, token: str, up: str | None = None) -> dict[str, Any]:
        seen.append(url)
        tok = url.split("pageToken=")[1] if "pageToken=" in url else ""
        return pages[tok]
    monkeypatch.setattr(preflight, "get_json", get_json)
    assert preflight.usable_subnet_paths(HOST, "t") == {f"projects/{HOST}/regions/{REGION}/subnetworks/{SUB}"}
    assert len(seen) == 2 and all(f"projects/{HOST}/aggregated/subnetworks/listUsable" in u for u in seen)


def test_shared_vpc_wrong_network_or_missing_subnet(monkeypatch: pytest.MonkeyPatch) -> None:
    st = run_shared(monkeypatch, subnet={"network": "projects/x/global/networks/other", "purpose": "PRIVATE"})
    assert st["shared subnet: network and region"] == "FAIL"
    preflight.RESULTS.clear()
    st = run_shared(monkeypatch, subnet=404)
    assert st["shared subnet: network and region"] == "FAIL"
    assert "not found" in next(r.detail for r in preflight.RESULTS if r.check == "shared subnet: network and region")


def test_proxy_only_subnet_unlistable_is_a_warning_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    st = run_shared(monkeypatch, proxies=403)
    assert st["shared VPC: proxy-only subnet"] == "WARN"
    d = next(r.detail for r in preflight.RESULTS if r.check == "shared VPC: proxy-only subnet")
    assert "network team" in d and "REGIONAL_MANAGED_PROXY" in d and "ACTIVE" in d


@pytest.mark.parametrize("proxies", [[], [{"name": "p", "network": SUB_URL, "role": "BACKUP"}],
                                     [{"name": "p", "network": "projects/h/global/networks/other", "role": "ACTIVE"}]])
def test_proxy_only_subnet_missing_fails(monkeypatch: pytest.MonkeyPatch, proxies: list[dict[str, Any]]) -> None:
    assert run_shared(monkeypatch, proxies=proxies)["shared VPC: proxy-only subnet"] == "FAIL"


def test_project_not_attached_fails_and_unreadable_is_info(monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_shared(monkeypatch, xpn={})["shared VPC: project attached"] == "FAIL"
    preflight.RESULTS.clear()
    assert run_shared(monkeypatch, xpn=403)["shared VPC: project attached"] == "INFO"


@pytest.mark.parametrize("pol,expected", [
    ({"listPolicy": {"allValues": "DENY"}}, "FAIL"),
    ({"listPolicy": {"deniedValues": [f"projects/{HOST}"]}}, "FAIL"),
    ({"listPolicy": {"allowedValues": [f"under:projects/{HOST}"]}}, "PASS"),
    ({"listPolicy": {"allowedValues": ["under:folders/123"]}}, "WARN"),
    ({}, "PASS"),
])
def test_shared_vpc_org_policies(monkeypatch: pytest.MonkeyPatch, pol: dict[str, Any], expected: str) -> None:
    st = run_shared(monkeypatch, policies={"compute.restrictSharedVpcHostProjects": pol,
                                           "compute.restrictSharedVpcSubnetworks": pol})
    assert st["org policy compute.restrictSharedVpcHostProjects"] == expected
    assert st["org policy compute.restrictSharedVpcSubnetworks"] == expected


def test_subnet_policy_accepts_the_exact_subnet_path(monkeypatch: pytest.MonkeyPatch) -> None:
    pol = {"listPolicy": {"allowedValues": [f"projects/{HOST}/regions/{REGION}/subnetworks/{SUB}"]}}
    st = run_shared(monkeypatch, policies={"compute.restrictSharedVpcSubnetworks": pol})
    assert st["org policy compute.restrictSharedVpcSubnetworks"] == "PASS"


def test_shared_vpc_settings_incomplete_or_self_host(monkeypatch: pytest.MonkeyPatch) -> None:
    preflight.check_shared_vpc(PROJ, REGION, "", NET, SUB, "t")
    assert statuses()["shared VPC settings"] == "FAIL"
    preflight.RESULTS.clear()
    preflight.check_shared_vpc(PROJ, REGION, PROJ, NET, SUB, "t")
    assert statuses()["shared VPC settings"] == "FAIL"


def test_report_carries_the_invoker_guidance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(preflight, "get_json", lambda url, token, up=None: {"spec": {"rules": [{"enforce": True}]}})
    preflight.check_invoker_iam(PROJ, "t")
    rep = tmp_path / "r.md"

    class A:
        project, region, zone = PROJ, REGION, f"{REGION}-a"
    preflight.write_report(rep, A(), "installer@example.com")  # type: ignore[arg-type]
    text = rep.read_text()
    assert "BLOCKED" in text and "gcloud org-policies set-policy" in text


# ----------------------------------------------------------------------------- installer wiring
def test_installer_passes_shared_args_and_skips_own_vpc_checks() -> None:
    sh = (ROOT / "install.sh").read_text()
    assert '"$(tfvar_value network_mode)" == "shared"' in sh
    for flag in ("--network-mode shared", "--shared-vpc-host-project", "--shared-vpc-network", "--shared-vpc-subnet"):
        assert flag in sh, flag
    assert 'res("SKIP", "V96"' in sh and "network_mode = shared" in sh


def test_tfvar_value_reads_auto_tfvars_last(tmp_path: Path) -> None:
    import subprocess
    sh = (ROOT / "install.sh").read_text()
    fn = re.search(r"^tfvar_value\(\) \{.*?^\}", sh, re.S | re.M).group(0)  # type: ignore[union-attr]
    (tmp_path / "terraform.tfvars").write_text('network_mode = "create"\n')
    (tmp_path / "poc.auto.tfvars").write_text('network_mode            = "shared"\nshared_vpc_subnet       = "lab-agy-euw3"\n'
                                              'ilb_global_access       = true\n')
    out = subprocess.run(["bash", "-c", f'{fn}\nTF_DIR="$1"; echo "$(tfvar_value network_mode)|$(tfvar_value shared_vpc_subnet)|'
                          f'$(tfvar_value ilb_global_access)|$(tfvar_value nope)"', "x", str(tmp_path)],
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out == "shared|lab-agy-euw3|true|"
