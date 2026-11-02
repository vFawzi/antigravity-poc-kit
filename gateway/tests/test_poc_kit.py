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

"""Unit tests for the POC kit helper (poc/poc_kit.py): devices.csv validation, generated tfvars, kit layout."""
from __future__ import annotations

import json
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc"))

import poc_kit  # noqa: E402

HEADER = "device,owner,persona,os\n"


def write_csv(tmp_path: Path, body: str, header: str = HEADER) -> Path:
    p = tmp_path / "devices.csv"
    p.write_text(header + body)
    return p


def test_example_csv_is_valid() -> None:
    devs = poc_kit.read_devices(ROOT / "poc" / "devices.csv.example")
    assert len(devs) == 5 and {d.os for d in devs} == {"windows", "macos"}
    assert {d.group for d in devs} == {"agy-dev", "agy-contractor"}


@pytest.mark.parametrize("body,needle", [
    ("Bad Name,a@example.com,dev,windows\n", "must be lowercase letters, digits"),
    ("win-01,not-an-email,dev,windows\n", "not an e-mail"),
    ("win-01,a@example.com,admin,windows\n", "persona 'admin'"),
    ("win-01,a@example.com,dev,android\n", "os 'android'"),
    ("win-01,a@example.com,dev,windows\nwin-01,b@example.com,dev,windows\n", "duplicate"),
    ("win-01,a@example.com,dev\n", "expected 4 columns"),
])
def test_invalid_rows_rejected(tmp_path: Path, body: str, needle: str) -> None:
    with pytest.raises(poc_kit.KitError, match=needle):
        poc_kit.read_devices(write_csv(tmp_path, body))


def test_header_and_case_normalised(tmp_path: Path) -> None:
    with pytest.raises(poc_kit.KitError, match="header"):
        poc_kit.read_devices(write_csv(tmp_path, "x,a@example.com,dev,windows\n", header="name,owner,persona,os\n"))
    d = poc_kit.read_devices(write_csv(tmp_path, "# comment\nWIN-01 , a@example.com , Contractor , MacOS\n"))[0]
    assert (d.device, d.persona, d.os, d.group) == ("win-01", "contractor", "macos", "agy-contractor")


def test_tfvars_registry_labels_and_budgets(tmp_path: Path) -> None:
    devs = poc_kit.read_devices(write_csv(tmp_path, "win-01,a@example.com,dev,windows\nmac-02,b@example.com,contractor,macos\n"))
    out = poc_kit.render_tfvars(devs, "010631-059865-B279E4", {"dev": 2000, "contractor": 1000})
    assert "billing_labels  = true" in out and 'billing_account = "010631-059865-B279E4"' in out
    assert '"win-01" = { user = "a@example.com", group = "agy-dev" }' in out
    assert '"mac-02" = { user = "b@example.com", group = "agy-contractor" }' in out
    assert '"dev" = { amount = 2000, thresholds = [0.5, 0.9, 1.0] }' in out
    assert '"contractor" = { amount = 1000, thresholds = [0.5, 0.9, 1.0] }' in out


@pytest.mark.parametrize("ba,budgets,needle", [
    ("bad", {"dev": 1}, "billing account"),
    ("", {"admin": 1}, "unknown persona"),
    ("", {"dev": 0}, "must be > 0"),
])
def test_tfvars_rejects_bad_input(tmp_path: Path, ba: str, budgets: dict[str, float], needle: str) -> None:
    devs = poc_kit.read_devices(write_csv(tmp_path, "win-01,a@example.com,dev,windows\n"))
    with pytest.raises(poc_kit.KitError, match=needle):
        poc_kit.render_tfvars(devs, ba, budgets)


def _self_signed(path: Path, cn: str) -> None:
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", f"/CN={cn}", "-days", "3", "-keyout", str(path.with_suffix(".key")), "-out", str(path)],
                   check=True, capture_output=True)


def test_kit_layout_permissions_and_config(tmp_path: Path) -> None:
    csvp = write_csv(tmp_path, "win-01,a@example.com,dev,windows\nmac-02,b@example.com,contractor,macos\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    for dev in ("win-01", "mac-02"):
        _self_signed(certs / f"{dev}.crt", dev)
    _self_signed(certs / "gateway-ca.pem", "ca")
    out = tmp_path / "kit"
    arcs = poc_kit.build_kit(poc_kit.read_devices(csvp), certs, out, "https://gateway.agy.internal", "10.0.0.5",
                             "example-proj", "europe-west4", {"agy-hosts-pin": "a.example,b.example"})
    assert [a.name for a in arcs] == ["win-01.tar.gz", "win-01.zip", "mac-02.tar.gz"]
    import zipfile
    with zipfile.ZipFile(out / "win-01.zip") as z:
        names = z.namelist()
    assert "win-01/device.key" in names and "win-01/README.txt" in names and "win-01/install-windows.ps1" in names
    assert stat.S_IMODE((out / "win-01.zip").stat().st_mode) == 0o600
    wr = (out / "win-01" / "README.txt").read_text()
    assert "Get-ChildItem -Path . -Recurse | Unblock-File" in wr and "system32" in wr and "-ExecutionPolicy Bypass" in wr and "win-01" in wr and "-Collect" in wr
    mr = (out / "mac-02" / "README.txt").read_text()
    assert "sudo bash install-macos.sh --install" in mr and "Command Line Tools" in mr
    cfg = json.loads((out / "mac-02" / "poc.json").read_text())
    assert cfg["schema"] == poc_kit.KIT_SCHEMA and cfg["persona"] == "contractor" and cfg["group"] == "agy-contractor"
    assert cfg["gateway"] == {"url": "https://gateway.agy.internal", "hostname": "gateway.agy.internal",
                              "ip": "10.0.0.5", "pin_hosts": True}
    assert cfg["hook"]["critical"] == "enforce" and cfg["hook"]["noisy"] == "audit" and cfg["certificate"]["not_after"]
    for name in ("device.key", "device.crt", "gateway-ca.pem", "poc.json"):
        assert stat.S_IMODE((out / "win-01" / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert stat.S_IMODE(arcs[0].stat().st_mode) == 0o600
    with tarfile.open(arcs[0]) as t:
        assert "win-01/device.key" in t.getnames()
    assert (out / "win-01" / "bundle" / "files" / "controls" / "Apply-AGYControls.ps1").is_file()
    assert (out / "win-01" / "bundle" / "bootstrap.ps1").is_file() and (out / "win-01" / "Install-AGYEndpoint.ps1").is_file()
    assert not (out / "mac-02" / "bundle" / "files").exists(), "the Windows bundle only goes into Windows kits"
    for rel in poc_kit.MACOS_BUNDLE:
        assert (out / "mac-02" / "bundle" / rel).is_file(), rel
    wcfg = json.loads((out / "win-01" / "poc.json").read_text())
    assert wcfg["client"]["cli_manifest_url"].endswith("windows_amd64.json") and wcfg["hosts_pin"] == "a.example,b.example"
    assert wcfg["hook"]["audit_classes"] == ["destructive", "workspace_commands", "workspace_write"]
    assert wcfg["layers"] == {"app_control": False, "sysmon": False, "egress_firewall": False, "rdp": "admins"}
    rows = poc_kit.status_rows(poc_kit.read_devices(csvp), out)
    assert rows[0][:3] == ["win-01", "dev", "windows"] and "days left" in rows[0][4]


def test_kit_refuses_missing_cert_and_plain_http(tmp_path: Path) -> None:
    csvp = write_csv(tmp_path, "win-01,a@example.com,dev,windows\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    _self_signed(certs / "gateway-ca.pem", "ca")
    devs = poc_kit.read_devices(csvp)
    with pytest.raises(poc_kit.KitError, match="https://"):
        poc_kit.build_kit(devs, certs, tmp_path / "k", "http://gw", "", "p", "r")
    with pytest.raises(poc_kit.KitError, match="certificate or key missing"):
        poc_kit.build_kit(devs, certs, tmp_path / "k", "https://gw", "", "p", "r")


def test_cli_validate_exit_codes(tmp_path: Path) -> None:
    ok = subprocess.run([sys.executable, str(ROOT / "poc" / "poc_kit.py"), "validate",
                         str(ROOT / "poc" / "devices.csv.example")], capture_output=True, text=True)
    assert ok.returncode == 0 and "5 devices OK" in ok.stdout
    bad = subprocess.run([sys.executable, str(ROOT / "poc" / "poc_kit.py"), "validate",
                          str(write_csv(tmp_path, "x y,a,b,c\n"))], capture_output=True, text=True)
    assert bad.returncode == 2 and "ERROR" in bad.stderr


def test_prices_file_rendered_and_validated(tmp_path: Path) -> None:
    devs = poc_kit.read_devices(write_csv(tmp_path, "win-01,a@example.com,dev,windows\n"))
    prices = poc_kit.read_prices(ROOT / "poc" / "model-prices.json")
    assert set(prices) == {"gemini-3.8-flash", "gemini-4-argon"}
    out = poc_kit.render_tfvars(devs, "", {"dev": 1}, prices)
    assert '"gemini-4-argon" = { input = 4.4, output = 22 }' in out
    assert '"gemini-3.8-flash" = { input = 0.825, output = 4.125 }' in out
    bad = tmp_path / "p.json"
    bad.write_text('{"models": {"m": {"input": "x"}}}')
    with pytest.raises(poc_kit.KitError, match="invalid price file"):
        poc_kit.read_prices(bad)


def test_hook_mode_enforce_clears_audit_classes(tmp_path: Path) -> None:
    csvp = write_csv(tmp_path, "win-01,a@example.com,dev,windows\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    _self_signed(certs / "win-01.crt", "win-01")
    _self_signed(certs / "gateway-ca.pem", "ca")
    poc_kit.build_kit(poc_kit.read_devices(csvp), certs, tmp_path / "k", "https://gw", "", "p", "r", None, "enforce")
    cfg = json.loads((tmp_path / "k" / "win-01" / "poc.json").read_text())
    assert cfg["hook"]["noisy"] == "enforce" and cfg["hook"]["audit_classes"] == []
    with pytest.raises(poc_kit.KitError, match="audit or enforce"):
        poc_kit.build_kit(poc_kit.read_devices(csvp), certs, tmp_path / "k2", "https://gw", "", "p", "r", None, "off")


# --- installer preflight in POC mode (prompt logging hash = grant-installer.sh --no-evidence)
def _preflight():
    import importlib
    sys.path.insert(0, str(ROOT / "install"))
    return importlib.import_module("preflight")


def test_preflight_no_evidence_skips_deny_permissions(monkeypatch: pytest.MonkeyPatch) -> None:
    pf = _preflight()
    asked: list[str] = []

    def fake_test(project: str, perms: list[str], token: str) -> tuple[set[str], list[str]]:
        asked.extend(perms)
        return {p for p in perms if not p.startswith("iam.denypolicies.")}, []

    monkeypatch.setattr(pf.cp, "test", fake_test)
    monkeypatch.setattr(pf, "RESULTS", [])
    pf.check_permissions("demo-project", "t", "user:a@example.com", no_evidence=True)
    assert not [p for p in asked if p.startswith("iam.denypolicies.")]
    assert [r.status for r in pf.RESULTS] == ["PASS"]
    monkeypatch.setattr(pf, "RESULTS", [])
    pf.check_permissions("demo-project", "t", "user:a@example.com")   # evidence modes still need the deny rights
    assert pf.RESULTS[0].status == "FAIL" and "iam.denypolicies" in pf.RESULTS[0].detail


def test_installer_passes_no_evidence_and_quota_permission() -> None:
    inst = (ROOT / "install.sh").read_text()
    assert '^(none|hash)$ ]] && args+=(--no-evidence)' in inst
    perms = (ROOT / "install" / "permissions.txt").read_text().split()
    assert "serviceusage.services.use" in perms   # gcloud --billing-project / quota project calls


def test_state_bootstrap_never_hangs_on_hidden_gcloud_prompt() -> None:
    sb = (ROOT / "install" / "state-bootstrap.sh").read_text()
    assert "export CLOUDSDK_CORE_DISABLE_PROMPTS=1" in sb.split("log()", 1)[0]
    wait = sb.index("gcloud kms locations list")
    assert sb.index("cloudkms.googleapis.com") < wait < sb.index("gcloud kms keyrings describe")


def test_kits_carry_the_attack_pack_without_results(tmp_path: Path) -> None:
    csvp = write_csv(tmp_path, "win-01,a@example.com,dev,windows\nmac-02,b@example.com,contractor,macos\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    for dev in ("win-01", "mac-02", "gateway-ca"):
        _self_signed(certs / (f"{dev}.crt" if dev != "gateway-ca" else "gateway-ca.pem"), dev)
    out = tmp_path / "kit"
    poc_kit.build_kit(poc_kit.read_devices(csvp), certs, out, "https://gateway.agy.internal", "", "p", "europe-west4")
    for dev, os_name in (("win-01", "windows"), ("mac-02", "macos")):
        ap = out / dev / "attack-pack"
        assert (ap / "runner.py").is_file() and (ap / "scenarios.json").is_file() and (ap / "repos").is_dir()
        assert not list(ap.rglob("__pycache__")) and not (ap / "results").exists()
        readme = (out / dev / "README.txt").read_text()
        assert f"--mode live --os {os_name}" in readme and "never device.key" in readme
    with tarfile.open(out / "mac-02.tar.gz") as t:
        assert "mac-02/attack-pack/runner.py" in t.getnames()
    assert 'C:\\Program Files\\Python312\\python.exe' in (out / "win-01" / "README.txt").read_text()


def test_linux_devices_are_rejected_until_a_linux_endpoint_script_exists(tmp_path: Path) -> None:
    csvp = write_csv(tmp_path, "lin-01,a@example.com,dev,linux\n")
    with pytest.raises(poc_kit.KitError, match="os 'linux' must be one of windows, windows10, macos"):
        poc_kit.read_devices(csvp)


def test_poc_enables_shared_saved_queries_off_by_default() -> None:
    assert "enable_saved_queries = true" in poc_kit.render_tfvars([], "", {})
    obs = (ROOT / "terraform" / "modules" / "observability" / "main.tf").read_text()
    assert 'for_each     = var.enable_saved_queries ? local.saved_queries : {}' in obs
    assert 'visibility   = "SHARED"' in obs and "._AllLogs`" in obs
    root_vars = (ROOT / "terraform" / "variables.tf").read_text()
    block = root_vars.split('variable "enable_saved_queries"', 1)[1].split("}", 1)[0]
    assert "default     = false" in block
    perms = (ROOT / "install" / "permissions.txt").read_text().split()
    assert {"logging.queries.create", "logging.queries.share", "logging.queries.deleteShared"} <= set(perms)


def test_image_probe_permission_denied_fails_clearly_instead_of_rebuilding() -> None:
    inst = (ROOT / "install.sh").read_text()
    p4 = inst.split("p4_image() {", 1)[1].split("\n}\n", 1)[0]
    assert p4.index('[[ "$code" == "403" ]]') < p4.index("gcloud builds submit")
    assert "images describe" not in p4 and "/packages/agy-gateway/tags/" in p4
    perms = (ROOT / "install" / "permissions.txt").read_text().split()
    assert "artifactregistry.tags.get" in perms


def test_every_endpoint_script_ships_with_the_kit_builder() -> None:
    # runs in the published trees too: a script missing from the release list fails here, not on a customer laptop
    for os_name, script in poc_kit.OS_SCRIPTS.items():
        assert (ROOT / "poc" / script).is_file(), f"{os_name}: poc/{script} missing"


def test_kit_refuses_a_missing_endpoint_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    csvp = write_csv(tmp_path, "w10-01,a@example.com,dev,windows10\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    _self_signed(certs / "w10-01.crt", "w10-01")
    _self_signed(certs / "gateway-ca.pem", "ca")
    monkeypatch.setitem(poc_kit.OS_SCRIPTS, "windows10", "does-not-exist.ps1")
    with pytest.raises(poc_kit.KitError, match="endpoint script does-not-exist.ps1 missing"):
        poc_kit.build_kit(poc_kit.read_devices(csvp), certs, tmp_path / "k", "https://gw", "", "p", "r")
