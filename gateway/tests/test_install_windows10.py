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

"""Windows 10 POC endpoint script (poc/install-windows10.ps1, short-term): OS gate, forced approval mode, kits.

Text-level checks (no PowerShell needed; runs as root in a Linux container)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc"))

import poc_kit  # noqa: E402

W10 = (ROOT / "poc" / "install-windows10.ps1").read_text()
W11 = (ROOT / "poc" / "install-windows.ps1").read_text()
CONTROLS = ROOT / "windows" / "files" / "controls"


def _func(src: str, name: str) -> str:
    start = src.index(f"function {name}")
    nxt = re.search(r"(?m)^(function |# -{10,}|\$\w+ = )", src[start + 10:])
    return src[start: start + 10 + (nxt.start() if nxt else len(src))]


def _params(src: str) -> set[str]:
    block = src[src.index("param("): src.index("\n)\n")]
    return set(re.findall(r"\]\s*\[?\w*\]?\$(\w+)", block))


# ---------------------------------------------------------------- header + modes
def test_header_short_term_end_of_support_and_esu() -> None:
    head = W10[:2500]
    assert "SHORT-TERM MITIGATION" in head and "14 October" in head and "2025" in head and "Extended Security Updates" in head
    assert "LTSC 2021" in head and "12 January 2027" in head
    assert "separate copy of install-windows.ps1" in head   # documented design choice


def test_same_modes_and_parameters_as_windows11_except_allowserver() -> None:
    assert _params(W11) - _params(W10) == {"AllowServer"}
    assert _params(W10) >= {"Install", "Test", "Collect", "Uninstall", "User", "AppControl", "Sysmon", "Offline", "Yes", "Kit"}
    for mode in ("Invoke-Install", "Invoke-Test", "Invoke-Collect", "Invoke-Uninstall"):
        assert f"function {mode}" in W10 and f"{{ {mode} }}" in W10
    assert "AllowServer" not in W10 and "26100" not in W10 and "LAB SIMULATION" not in W10


# ---------------------------------------------------------------- OS gate
def _gate(build: int, client: bool = True) -> str:
    """Python mirror of Get-OsRefusal, kept honest by asserting the PowerShell text below."""
    if not client:
        return "server"
    if build >= 22000:
        return "win11"
    if build < 19044:
        return "old"
    if build not in (19044, 19045):
        return "unsupported"
    return ""


def test_build_gate_text() -> None:
    g = _func(W10, "Get-OsRefusal")
    assert "$Win10Builds = @(19044, 19045); $Win11Build = 22000" in W10
    order = [g.index(s) for s in ("-not $os.Client", "-ge $Win11Build", "-lt $Win10Builds[0]", "-notin $Win10Builds")]
    assert order == sorted(order), "server, Windows 11, too old, other - in this order"
    assert "Windows Server is not supported by this script" in g
    assert "Windows 11 detected (build $($os.Build)) - use install-windows.ps1" in g
    assert "Windows 10 21H2 / LTSC 2021 (build 19044) or 22H2 (build 19045) required" in g
    inst = _func(W10, "Invoke-Install")
    # the gate runs before anything is changed on the device (owner lookup, hosts, certificate, groups)
    assert inst.index("Get-OsRefusal $os") < inst.index("Resolve-Account $User") < inst.index("Set-HostsEntry")


@pytest.mark.parametrize(("build", "client", "want"), [(19045, True, ""), (19044, True, ""), (19043, True, "old"), (17763, True, "old"),
                                                        (22000, True, "win11"), (22631, True, "win11"), (26100, True, "win11"),
                                                        (20348, False, "server"), (19045, False, "server"), (19046, True, "unsupported")])
def test_build_gate_matrix(build: int, client: bool, want: str) -> None:
    assert _gate(build, client) == want


def test_app_control_needs_enterprise_or_education() -> None:
    assert "Edition = [string]$cv.EditionID" in W10
    f = _func(W10, "Get-AppControlRefusal")
    assert "'^(IoT)?(Enterprise|Education)'" in f and "-AppControl needs Windows 10 Enterprise or Education" in f
    for ed, ok in (("Enterprise", True), ("EnterpriseN", True), ("EnterpriseS", True), ("EnterpriseSN", True),
                   ("Education", True), ("EducationN", True), ("IoTEnterpriseS", True), ("Professional", False),
                   ("Core", False), ("ProfessionalEducation", False)):
        assert bool(re.match(r"^(IoT)?(Enterprise|Education)", ed)) is ok, ed
    inst = _func(W10, "Invoke-Install")
    assert inst.index("Get-AppControlRefusal $os") < inst.index("Install-AGYEndpoint.ps1\") -ParamsFile")


# ---------------------------------------------------------------- forced approval mode
def test_forced_no_sandbox_params() -> None:
    assert re.search(r'"agy-sandbox"\s+=\s+"off"', W10) and not re.search(r'"agy-sandbox"\s+=\s+"auto"', W10)
    assert re.search(r'"agy-sandbox"\s+=\s+"auto"', W11), "Windows 11 script keeps auto"
    apply_ = (CONTROLS / "Apply-AGYControls.ps1").read_text()
    # "off" -> no sandbox -> settings rewritten to request-review + enableTerminalSandbox false
    assert '"off" { $false }' in apply_
    assert "'\"toolPermission\": \"request-review\"'" in apply_ and "'\"enableTerminalSandbox\": false'" in apply_


def test_selftest_p07_approval_mode() -> None:
    t = _func(W10, "Invoke-Test")
    assert '"Terminal sandbox not available on Windows 10: approval mode active (every agent command needs the user\'s approval)"' in t
    assert 'Add-Row "PASS" "P07"' in t
    assert '$st.toolPermission -eq "request-review" -and $st.enableTerminalSandbox -eq $false -and $sbParam -eq "off"' in t
    assert "ProfileList\\$($inst.sid)" in t
    for pid in ("P00", "P01", "P02", "P03", "P04", "P05", "P06"):   # unchanged ids
        assert f'"{pid}"' in t and f'"{pid}"' in _func(W11, "Invoke-Test")


# ---------------------------------------------------------------- kit checks
def test_kit_os_checks_both_directions() -> None:
    r10 = _func(W10, "Read-Kit")
    assert 'if ($c.os -eq "windows") { Fail "this kit is for Windows 11 - use install-windows.ps1" }' in r10
    assert 'if ($c.os -ne "windows10")' in r10
    r11 = _func(W11, "Read-Kit")
    assert '"this kit is for Windows 10 - use install-windows10.ps1"' in r11 and 'if ($c.os -ne "windows")' in r11


def test_windows11_script_otherwise_unchanged() -> None:
    for s in ('Fail "Windows 11 24H2 (build 26100) or later required for the terminal sandbox', "-not $AllowServer",
              "LAB SIMULATION: Windows Server has no terminal sandbox"):
        assert s in W11
    # only Read-Kit differs between the shared parts of the two scripts
    w11_body = W11[W11.index("function Say"):]
    w10_body = W10[W10.index("function Say"):]
    assert _func(w11_body, "Invoke-Collect") == _func(w10_body, "Invoke-Collect")
    assert _func(w11_body, "Invoke-Uninstall") == _func(w10_body, "Invoke-Uninstall")


# ---------------------------------------------------------------- Windows 10 blocker handled in the bundle: no CiTool
def test_wdac_without_citool_is_staged_not_fatal() -> None:
    s = (CONTROLS / "Set-AGYAppControl.ps1").read_text()
    assert "$HasCiTool = [bool](Get-Command CiTool.exe -ErrorAction SilentlyContinue)" in s
    assert "CiPolicies\\Active" in s and "WDAC_PENDING_REBOOT" in s
    assert s.count("& CiTool.exe --update-policy") == 1, "every deployment goes through Install-AgyCiPolicy"
    r = (CONTROLS / "Remove-AGYEndpoint.ps1").read_text()
    assert "if (Get-Command CiTool.exe -ErrorAction SilentlyContinue)" in r and "CiPolicies\\Active\\$guid.cip" in r
    t = (CONTROLS / "Test-AGYEndpoint.ps1").read_text()
    assert "if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue))" in t and 'Write-Result "WARN" "V74"' in t


# ---------------------------------------------------------------- poc_kit: windows10 kits and validator
def _self_signed(path: Path, cn: str) -> None:
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-subj", f"/CN={cn}", "-days", "3", "-keyout", str(path.with_suffix(".key")), "-out", str(path)],
                   check=True, capture_output=True)


def test_windows10_kit_layout(tmp_path: Path) -> None:
    csvp = tmp_path / "devices.csv"
    csvp.write_text("device,owner,persona,os\nw10-01,a@example.com,dev,Windows10\nwin-02,b@example.com,contractor,windows\n")
    devs = poc_kit.read_devices(csvp)
    assert [d.os for d in devs] == ["windows10", "windows"]
    certs = tmp_path / "certs"
    certs.mkdir()
    for dev in ("w10-01", "win-02"):
        _self_signed(certs / f"{dev}.crt", dev)
    _self_signed(certs / "gateway-ca.pem", "ca")
    out = tmp_path / "kit"
    arcs = poc_kit.build_kit(devs, certs, out, "https://gateway.agy.internal", "10.0.0.5", "p", "europe-west4")
    assert [a.name for a in arcs] == ["w10-01.tar.gz", "w10-01.zip", "win-02.tar.gz", "win-02.zip"]
    with zipfile.ZipFile(out / "w10-01.zip") as z:
        names = set(z.namelist())
    assert "w10-01/install-windows10.ps1" in names and "w10-01/install-windows.ps1" not in names
    assert {"w10-01/bundle/bootstrap.ps1", "w10-01/Install-AGYEndpoint.ps1", "w10-01/bundle/files/controls/Apply-AGYControls.ps1"} <= names
    with tarfile.open(out / "w10-01.tar.gz") as t:
        assert "w10-01/install-windows10.ps1" in t.getnames()
    assert not (out / "win-02" / "install-windows10.ps1").exists() and (out / "win-02" / "install-windows.ps1").is_file()
    cfg = json.loads((out / "w10-01" / "poc.json").read_text())
    assert cfg["os"] == "windows10" and cfg["client"] == {"version_policy": "latest-tested", **poc_kit.WINDOWS_CLIENT}
    rd = (out / "w10-01" / "README.txt").read_text()
    assert "install-windows10.ps1 -Install" in rd and "install-windows10.ps1 -Uninstall" in rd and "install-windows.ps1" not in rd
    assert "approval mode" in rd and "14 October 2025" in rd and "Extended Security Updates" in rd and "Unblock-File" in rd
    assert "LTSC 2021" in rd and "12 January 2027" in rd and "19044" in rd
    assert "install-windows.ps1 -Install" in (out / "win-02" / "README.txt").read_text()


def test_os_values_and_device_message(tmp_path: Path) -> None:
    assert set(poc_kit.OS_SCRIPTS) == {"windows", "windows10", "macos"}
    p = tmp_path / "devices.csv"
    p.write_text("device,owner,persona,os\nLaptop_With_A_Very_Long_Name.corp.example.com.and.more.labels.to.exceed.63,a@example.com,dev,windows10\n")
    with pytest.raises(poc_kit.KitError) as e:
        poc_kit.read_devices(p)
    msg = str(e.value)
    assert "must be lowercase letters, digits, '.', '_' or '-' (2-63 characters)" in msg
    assert "the laptop's short hostname in lowercase; an FQDN also works up to 63 characters" in msg
    p.write_text("device,owner,persona,os\nw10-01,a@example.com,dev,windows11\n")
    with pytest.raises(poc_kit.KitError, match="must be one of windows, windows10, macos"):
        poc_kit.read_devices(p)


# ---------------------------------------------------------------- WDAC: base allows supplemental policies; V74 activation
def test_base_policy_allows_supplemental_and_keeps_stable_id() -> None:
    s = (CONTROLS / "Set-AGYAppControl.ps1").read_text()
    base = s[s.index("Copy-Item \"$env:WINDIR\\schemas\\CodeIntegrity\\ExamplePolicies\\DefaultWindows_Audit.xml\""):
             s.index("Install-AgyCiPolicy $cip \"WDAC base policy\"")]
    assert "Set-RuleOption -FilePath $wdacXml -Option 17" in base   # Enabled:Allow Supplemental Policies
    assert "-ResetPolicyID" not in s, "the base PolicyID stays the example policy's GUID (the supplemental references it)"
    assert "-SupplementsBasePolicyID $baseGuid" in s


def test_v74_activation_from_event_3099_or_citool() -> None:
    t = (CONTROLS / "Test-AGYEndpoint.ps1").read_text()
    v74 = t[t.index('$t74 = "WDAC base'):t.index("# ---------------------------------------------------------------- V75")]
    assert '$allowSupp = $baseXmlText -match "Enabled:Allow Supplemental Policies"' in v74
    # no CiTool (Windows 10): event 3099 since the last boot for BOTH policy ids -> PASS, else WARN (staged)
    no_ct = v74[v74.index("if (-not (Get-Command CiTool.exe"):v74.index("} else {\ntry {")]
    assert 'LogName = "Microsoft-Windows-CodeIntegrity/Operational"; Id = 3099; StartTime = $boot' in no_ct
    assert "LastBootUpTime" in no_ct
    assert "$on[$baseCip[0].BaseName] -and $on[$suppCip[0].BaseName] -and -not $newer" in no_ct
    assert no_ct.index('Write-Result "PASS" "V74"') < no_ct.index('Write-Result "WARN" "V74"')
    assert "lacks 'Enabled:Allow Supplemental Policies'" in no_ct
    # CiTool (Windows 11): enforced base + supplemental AND the base allows supplementals
    assert "if ($base -and $supp -and $allowSupp)" in v74[v74.index("} else {\ntry {"):]


@pytest.mark.parametrize(("base_on", "supp_on", "newer", "want"), [
    (True, True, False, "PASS"), (True, False, False, "WARN"), (False, True, False, "WARN"),
    (False, False, False, "WARN"), (True, True, True, "WARN")])
def test_v74_no_citool_decision(base_on: bool, supp_on: bool, newer: bool, want: str) -> None:
    """Python mirror of the Windows 10 V74 decision (text asserted above)."""
    assert ("PASS" if base_on and supp_on and not newer else "WARN") == want
