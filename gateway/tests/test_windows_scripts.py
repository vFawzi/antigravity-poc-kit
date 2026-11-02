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

"""Static checks for the Windows PowerShell scripts (pitfalls found on the reference workstation)."""
from __future__ import annotations

import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2] / "windows"
SCRIPTS = sorted(p for p in ROOT.rglob("*.ps1") if "w0" not in p.parts)
# built-in aliases shadow functions of the same name (e.g. md = mkdir): never define functions with these names
ALIASES = {"md", "cd", "rd", "del", "cp", "mv", "rm", "ls", "dir", "cat", "echo", "gc", "sc", "ni", "type", "set",
           "sleep", "sort", "start", "kill", "ps", "gp", "sp", "where", "select", "group", "measure", "compare", "diff"}


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_function_shadowed_by_alias(path: pathlib.Path) -> None:
    names = {m.lower() for m in re.findall(r"(?im)^\s*function\s+([\w-]+)", path.read_text())}
    assert not names & ALIASES, f"function name(s) shadowed by a built-in alias: {names & ALIASES}"


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_args_parameter(path: pathlib.Path) -> None:
    # $args is an automatic variable; a parameter with that name silently receives nothing
    assert not re.search(r"\[\w+\]\s*\$args\b", path.read_text(), re.I)


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_parenthesised_try(path: pathlib.Path) -> None:
    # "(try { } catch { })" is a parse error in Windows PowerShell 5.1; use $(try { } catch { })
    assert not re.search(r"(?<!\$)\(\s*try\s*\{", path.read_text())


def test_no_force_new_item_on_registry() -> None:
    # New-Item -Force on an existing registry key recreates it and drops its values
    for p in SCRIPTS:
        for line in p.read_text().splitlines():
            if re.search(r"New-Item\s+-Path\s+\S*HKLM", line, re.I) or ("New-Item -Path $" in line and "Force" in line):
                assert "Test-Path" in line, f"{p.name}: unguarded New-Item -Force: {line.strip()}"


def test_windows_settings_have_only_absolute_windows_paths() -> None:
    # a Linux path such as /tmp makes the Windows terminal sandbox fail ("non-absolute file path")
    import json
    import re as _re
    for f in (ROOT / "files" / "policies").glob("agy-*.settings.json"):
        perms = json.loads(f.read_text())["permissions"]
        for rule in perms["allow"] + perms["deny"] + perms["ask"]:
            m = _re.match(r"^(read_file|write_file)\((.*)\)$", rule)
            if m:
                assert _re.match(r"^[A-Za-z]:/", m.group(2)), f"{f.name}: {rule}"


def test_windows_bundle_is_generated() -> None:
    import subprocess
    import sys
    r = subprocess.run([sys.executable, str(ROOT / "gen-policies.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_no_settings_deny_covers_the_cli_brain() -> None:
    # plan mode / artifacts live under ~/.gemini/antigravity-cli/brain: a broader deny (e.g. ~/.gemini or ~) breaks them
    import json
    base = pathlib.Path(__file__).resolve().parents[2]
    files = list((base / "endpoint" / "files" / "policies").glob("agy-*.settings.json")) + list((ROOT / "files" / "policies").glob("agy-*.settings.json"))
    for f in files:
        user = "dev" if "dev" in f.name else "contractor"
        for brain in (f"/home/{user}/.gemini/antigravity-cli/brain/x", f"C:/Users/{user}/.gemini/antigravity-cli/brain/x"):
            for rule in json.loads(f.read_text())["permissions"]["deny"]:
                if rule.startswith("write_file("):
                    p = rule[len("write_file("):-1].rstrip("/")
                    assert not brain.startswith(p + "/"), f"{f.name}: {rule} blocks the CLI brain"


@pytest.mark.parametrize("persona", ["agy-dev", "agy-contractor"])
def test_native_sandbox_bypass_disabled(persona: str) -> None:
    # vendor control, in addition to the hook's deny_sandbox_bypass (defence in depth), on Linux and Windows
    import json
    for base in (ROOT.parent / "endpoint" / "files" / "policies", ROOT / "files" / "policies"):
        assert json.loads((base / f"{persona}.settings.json").read_text())["disableSandboxBypass"] is True


def test_admin_enforced_sandbox_is_detected_and_validated() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "Enforcing SandboxMode = true" in apply and "sandbox-state.json" in apply
    assert "SANDBOX_UNAVAILABLE_ADMIN_ENFORCED" in apply
    test = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    assert '"V71"' in test and "sandbox-state.json" in test
    assert "Test-AGYEndpoint.ps1" in (ROOT.parent / "install.sh").read_text()


def _appctl() -> str:
    return (ROOT / "files" / "controls" / "Set-AGYAppControl.ps1").read_text()


def test_contractor_curl_exe_deny_removed_egress_is_the_control() -> None:
    s = _appctl()
    contractor = s.split("$denyContractor = @(", 1)[1].split(")\n", 1)[0]
    assert "curl.exe" not in contractor and "robocopy.exe" in contractor


def test_workspace_exec_deny_only_for_contractors_and_dev_gets_build_roots() -> None:
    s = _appctl()
    writable = s.split("$writable = @(", 1)[1].split(")", 1)[0]
    assert "$Workspace" not in writable                                    # developers: no blanket workspace deny
    assert '$writableContractor = @("$Workspace\\*"' in s                  # contractors keep it
    assert '$devExe = @("$BuildRoot\\*", "$CacheRoot\\*"' in s and "node_modules\\.bin" in s
    assert 'PathRule "Allow" $x "AGY dev build/run"' in s


def test_signed_scripts_fulllanguage_for_dev_only() -> None:
    s = _appctl()
    assert 'PublisherRule $x "AGY dev Microsoft-signed scripts"' in s
    assert "foreach ($x in $devS) {\n  $scr += PublisherRule" in s            # developer SIDs only
    assert 'PublisherRule $sid["AGY-Contractor"]' not in s


def test_wsl_docker_only_for_container_group() -> None:
    s = _appctl()
    assert '"AGY-NoContainers"' in s and "wsl.exe" in s and 'PathRule "Deny" $sid["AGY-NoContainers"]' in s


def test_wdac_supplemental_has_stable_id_and_option_18_only_there() -> None:
    s = _appctl()
    assert "{A6A0B11D-0000-4A67-8000-000000000018}" in s
    assert s.count("Disabled:Runtime FilePath Rule Protection") == 1 and "-Option 18" not in s
    assert "Enabled:Unsigned System Integrity Policy" in s                 # else "signed policy required"


def test_build_layout_and_validation_checks() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    for k in ("UseArtifactsOutput", "ArtifactsPath", "NUGET_PACKAGES", "GOTMPDIR", "PropertyType ExpandString"):
        assert k in apply, k
    assert "Format-Volume" not in apply                                     # never reformat the data disk
    test = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    for v in ("V72", "V73", "V74", "V75"):
        assert f'"{v}"' in test, v
    sql = ROOT.parent / "terraform" / "modules" / "siem" / "sql" / "v_wdac_enforce_readiness.sql"
    assert "ready_to_enforce" in sql.read_text()


def test_cloud_sdk_for_developers_not_contractors() -> None:
    s = _appctl()
    deny_all = s.split("$denyAll = @(", 1)[1].split("\n)\n", 1)[0]
    contractor = s.split("$denyContractor = @(", 1)[1].split(")\n", 1)[0]
    assert "Cloud SDK" not in deny_all and "Cloud SDK" in contractor


def test_package_proxy_client_config_on_both_platforms() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "agy-package-proxy" in apply and "npm_config_registry" in apply and "packageSourceMapping" in apply
    boot = (ROOT.parent / "endpoint" / "bootstrap.sh").read_text()
    assert "agy-package-proxy" in boot and "/etc/profile.d/agy-package-proxy.sh" in boot
    assert '"V76"' in (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()


def test_package_proxy_module_is_eu_cmek_labelled() -> None:
    tf = (ROOT.parent / "terraform" / "modules" / "package_proxy" / "main.tf").read_text()
    assert "kms_key_name  = var.kms_key" in tf and "labels        = var.labels" in tf and "location      = var.region" in tf
    assert 'uri = "https://proxy.golang.org"' in tf and "REMOTE_REPOSITORY" in tf
    root = (ROOT.parent / "terraform" / "variables.tf").read_text()
    pub = root.split('variable "public_registry_hosts"', 1)[1].split("]", 1)[0]
    assert "registry.npmjs.org" in pub and '"sum.golang.org"' not in pub   # checksum DB stays reachable


def test_sysmon_config_managed_and_valid_xml() -> None:
    import xml.etree.ElementTree as ET
    root = ET.parse(ROOT / "files" / "controls" / "agy-sysmon.xml").getroot()
    assert root.tag == "Sysmon" and root.find("EventFiltering") is not None
    # Sysmon 15.22 crashes on "end with any" (validated on the reference VM)
    assert not [e for e in root.iter() if e.get("condition") == "end with any"]
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "agy-sysmon.xml" in apply and 'Invoke-Sysmon @("-c"' in apply
    assert "& $sysmonExe" not in apply   # native stderr -> NativeCommandError under ErrorActionPreference Stop
    tools_script = ROOT / "image" / "scripts" / "20-tools.ps1"   # absent in the trimmed POC kit (no image build)
    if tools_script.exists():
        assert "Get-AuthenticodeSignature" in tools_script.read_text()


def test_ops_agent_noise_filter_keeps_security_signal() -> None:
    boot = (ROOT / "bootstrap.ps1").read_text()
    assert "exclude_logs" in boot and "processors: [agy_drop_noise]" in boot
    drop = boot.split("match_any:", 1)[1].split("service:", 1)[0]
    for keep in ("5152", "5157", "3076", "3077", "8004", "8007"):   # never filtered
        assert keep not in drop, keep


def test_siem_phase4_views_and_detections() -> None:
    siem = ROOT.parent / "terraform" / "modules" / "siem"
    for v in ("v_agent_process_tree", "v_dx_kpis", "v_block_tuning_weekly", "v_wdac_enforce_readiness"):
        assert (siem / "sql" / f"{v}.sql").exists() and f'"{v}"' in (siem / "main.tf").read_text(), v
    det = (siem / "sql" / "detections.sql").read_text()
    for r in ("D8_SANDBOX_UNAVAILABLE_ADMIN_ENFORCED", "D9_AGENT_CREDENTIAL_ACCESS", "D10_AGENT_CLOUD_CLI_WITHOUT_AGENT_SA",
              "D11_BUILD_OUTPUT_EGRESS", "D12_AGENT_EXEC_CONFIG_WRITE"):
        assert r in det, r
    assert "WITH RECURSIVE" in (siem / "sql" / "v_agent_process_tree.sql").read_text()


def test_standard_user_elevation_settings_and_checks() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert '"ConsentPromptBehaviorUser" 0' in apply and '"EnableSudo" 0' in apply and '"TypeOfAdminApprovalMode" 2' in apply
    # missing parent keys are created level by level; never -Force on an existing key (it would wipe it)
    assert "create each missing level" in apply and "New-Item -Path $acc | Out-Null" in apply and "never -Force" in apply
    test = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    for v in ("V79", "V80", "V81", "V83"):
        assert f'"{v}"' in test, v


def test_pre_provisioning_bundle() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    for k in ("LongPathsEnabled", "SeCreateSymbolicLinkPrivilege", "S-1-5-32-559", "netsh http add urlacl",
              "NotifyOnListen False", "AllowStandardUserControl"):
        assert k in apply, k
    assert "5000..5010 + 7000..7010" in apply and "https://+:5001/" in apply and "https://+:7001/" in apply


def test_user_space_tool_locations_under_caches() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    for k in ("npm_config_prefix", "GOBIN", "PIPX_BIN_DIR", "WORKON_HOME", "POETRY_VIRTUALENVS_PATH", "UV_TOOL_BIN_DIR"):
        assert f'{k} = "$cacheRoot\\%USERNAME%' in apply, k
    s = _appctl()
    assert "\\.venv\\Scripts\\*" in s


def test_applocker_binary_denies_by_publisher() -> None:
    s = _appctl()
    assert "Get-AppLockerFileInformation" in s and "BinaryDenyRule" in s and 'Action=""Deny""' in s
    # vendor folders are not resolved by publisher (python.exe in the Cloud SDK would be blocked everywhere)
    assert "StartsWith($env:WINDIR" in s


def test_siem_elevation_view_and_detections_d14_d19() -> None:
    siem = ROOT.parent / "terraform" / "modules" / "siem"
    v = (siem / "sql" / "v_elevation_events.sql").read_text()
    for src in ("sysmon_high_integrity", "security_4688_elevated", "auditd_agy_priv", "agy_pkg", "in_agent_tree"):
        assert src in v, src
    assert "VIRTUAL USERS" in v                       # OpenSSH virtual accounts are not people
    assert '"v_elevation_events"' in (siem / "main.tf").read_text()
    det = (siem / "sql" / "detections.sql").read_text()
    for r in ("D14_ELEVATION_IN_AGENT_LINEAGE", "D15_AGENT_USER_PERSISTENCE", "D15_SCHEDULED_TASK_OR_RC_FILE",
              "D16_ELEVATION_ATTEMPT", "D16_DENIED_SUDO_OR_AGY_PKG", "D17_USER_TRUSTED_ROOT_CERTIFICATE",
              "D19_ROOT_EQUIVALENT_GROUP_MEMBERSHIP"):
        assert r in det, r


def test_elevation_telemetry_sources() -> None:
    import xml.etree.ElementTree as ET
    sm = ET.parse(ROOT / "files" / "controls" / "agy-sysmon.xml").getroot()
    text = ET.tostring(sm, encoding="unicode")
    assert "\\CurrentVersion\\Run" in text and "\\SystemCertificates\\Root\\Certificates\\" in text and "Startup" in text
    assert 'condition="begin with">HKU' not in text   # volume guard
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "Other Object Access Events" in apply and "Security Group Management" in apply
    ops = (ROOT.parent / "endpoint" / "files" / "ops-agent" / "config.yaml").read_text()
    assert "/var/log/auth.log" in ops and "agy_priv" in ops and "pkg)" in ops


def test_settings_source_registry_params_metadata() -> None:
    cfg = (ROOT / "files" / "controls" / "AGYConfig.ps1").read_text()
    body = cfg[cfg.index("function Get-AgyParam"):]
    assert body.index("AgyPolicyKey") < body.index("AgyParamsFile") < body.index("metadata.google.internal")
    for f in ("Apply-AGYControls.ps1", "Sync-AGYEgress.ps1", "Test-AGYEndpoint.ps1"):
        s = (ROOT / "files" / "controls" / f).read_text()
        assert "metadata.google.internal" not in s and "AGYConfig.ps1" in s, f   # one settings source for every script
    boot = (ROOT / "bootstrap.ps1").read_text()
    assert "HKLM:\\SOFTWARE\\Policies\\AGY" in boot and "params.json" in boot and "$OnGce" in boot


def test_bootstrap_off_google_cloud_is_safe() -> None:
    boot = (ROOT / "bootstrap.ps1").read_text()
    assert 'if ($OnGce) { Get-Disk | Where-Object PartitionStyle -eq "RAW" } else { @() }' in boot   # never formats disks
    assert "agy-workspace-root" in boot and "persona-initial-passwords.txt" in boot and "agy-personas" in boot
    assert "$wantOps = $OnGce -or" in boot


def test_workspace_root_substituted_in_policy_and_settings() -> None:
    apply = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "function Set-AgyWorkspace" in apply and apply.count("Set-AgyWorkspace (") >= 2


def test_offline_installer_and_bundle_builder() -> None:
    inst = (ROOT / "install" / "Install-AGYEndpoint.ps1").read_text()
    for k in ("WindowsBuiltInRole]::Administrator", "Python Software Foundation", "O=Google LLC", "O=Microsoft Corporation",
              "AGY-Bootstrap", "Test-AGYEndpoint.ps1", "Get-FileHash"):
        assert k in inst, k
    b = (ROOT.parent / "scripts" / "windows-offline-bundle.sh").read_text()
    assert '"agy-desktop-secrets"' in b and '"agy-config-bucket"' in b and "agy-workspace-root" in b   # GCE-only keys dropped


def test_applocker_has_packaged_app_rules() -> None:
    # Exe rules enforced without an Appx collection block every packaged app for every user (event 8027, Windows 11)
    s = _appctl()
    assert '<RuleCollection Type="Appx" EnforcementMode="Enabled">' in s and "AGY all signed packaged apps" in s


def test_applocker_drift_checks_live_enforcement() -> None:
    s = _appctl()
    assert "Get-AppLockerPolicy -Effective" in s and "APPLOCKER_DRIFT corrected" in s


def test_agent_runs_only_for_personas() -> None:
    s = _appctl()
    assert '$agyPath = "%PROGRAMFILES%\\Antigravity\\*"' in s
    assert 'PathRuleEx "Allow" $everyone "Program Files" "%PROGRAMFILES%\\*" @($agyPath)' in s          # Everyone: excluded
    assert 'PathRule "Deny" $admins "AGY no agent for administrators" $agyPath' in s                    # admins: denied
    assert 'PathRule "Allow" $x "AGY agent for personas" $agyPath' in s                           # personas: allowed
    det = (ROOT.parent / "terraform" / "modules" / "siem" / "sql" / "detections.sql").read_text()
    assert "D20_AGENT_OUTSIDE_PERSONA" in det


def test_applocker_drift_checks_rule_content() -> None:
    # a removed deny / added allow keeps every collection enforced: the local rule set must match ours exactly
    s = _appctl()
    assert "Get-AppLockerPolicy -Local -Xml" in s
    assert "Compare-Object -ReferenceObject (RuleSet ([xml]$xml))" in s
    assert "APPLOCKER_DRIFT corrected: rules changed" in s


def test_sandbox_compatible_persona_settings() -> None:
    # the Windows sandbox enforces a write_file deny as a deny of all access: none on the OS folder (DLL loads fail)
    import json
    for grp in ("agy-dev", "agy-contractor"):
        deny = json.loads((ROOT / "files" / "policies" / f"{grp}.settings.json").read_text())["permissions"]["deny"]
        assert "write_file(C:/Windows)" not in deny
        assert "read_file(C:/Windows/System32/config)" in deny          # the narrow credential-store deny stays


def test_sandbox_placeholder_dirs_and_user_path() -> None:
    s = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert '"AppData\\Roaming\\npm\\etc"' in s and '".cargo"' in s
    assert "SANDBOX_PLACEHOLDERS created" in s
    # tool bins: per-user Path, never %USERNAME% on the machine PATH (expands to SYSTEM)
    assert 'HKEY_USERS\\$($pp.Sid)\\Environment' in s
    assert '$_.Replace("%USERNAME%", $u)' in s


def test_v71_warns_on_old_cli() -> None:
    a = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    t = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    u = (ROOT / "files" / "controls" / "Update-AGYVersions.ps1").read_text()
    assert "cli_version = $cliVer" in a and "cli-version.json" in u
    assert '[version]"1.4.11"' in t and "older than 1.4.11" in t


def test_version_management_windows() -> None:
    u = (ROOT / "files" / "controls" / "Update-AGYVersions.ps1").read_text()
    a = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert 'Update-AGYVersions.ps1") -Bundle $Bundle -Root $Root' in a
    assert '"agy-version-policy" "latest-tested"' in u and '"agy-artifact-base"' in u
    assert 'compat\\agy-versions.json' in u
    # verification before use: digest from the matrix/manifest + Google signature + official URL prefix (or mirror)
    assert 'Get-FileHash $out -Algorithm $algo' in u and '-notmatch "O=Google LLC"' in u
    assert 'download URL outside $PublicBase' in u
    # swap only while not running (next logon), keep previous, roll back on version mismatch
    assert "Get-Process -Name agy" in u and "Get-Process -Name Antigravity" in u
    assert '"$CliExe.prev"' in u and '"$DeskDir.prev"' in u and "rolled back" in u
    # Desktop self-update off
    assert 'app-update.yml' in u and "antigravity-updater\\pending" in u
    assert "versions-state.json" in u


def test_version_management_linux() -> None:
    base = ROOT.parent / "endpoint"
    s = (base / "files" / "agy-version-sync.sh").read_text()
    boot = (base / "bootstrap.sh").read_text()
    pol = (base / "files" / "agy-policy-apply.sh").read_text()
    assert "/usr/local/sbin/agy-version-sync" in pol and '"$CFG/agy-version-sync.sh" /usr/local/sbin/agy-version-sync' in boot
    assert "agy-version-policy latest-tested" in boot and "/etc/antigravity/agy-versions.json" in boot
    assert 'sha512sum -c --quiet' in s and 'url outside $PUBLIC' in s
    assert 'pgrep -x antigravity' in s and "antigravity.prev" in s and "rolled back" in s


def test_matrix_copies_identical() -> None:
    src = (ROOT.parent / "compat" / "agy-versions.json").read_bytes()
    for d in (ROOT / "files" / "compat" / "agy-versions.json", ROOT.parent / "endpoint" / "files" / "compat" / "agy-versions.json"):
        assert d.read_bytes() == src


def test_v84_and_d21() -> None:
    t = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    u = (ROOT / "files" / "controls" / "Update-AGYVersions.ps1").read_text()
    v = (ROOT.parent / "install" / "validate-vm.sh").read_text()
    s = (ROOT.parent / "endpoint" / "files" / "agy-version-sync.sh").read_text()
    siem = ROOT.parent / "terraform" / "modules" / "siem"
    assert '"V84"' in t and "r \"$res\" V84" in v
    for src in (u, s):
        assert "UNMANAGED_CHANGE" in src and "AGY_VERSIONS:" in src
    assert "D21_AGY_VERSION_DRIFT" in (siem / "sql" / "detections.sql").read_text()
    assert "AGY_VERSIONS" in (siem / "sql" / "v_agy_versions.sql").read_text()
    assert 'sql/v_agy_versions.sql' in (siem / "main.tf").read_text()


def test_log_lock_audit_sink_and_egress() -> None:
    tf = ROOT.parent / "terraform"
    obs = (tf / "modules" / "observability" / "main.tf").read_text()
    siem = (tf / "modules" / "siem" / "main.tf").read_text()
    net = (tf / "modules" / "network" / "main.tf").read_text()
    var = (tf / "variables.tf").read_text()
    inst = (ROOT.parent / "install.sh").read_text()
    # lock duration is an installer input; the lock fixes retention; 0 = no lock
    assert 'variable "log_lock_days"' in var and "ask LOG_LOCK_DAYS" in inst and "log_lock_days             = ${LOG_LOCK_DAYS:-0}" in inst
    assert "locked           = local.locked" in obs and "locked           = var.lock_days > 0" in siem
    assert "var.log_lock_days > 0 ? var.log_lock_days" in obs
    # audit logs: regional CMEK bucket + sink, kept out of _Default
    assert 'bucket_id      = "${var.prefix}-audit"' in obs and "cloudaudit.googleapis.com/data_access" in obs
    assert 'resource "google_logging_project_exclusion" "default_audit"' in obs
    # VPC egress deny by default with explicit allows
    assert 'direction          = "EGRESS"' in net and 'name               = "${var.prefix}-deny-all-egress"' in net
    assert '"V94"' in inst and '"V95"' in inst and '"V96"' in inst


def test_windows_vm_ignores_operator_ssh_keys() -> None:
    # validation SSH adds metadata ssh-keys; without this Terraform never converges (V90)
    tf = (ROOT.parent / "terraform" / "modules" / "workstation_windows" / "main.tf").read_text()
    assert 'ignore_changes = [metadata["ssh-keys"]]' in tf


def test_check_ids_not_reused() -> None:
    # 1.11.0 almost reused V91/V92 (gateway audit attribution / streaming) for the logging checks: ids are never reused
    import re
    inst = (ROOT.parent / "install.sh").read_text()
    titles = lambda cid: {t.lower()[:8] for t in re.findall(rf'"{cid}",\s*f?"([^"]+)"', inst)}  # noqa: E731
    assert titles("V91") == {"vertex a"} and titles("V92") == {"streamed"}
    assert titles("V94") == {"audit lo"} and titles("V95") == {"log buck"} and titles("V96") == {"vpc egre"}


def test_seat_onboarding() -> None:
    a = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    t = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    v = (ROOT.parent / "install" / "validate-vm.sh").read_text()
    inst = (ROOT.parent / "install.sh").read_text()
    tf = (ROOT.parent / "terraform" / "main.tf").read_text()
    # Windows pins the seat licence like Linux; V85 on both OSes; seat users get the seat role (least privilege)
    assert '"agy-seat-project"' in a and "-NotePropertyName gcp" in a
    assert '"V85"' in t and 'r "$res" V85' in v
    assert 'role     = "roles/discoveryengine.agentspaceUser"' in tf and "ask SEAT_USERS" in inst and '"S37"' in inst


def test_groups_create_or_existing() -> None:
    tf = ROOT.parent / "terraform"
    g = (tf / "modules" / "groups" / "main.tf").read_text()
    var = (tf / "variables.tf").read_text()
    main = (tf / "main.tf").read_text()
    inst = (ROOT.parent / "install.sh").read_text()
    assert 'resource "google_cloud_identity_group" "g"' in g and "groups.security" in g
    assert 'variable "groups_mode"' in var and 'contains(["none", "create", "existing"]' in var
    assert '"group:${module.groups.dev_group}"' in main and "cloudidentity.googleapis.com" in main
    assert "ask GROUPS_MODE" in inst and "ask DEV_GROUP" in inst and '"S38"' in inst


def test_personas_from_directory_groups() -> None:
    c = (ROOT / "files" / "controls" / "AGYConfig.ps1").read_text()
    a = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    al = (ROOT / "files" / "controls" / "Set-AGYAppControl.ps1").read_text()
    eg = (ROOT / "files" / "controls" / "Sync-AGYEgress.ps1").read_text()
    t = (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    b = (ROOT / "bootstrap.ps1").read_text()
    hook = (ROOT.parent / "endpoint" / "files" / "hooks" / "agy-hook.py").read_text()
    # personas from the session token (WTSQueryUserToken), remembered per SID; directory group SIDs targeted directly
    assert "WTSQueryUserToken" in c and "persona-profiles.json" in c and '"agy-persona-groups"' in c
    assert "$PersonaProfiles = @(Get-AgyPersonaProfiles)" in a and '$who = "*$($pp.Sid)"' in a and "Personas.Keys" not in a
    assert "foreach ($x in $conS)" in al and "foreach ($x in $devS)" in al
    assert "(Get-AgyPersonaSids)[$u]" in eg and '"V86"' in t and '$personaSource -ne "groups"' in b
    assert "persona-groups.json" in hook and 'for g in ("agy-contractor", "agy-dev")' in hook


def test_local_personas_any_member_and_persona_members() -> None:
    # Google-only customers: GCPW local accounts assigned via agy-persona-members; any member of the local groups
    c = (ROOT / "files" / "controls" / "AGYConfig.ps1").read_text()
    assert "function Sync-AgyPersonaMembers" in c and '"agy-persona-members"' in c
    assert '$_.PrincipalSource -eq "Local"' in c and "$admins -contains $n" in c


def test_mixed_mode() -> None:
    tf = ROOT.parent / "terraform"
    var = (tf / "variables.tf").read_text()
    main = (tf / "main.tf").read_text()
    out = (tf / "outputs.tf").read_text()
    inst = (ROOT.parent / "install.sh").read_text()
    assert 'contains(["gateway", "seat", "mixed"], var.client_mode)' in var and 'variable "workstation_client_mode"' in var
    assert re.search(r'seat_on\s+= contains\(\["seat", "mixed"\], var\.client_mode\)', main) and "seat_inspector           = local.seat_on" in main
    assert re.search(r"egress_allowlist\s+= local\.egress_for\[local\.win_ws_mode\]", main) and re.search(r"client_mode\s+= local\.ws_mode", main)
    assert 'output "device_settings_by_mode"' in out
    assert "'^(gateway|seat|mixed)$'" in inst and '"$(tfo client_mode)" =~ ^(seat|mixed)$' in inst


def test_windows_gateway_proxy_and_enrolment() -> None:
    proxy = (ROOT.parent / "endpoint" / "files" / "credproxy" / "agy-credproxy.py").read_text()
    assert (ROOT / "files" / "credproxy" / "agy-credproxy.py").read_text() == proxy   # one implementation
    # Windows caller identity from the TCP owner process token, persona from group SIDs (contractor wins)
    assert "GetExtendedTcpTable" in proxy and "OpenProcessToken" in proxy and 'for g in ("agy-contractor", "agy-dev")' in proxy
    assert "k32.OpenProcess.restype" in proxy   # 64-bit handle safety
    e = (ROOT / "files" / "controls" / "Enroll-AGYDevice.ps1").read_text()
    assert "CertificateRequest" in e and "AddUri" in e and "certificateTemplate = $template" in e
    assert '"*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"' in e   # key folder: SYSTEM + Administrators only
    a = (ROOT / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert '$proxyTask = "AGY-CredProxy"' in a and "Enroll-AGYDevice.ps1" in a and "CREDPROXY_DRIFT" in a
    assert '"V87"' in (ROOT / "files" / "controls" / "Test-AGYEndpoint.ps1").read_text()
    tf = (ROOT.parent / "terraform" / "main.tf").read_text()
    assert 'extra_device_requesters = var.deploy_windows_workstation && local.win_ws_mode == "gateway"' in tf
    assert '["${local.p}-win-ws"]' in tf
