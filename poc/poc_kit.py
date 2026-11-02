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

"""POC kit helper for poc-gateway.sh (standard library only).

  poc_kit.py validate DEVICES_CSV
  poc_kit.py tfvars   DEVICES_CSV --billing-account ID --budget dev=2000 --budget contractor=1000 [--prices JSON] --out FILE
  poc_kit.py kit      DEVICES_CSV --certs DIR --out DIR --gateway-url URL --gateway-ip IP --project ID --region R
                      [--device-settings JSON]   (terraform output device_settings_by_mode, gateway entry)
  poc_kit.py status   DEVICES_CSV --out DIR

devices.csv columns: device,owner,persona,os  (persona: dev | contractor; os: windows | macos)
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

DEVICE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$")
PERSONAS = {"dev": "agy-dev", "contractor": "agy-contractor"}
OS_SCRIPTS = {"windows": "install-windows.ps1", "macos": "install-macos.sh"}   # Linux: no POC endpoint script yet
KIT_SCHEMA = "agy-poc-kit/1"
POC_DIR = Path(__file__).resolve().parent
REPO = POC_DIR.parent
# Windows client defaults (same values as the offline installer bundle): CLI release manifest, pinned Desktop build
WINDOWS_CLIENT = {
    "cli_manifest_url": "https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/windows_amd64.json",
    "desktop_object": "antigravity-hub/2.24.0-5780333019398144/windows-x64/Antigravity-x64.exe",
    "desktop_sha256": "b707cce37f3df44a1b731a4cc88d657114267bb7ca11da9d44ac0a5b791643a3",
}
# hook rule classes logged instead of denied while "noisy" rules are in audit (week 1); critical classes always enforce
NOISY_HOOK_CLASSES = ["destructive", "workspace_commands", "workspace_write"]


class KitError(Exception):
    """Invalid input; message is shown to the operator."""


@dataclass(frozen=True)
class Device:
    device: str
    owner: str
    persona: str
    os: str

    @property
    def group(self) -> str:
        return PERSONAS[self.persona]


def read_devices(path: Path) -> list[Device]:
    if not path.is_file():
        raise KitError(f"{path}: file not found")
    with path.open(newline="", encoding="utf-8-sig") as f:
        rows = [r for r in csv.reader(f) if r and not r[0].lstrip().startswith("#")]
    if not rows:
        raise KitError(f"{path}: empty")
    header = [c.strip().lower() for c in rows[0]]
    if header != ["device", "owner", "persona", "os"]:
        raise KitError(f"{path}: header must be device,owner,persona,os (got {','.join(header)})")
    devices: list[Device] = []
    errors: list[str] = []
    seen: set[str] = set()
    for n, row in enumerate(rows[1:], start=2):
        if len(row) != 4:
            errors.append(f"line {n}: expected 4 columns, got {len(row)}")
            continue
        d = Device(*(c.strip() for c in row))
        d = Device(d.device.lower(), d.owner, d.persona.lower(), d.os.lower())
        if not DEVICE_RE.match(d.device):
            errors.append(f"line {n}: device '{d.device}' must match {DEVICE_RE.pattern}")
        if d.device in seen:
            errors.append(f"line {n}: duplicate device '{d.device}'")
        if not EMAIL_RE.match(d.owner):
            errors.append(f"line {n}: owner '{d.owner}' is not an e-mail address")
        if d.persona not in PERSONAS:
            errors.append(f"line {n}: persona '{d.persona}' must be one of {', '.join(PERSONAS)}")
        if d.os not in OS_SCRIPTS:
            errors.append(f"line {n}: os '{d.os}' must be one of {', '.join(OS_SCRIPTS)}")
        seen.add(d.device)
        devices.append(d)
    if errors:
        raise KitError(f"{path}:\n  " + "\n  ".join(errors))
    if not devices:
        raise KitError(f"{path}: no devices")
    return devices


def hcl_str(s: str) -> str:
    return json.dumps(s)   # JSON string literals are valid HCL string literals


def read_prices(path: Path | None) -> dict[str, dict[str, float]]:
    """Model price file ({"models": {model: {"input": x, "output": y}}}, USD per 1M tokens) -> tfvars map."""
    if path is None:
        return {}
    try:
        models = json.loads(path.read_text())["models"]
        return {str(m): {"input": float(p["input"]), "output": float(p["output"])} for m, p in models.items()}
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise KitError(f"{path}: invalid price file ({e})") from e


def render_tfvars(devices: list[Device], billing_account: str, budgets: dict[str, float],
                  prices: dict[str, dict[str, float]] | None = None) -> str:
    unknown = set(budgets) - set(PERSONAS)
    if unknown:
        raise KitError(f"budget for unknown persona(s): {', '.join(sorted(unknown))}")
    if billing_account and not re.match(r"^[A-F0-9]{6}-[A-F0-9]{6}-[A-F0-9]{6}$", billing_account):
        raise KitError(f"billing account '{billing_account}' must look like XXXXXX-XXXXXX-XXXXXX")
    lines = ["# GENERATED by poc/poc-gateway.sh from devices.csv - do not edit; edit devices.csv and re-run.",
             "billing_labels  = true", "enable_saved_queries = true", f"billing_account = {hcl_str(billing_account)}", "", "fleet_devices = {"]
    for d in devices:
        lines.append(f"  {hcl_str(d.device)} = {{ user = {hcl_str(d.owner)}, group = {hcl_str(d.group)} }}")
    lines += ["}", "", "persona_budgets = {"]
    for p, amount in sorted(budgets.items()):
        if amount <= 0:
            raise KitError(f"budget for {p} must be > 0")
        lines.append(f"  {hcl_str(p)} = {{ amount = {amount:g}, thresholds = [0.5, 0.9, 1.0] }}")
    lines += ["}", "", "model_prices_usd_per_mtok = {"]
    for m, p in sorted((prices or {}).items()):
        if p["input"] < 0 or p["output"] < 0:
            raise KitError(f"price for {m} must be >= 0")
        lines.append(f"  {hcl_str(m)} = {{ input = {p['input']:g}, output = {p['output']:g} }}")
    lines += ["}", ""]
    return "\n".join(lines)


def cert_not_after(cert: Path) -> str:
    r = subprocess.run(["openssl", "x509", "-noout", "-enddate", "-in", str(cert)], capture_output=True, text=True,
                       check=False)
    if r.returncode != 0:
        return ""
    raw = r.stdout.strip().removeprefix("notAfter=")
    try:
        return dt.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc).isoformat()
    except ValueError:
        return raw


def copy_windows_bundle(dest: Path) -> None:
    """Endpoint bundle from the repository (bootstrap, controls, hooks, policies, credential proxy, installer)."""
    src_files = REPO / "windows" / "files"
    if not src_files.is_dir():
        raise KitError(f"{src_files}: missing (run from a full checkout)")
    bundle = dest / "bundle"
    if bundle.exists():
        shutil.rmtree(bundle)
    shutil.copytree(src_files, bundle / "files", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copyfile(REPO / "windows" / "bootstrap.ps1", bundle / "bootstrap.ps1")
    shutil.copyfile(REPO / "windows" / "install" / "Install-AGYEndpoint.ps1", dest / "Install-AGYEndpoint.ps1")


MACOS_BUNDLE = {   # kit path -> repository source (the macOS endpoint reuses the Linux hook, policy, proxy and settings)
    "hooks/agy-hook.py": "vm/files/hooks/agy-hook.py",
    "hooks/policy.json": "vm/files/hooks/policy.json",
    "hooks/hooks.json": "vm/files/hooks/hooks.json",
    "credproxy/agy-credproxy.py": "vm/files/credproxy/agy-credproxy.py",
    "policies/admin_settings.json": "vm/files/policies/admin_settings.json",
    "policies/agy-dev.settings.json": "vm/files/policies/agy-dev.settings.json",
    "policies/agy-contractor.settings.json": "vm/files/policies/agy-contractor.settings.json",
    "policies/agy-dev.mcp_config.json": "vm/files/policies/agy-dev.mcp_config.json",
    "policies/agy-contractor.mcp_config.json": "vm/files/policies/agy-contractor.mcp_config.json",
}


def copy_macos_bundle(dest: Path) -> None:
    bundle = dest / "bundle"
    if bundle.exists():
        shutil.rmtree(bundle)
    for rel, src in MACOS_BUNDLE.items():
        s = REPO / src
        if not s.is_file():
            raise KitError(f"{s}: missing (run from a full checkout)")
        (bundle / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(s, bundle / rel)


KIT_README = {
    "windows": """Antigravity POC - device kit {device} ({persona}, Windows)
====================================================================
This folder contains the device certificate and private key for {device}. Keep it confidential:
copy it to the laptop over a secure channel and delete every copy after the installation.

On the laptop, as IT administrator (the device owner stays a standard user):
  1. Sign in as the owner once, then open Terminal (Admin) / PowerShell as administrator.
  2. cd <path to this folder>
  3. Get-ChildItem -Recurse | Unblock-File
  4. powershell -ExecutionPolicy Bypass -File .\\install-windows.ps1 -Install
     (the signed-in user is proposed as device owner; or add -User DOMAIN\\user / AzureAD\\user@corp)
     Add -Offline when the laptop is not on the VPN yet.
  5. Ask the owner to sign out and in once.

Check:      powershell -ExecutionPolicy Bypass -File .\\install-windows.ps1 -Test
Evidence:   powershell -ExecutionPolicy Bypass -File .\\install-windows.ps1 -Collect
            -> send C:\\ProgramData\\AntigravityPOC\\collect-*.zip to the POC team
Remove:     powershell -ExecutionPolicy Bypass -File .\\install-windows.ps1 -Uninstall

Attack pack (live scenarios, after -Test passes; see attack-pack\\README.md): before deleting this kit, copy ONLY the
            attack-pack folder to the owner's profile (never device.key), then as the owner:
            cd attack-pack; & "C:\\Program Files\\Python312\\python.exe" runner.py run --mode live --os windows --persona {persona} --out results\\
""",
    "macos": """Antigravity POC - device kit {device} ({persona}, macOS)
==================================================================
This folder contains the device certificate and private key for {device}. Keep it confidential:
copy it to the Mac over a secure channel and delete every copy after the installation.
Requires macOS 14 or later and the Command Line Tools (xcode-select --install) for /usr/bin/python3.

On the Mac, as IT administrator (the device owner stays a standard user):
  1. Let the owner sign in, then open Terminal with an administrator account.
  2. cd <path to this folder>
  3. sudo bash install-macos.sh --install
     (the signed-in console user is proposed as device owner; or add --user <short name>)
     Add --offline when the Mac is not on the VPN yet.
  4. Ask the owner to sign out and in once.

Check:      sudo bash install-macos.sh --test
Evidence:   sudo bash install-macos.sh --collect
            -> send /Library/Application Support/AntigravityPOC/collect-*.tar.gz to the POC team
Remove:     sudo bash install-macos.sh --uninstall

Attack pack (live scenarios, after --test passes; see attack-pack/README.md): before deleting this kit, copy ONLY the
            attack-pack folder to the owner's home folder (never device.key), then as the owner:
            cd attack-pack && /usr/bin/python3 runner.py run --mode live --os macos --persona {persona} --out results/
""",
}


def read_device_settings(path: Path | None) -> dict[str, str]:
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise KitError(f"{path}: invalid device settings ({e})") from e
    data = data.get("gateway", data) if isinstance(data, dict) else {}
    return {k: str(v) for k, v in data.items() if isinstance(k, str) and k.startswith("agy-")}


def build_kit(devices: list[Device], certs: Path, out: Path, gateway_url: str, gateway_ip: str,
              project: str, region: str, device_settings: dict[str, str] | None = None,
              hook_noisy: str = "audit") -> list[Path]:
    if hook_noisy not in ("audit", "enforce"):
        raise KitError(f"hook mode '{hook_noisy}' must be audit or enforce")
    if not gateway_url.startswith("https://"):
        raise KitError(f"gateway url '{gateway_url}' must start with https://")
    host = gateway_url.removeprefix("https://").split("/")[0]
    ca = certs / "gateway-ca.pem"
    if not ca.is_file():
        raise KitError(f"{ca}: missing (run scripts/fleet-cert.sh first)")
    ssl.PEM_cert_to_DER_cert(ca.read_text().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    archives: list[Path] = []
    for d in devices:
        crt, key = certs / f"{d.device}.crt", certs / f"{d.device}.key"
        if not crt.is_file() or not key.is_file():
            raise KitError(f"{d.device}: certificate or key missing in {certs}")
        kd = out / d.device
        kd.mkdir(mode=0o700, exist_ok=True)
        for src, name in ((crt, "device.crt"), (key, "device.key"), (ca, "gateway-ca.pem")):
            shutil.copyfile(src, kd / name)
            os.chmod(kd / name, 0o600)
        script = POC_DIR / OS_SCRIPTS[d.os]
        if script.is_file():
            shutil.copyfile(script, kd / script.name)
            os.chmod(kd / script.name, 0o700)
        if d.os == "windows":
            copy_windows_bundle(kd)
        elif d.os == "macos":
            copy_macos_bundle(kd)
        # attack pack for the live scenarios on the laptop (prompts, fixtures, evidence checklist); no results
        if (kd / "attack-pack").exists():
            shutil.rmtree(kd / "attack-pack")
        shutil.copytree(POC_DIR / "attack-pack", kd / "attack-pack",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "results", "live*.json"))
        cfg = {
            "schema": KIT_SCHEMA,
            "device_id": d.device, "owner": d.owner, "persona": d.persona, "group": d.group, "os": d.os,
            "gateway": {"url": gateway_url, "hostname": host, "ip": gateway_ip, "pin_hosts": bool(gateway_ip)},
            "project": project, "region": region,
            "certificate": {"cert": "device.crt", "key": "device.key", "gateway_ca": "gateway-ca.pem",
                            "not_after": cert_not_after(crt)},
            "hook": {"critical": "enforce", "noisy": hook_noisy,
                     "audit_classes": NOISY_HOOK_CLASSES if hook_noisy == "audit" else []},
            "client": {"version_policy": "latest-tested", **(WINDOWS_CLIENT if d.os == "windows" else {})},
            # hosts sinkholes for direct model endpoints and tunnels (forces the gateway path); no egress allowlist
            "hosts_pin": (device_settings or {}).get("agy-hosts-pin", ""),
            "layers": {"app_control": False, "sysmon": False, "egress_firewall": False, "rdp": "admins"},
            "generated": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        }
        (kd / "poc.json").write_text(json.dumps(cfg, indent=2) + "\n")
        os.chmod(kd / "poc.json", 0o600)
        if d.os in KIT_README:
            (kd / "README.txt").write_text(KIT_README[d.os].format(device=d.device, persona=d.persona))
        archive = out / f"{d.device}.tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            t.add(kd, arcname=d.device)
        os.chmod(archive, 0o600)
        archives.append(archive)
        if d.os == "windows":   # Windows: a zip opens in Explorer without extra tools
            zpath = out / f"{d.device}.zip"
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
                for f in sorted(kd.rglob("*")):
                    if f.is_file():
                        z.write(f, str(Path(d.device) / f.relative_to(kd)))
            os.chmod(zpath, 0o600)
            archives.append(zpath)
    return archives


def status_rows(devices: list[Device], out: Path) -> list[list[str]]:
    now = dt.datetime.now(dt.timezone.utc)
    rows = []
    for d in devices:
        crt = out / d.device / "device.crt"
        exp = cert_not_after(crt) if crt.is_file() else ""
        if not exp:
            state = "no kit"
        else:
            try:
                days = (dt.datetime.fromisoformat(exp) - now).days
                state = "EXPIRED" if days < 0 else f"{days} days left"
            except ValueError:
                state = exp
        rows.append([d.device, d.persona, d.os, d.owner, state])
    return rows


def parse_budgets(items: list[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for it in items:
        k, sep, v = it.partition("=")
        if not sep:
            raise KitError(f"--budget '{it}' must be persona=amount")
        try:
            out[k.strip()] = float(v)
        except ValueError as e:
            raise KitError(f"--budget '{it}': amount is not a number") from e
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="poc_kit.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate")
    v.add_argument("csv", type=Path)
    t = sub.add_parser("tfvars")
    t.add_argument("csv", type=Path)
    t.add_argument("--billing-account", default="")
    t.add_argument("--budget", action="append", default=[])
    t.add_argument("--prices", type=Path, default=None)
    t.add_argument("--out", type=Path, required=True)
    k = sub.add_parser("kit")
    k.add_argument("csv", type=Path)
    k.add_argument("--certs", type=Path, required=True)
    k.add_argument("--out", type=Path, required=True)
    k.add_argument("--gateway-url", required=True)
    k.add_argument("--gateway-ip", default="")
    k.add_argument("--project", required=True)
    k.add_argument("--region", required=True)
    k.add_argument("--device-settings", type=Path, default=None)
    k.add_argument("--hook-noisy", choices=("audit", "enforce"), default="audit")
    s = sub.add_parser("status")
    s.add_argument("csv", type=Path)
    s.add_argument("--out", type=Path, required=True)
    a = ap.parse_args(argv)
    try:
        devices = read_devices(a.csv)
        if a.cmd == "validate":
            by = {p: sum(1 for d in devices if d.persona == p) for p in PERSONAS}
            print(f"{len(devices)} devices OK ({', '.join(f'{n} {p}' for p, n in by.items())})")
        elif a.cmd == "tfvars":
            a.out.write_text(render_tfvars(devices, a.billing_account, parse_budgets(a.budget), read_prices(a.prices)))
            print(f"wrote {a.out}")
        elif a.cmd == "kit":
            for arc in build_kit(devices, a.certs, a.out, a.gateway_url, a.gateway_ip, a.project, a.region,
                                 read_device_settings(a.device_settings), a.hook_noisy):
                print(f"kit {arc}")
        elif a.cmd == "status":
            for r in status_rows(devices, a.out):
                print(" | ".join(r))
    except KitError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
