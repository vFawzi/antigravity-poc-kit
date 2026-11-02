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

"""Harness for poc/install-macos.sh: the real script against a fake filesystem root with stub macOS tools.

Proves the script's logic (files, ownership, immutable flags, groups, LaunchDaemons, hosts, uninstall) on any OS
without touching the machine. Real macOS behaviour is validated separately on a macOS CI runner.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc"))

import poc_kit  # noqa: E402

STUB = r'''#!/usr/bin/env python3
"""Stub macOS tools for the install-macos.sh harness. State lives in $AGY_STUB_STATE (JSON)."""
import hashlib, json, os, stat, sys
from pathlib import Path
st_path = Path(os.environ["AGY_STUB_STATE"]); root = os.environ["AGY_ROOT"]
st = json.loads(st_path.read_text()) if st_path.exists() else {"owner": {}, "flags": {}, "groups": {}, "launchd": [], "users": {}}
def save(): st_path.write_text(json.dumps(st))
def real(p): return p if p.startswith(root) else root + p
tool, args = os.path.basename(sys.argv[0]), sys.argv[1:]
if tool == "dscl":                       # dscl . -read /Users/<u> <attr> | /Groups/<g>
    path = args[2]
    if path.startswith("/Users/"):
        u = path.split("/")[2]
        if u not in st["users"]: sys.exit(56)
        if len(args) > 3 and args[3] == "NFSHomeDirectory": print("NFSHomeDirectory: /Users/" + u)
        else: print("UniqueID: 501")
    elif path.startswith("/Groups/"):
        sys.exit(0 if path.split("/")[2] in st["groups"] else 56)
elif tool == "dseditgroup":
    o = args[args.index("-o") + 1]; g = args[-1]
    if o == "create": st["groups"].setdefault(g, [])
    elif o == "delete": st["groups"].pop(g, None)
    elif o == "edit":
        u = args[args.index("-a") + 1] if "-a" in args else args[args.index("-d") + 1]
        m = st["groups"].setdefault(g, [])
        if "-a" in args and u not in m: m.append(u)
        if "-d" in args and u in m: m.remove(u)
    elif o == "checkmember":
        u = args[args.index("-m") + 1]
        print("yes " + u + " is a member of " + g if u in st["groups"].get(g, []) else "no " + u + " is NOT a member of " + g)
    save()
elif tool == "chown":
    rec = "-R" in args; args = [a for a in args if a != "-R"]; who = args[0].split(":")[0]
    for p in args[1:]:
        if st["flags"].get(p, "").find("schg") >= 0: print("chown: " + p + ": Operation not permitted", file=sys.stderr); sys.exit(1)
        st["owner"][p] = who
        if rec:
            for d, _, fs in os.walk(p):
                for x in [d] + [os.path.join(d, f) for f in fs]: st["owner"][x] = who
    save()
elif tool == "chflags":
    flag, paths = args[0], args[1:]
    for p in paths:
        if flag.startswith("no"): st["flags"][p] = ""
        else: st["flags"][p] = flag
    save()
elif tool == "stat":                     # stat -f <fmt> <path>   (%Su owner, %Sg group, %Sf flags, %Lp perms)
    fmt, p = args[1], args[2]
    if p not in st["owner"] and not os.path.exists(p): sys.exit(1)   # /dev/console is absent in CI containers
    perms = format(stat.S_IMODE(os.stat(p).st_mode), "o") if os.path.exists(p) else "600"
    print(fmt.replace("%Su", st["owner"].get(p, "user")).replace("%Sg", "wheel").replace("%Sf", st["flags"].get(p, "-") or "-").replace("%Lp", perms))
elif tool == "launchctl":
    sub = args[0]
    if sub == "bootstrap": st["launchd"].append(os.path.basename(args[2]).removesuffix(".plist")); save()
    elif sub == "bootout":
        lab = args[1].split("/")[-1]
        if lab in st["launchd"]: st["launchd"].remove(lab); save()
        else: sys.exit(3)
    elif sub == "print": sys.exit(0 if args[1].split("/")[-1] in st["launchd"] else 113)
elif tool == "sw_vers": print("15.1")
elif tool == "shasum":
    print(hashlib.sha512(open(args[-1], "rb").read()).hexdigest() + "  " + args[-1])
elif tool == "curl": print("000")   # no network, no proxy in the harness
elif tool == "install": sys.exit(1)  # force the cp fallback (no root)
else: pass                            # dscacheutil, killall, logger, xattr, log, nc: no-ops
'''
TOOLS = ["dscl", "dseditgroup", "chown", "chflags", "stat", "launchctl", "sw_vers", "shasum", "curl", "install",
         "dscacheutil", "killall", "logger", "xattr", "log", "nc"]


@pytest.fixture()
def mac(tmp_path: Path) -> dict[str, Path]:
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (root / "Users" / "dev" / ".gemini").mkdir(parents=True)
    (root / "Users" / "dev" / ".gemini" / "my-notes.txt").write_text("user data")
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    stub = bin_ / "_stub.py"
    stub.write_text(STUB)
    stub.chmod(0o755)
    for t in TOOLS:
        (bin_ / t).symlink_to(stub)
    state = tmp_path / "stub.json"
    state.write_text(json.dumps({"owner": {}, "flags": {}, "groups": {"admin": ["itadmin"]}, "launchd": [],
                                 "users": {"dev": {}, "itadmin": {}}}))
    # kit for a macOS developer device (self-signed test certificates, fake CLI archive)
    csvp = tmp_path / "devices.csv"
    csvp.write_text("device,owner,persona,os\nmac-dev-01,dev@example.com,dev,macos\n")
    certs = tmp_path / "certs"
    certs.mkdir()
    for name in ("mac-dev-01.crt", "gateway-ca.pem"):
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                        "-subj", "/CN=test", "-days", "20", "-keyout", str(certs / (Path(name).stem + ".key")),
                        "-out", str(certs / name)], check=True, capture_output=True)
    kit = tmp_path / "kit"
    poc_kit.build_kit(poc_kit.read_devices(csvp), certs, kit, "https://gateway.agy.internal", "10.0.0.5",
                      "example-proj", "europe-west4", {"agy-hosts-pin": "aiplatform.googleapis.com,api.ngrok.com"})
    cli = tmp_path / "cli"
    cli.mkdir()
    (cli / "agy").write_text("#!/bin/sh\necho agy-test\n")
    (cli / "agy").chmod(0o755)
    with tarfile.open(tmp_path / "cli.tgz", "w:gz") as t:
        t.add(cli / "agy", arcname="agy")
    return {"root": root, "bin": bin_, "state": state, "kit": kit / "mac-dev-01", "cli": tmp_path / "cli.tgz"}


def run(mac: dict[str, Path], *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "AGY_ROOT": str(mac["root"]), "AGY_STUB_STATE": str(mac["state"]), "AGY_CLI_TARBALL": str(mac["cli"]),
           "AGY_PYTHON": sys.executable, "PATH": f"{mac['bin']}:{os.environ['PATH']}"}
    trace = ["-x"] if os.environ.get("AGY_HARNESS_TRACE") else []
    return subprocess.run(["bash", *trace, str(mac["kit"] / "install-macos.sh"), *args], env=env, capture_output=True, text=True,
                          timeout=120)


def results(mac: dict[str, Path]) -> dict[str, str]:
    data = json.loads((mac["root"] / "Library/Application Support/AntigravityPOC/test.json").read_text())
    return {r["id"]: r["status"] for r in data}


def test_install_test_repair_uninstall_cycle(mac: dict[str, Path]) -> None:
    r = run(mac, "--install", "--user", "dev", "--offline")
    assert r.returncode == 0, r.stdout + r.stderr
    res = results(mac)
    for cid in ("M01", "M02", "M03", "M05", "M06", "M07", "M08", "M09", "M10", "M12", "M13"):
        assert res[cid] == "PASS", (cid, r.stdout)
    assert res["M04"] == "FAIL" and res["M11"] == "FAIL", "no proxy / no gateway in the harness"
    st = json.loads(mac["state"].read_text())
    home = str(mac["root"] / "Users/dev")
    sup = str(mac["root"] / "Library/Application Support/Antigravity")
    for f in (f"{home}/.gemini/antigravity-cli/settings.json", f"{home}/.gemini/config/hooks.json",
              f"{home}/.gemini/config/mcp_config.json", f"{home}/.gemini/antigravity/browserAllowlist.txt",
              f"{sup}/admin_settings.json", f"{sup}/hooks/policy.json"):
        assert st["owner"][f] == "root" and "schg" in st["flags"][f], f
    assert "schg" in st["flags"][f"{home}/.gemini"], "~/.gemini immutable (can't be renamed away)"
    assert st["groups"]["agy-dev"] == ["dev"] and "agy-contractor" in st["groups"]
    assert sorted(st["launchd"]) == ["com.google.agy.credproxy", "com.google.agy.policy"]
    settings = (mac["root"] / "Users/dev/.gemini/antigravity-cli/settings.json").read_text()
    assert "/Users/dev/projects" in settings and "/data/projects/dev" not in settings, "persona paths rewritten"
    pol = json.loads((mac["root"] / "Library/Application Support/Antigravity/hooks/policy.json").read_text())
    assert pol["default"]["audit_classes"] == ["destructive", "workspace_commands", "workspace_write"]
    hosts = (mac["root"] / "etc/hosts").read_text()
    assert "10.0.0.5 gateway.agy.internal # agy-poc-gw" in hosts and "0.0.0.0 api.ngrok.com # agy-pin" in hosts
    key = mac["root"] / "Library/Application Support/Antigravity/credproxy/device.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    plist = (mac["root"] / "Library/LaunchDaemons/com.google.agy.credproxy.plist").read_text()
    assert "<string>cert</string>" in plist and "/Library/Application Support/Antigravity/credproxy/device.key" in plist
    # drift repair re-applies a removed lock
    st["flags"][f"{home}/.gemini/config/hooks.json"] = ""
    mac["state"].write_text(json.dumps(st))
    assert run(mac, "--repair").returncode == 0
    assert "schg" in json.loads(mac["state"].read_text())["flags"][f"{home}/.gemini/config/hooks.json"]
    # evidence, then uninstall -> not installed, user's own files kept
    c = run(mac, "--collect")
    assert c.returncode == 0 and "evidence:" in c.stdout, c.stderr
    u = run(mac, "--uninstall")
    assert u.returncode == 0, u.stdout + u.stderr
    assert results(mac) == {"P00": "PASS"}, u.stdout
    st = json.loads(mac["state"].read_text())
    assert "agy-dev" not in st["groups"] and not st["launchd"]
    assert (mac["root"] / "Users/dev/.gemini/my-notes.txt").read_text() == "user data"
    assert not (mac["root"] / "Users/dev/.gemini/config/hooks.json").exists()
    assert "agy-poc-gw" not in (mac["root"] / "etc/hosts").read_text()


def test_refuses_admin_owner_and_wrong_kit(mac: dict[str, Path]) -> None:
    st = json.loads(mac["state"].read_text())
    st["users"]["boss"] = {}
    st["groups"]["admin"].append("boss")
    mac["state"].write_text(json.dumps(st))
    r = run(mac, "--install", "--user", "boss", "--offline")
    assert r.returncode != 0 and "administrator" in r.stderr
    r = run(mac, "--install", "--offline")   # console user proposed, no answer on stdin -> no install
    assert r.returncode != 0 and not (mac["root"] / "Library/Application Support/AntigravityPOC/install.json").exists()
    cfg = json.loads((mac["kit"] / "poc.json").read_text())
    cfg["os"] = "windows"
    (mac["kit"] / "poc.json").write_text(json.dumps(cfg))
    r = run(mac, "--install", "--user", "dev", "--offline")
    assert r.returncode != 0 and "not macOS" in r.stderr


def test_launcher_refuses_admin_and_review_bypass(mac: dict[str, Path]) -> None:
    assert run(mac, "--install", "--user", "dev", "--offline").returncode == 0
    shim = (mac["root"] / "usr/local/bin/agy").read_text()
    for needle in ("--dangerously-skip-permissions", "accept-edits", "admin", "agy-dev", "AGY_CLI_DISABLE_AUTO_UPDATE"):
        assert needle in shim


def test_console_user_is_proposed_as_owner(mac: dict[str, Path]) -> None:
    st = json.loads(mac["state"].read_text())
    st["owner"]["/dev/console"] = "dev"
    mac["state"].write_text(json.dumps(st))
    r = run(mac, "--install", "--offline", "--yes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "device owner: dev (console user)" in r.stdout
    assert json.loads((mac["root"] / "Library/Application Support/AntigravityPOC/install.json").read_text())["user"] == "dev"
    st = json.loads(mac["state"].read_text())
    st["owner"]["/dev/console"] = "root"
    mac["state"].write_text(json.dumps(st))
    assert run(mac, "--uninstall").returncode == 0
    r = run(mac, "--install", "--offline", "--yes")
    assert r.returncode != 0 and "nobody is signed in" in r.stderr
