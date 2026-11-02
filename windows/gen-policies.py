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

"""Generate the Windows policy bundle from the Linux source of truth (single policy, two platforms).

Writes windows/files/policies/{admin_settings.json, admin_settings.seat.json, agy-dev.settings.json,
agy-contractor.settings.json, agy-dev.mcp_config.json, agy-contractor.mcp_config.json, hooks.json} and copies the cross-platform hook to windows/files/hooks/agy-hook.py.
Run: python3 windows/gen-policies.py   (a unit test fails when the committed bundle is stale)
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "vm" / "files" / "policies"
OUT = ROOT / "windows" / "files" / "policies"
HOOK_SRC = ROOT / "vm" / "files" / "hooks" / "agy-hook.py"
HOOK_OUT = ROOT / "windows" / "files" / "hooks" / "agy-hook.py"
# AGY version support matrix: one source (compat/), copied into both endpoint bundles
MATRIX_SRC = ROOT / "compat" / "agy-versions.json"
# credential proxy: one implementation for Linux and Windows (gateway mode)
PROXY_SRC = ROOT / "vm" / "files" / "credproxy" / "agy-credproxy.py"
PROXY_OUT = ROOT / "windows" / "files" / "credproxy" / "agy-credproxy.py"
MATRIX_OUT = [ROOT / "windows" / "files" / "compat" / "agy-versions.json", ROOT / "vm" / "files" / "compat" / "agy-versions.json"]

WS = "D:/projects"
PYTHON = r"C:\Program Files\Python312\python.exe"
HOOK = r"C:\ProgramData\Antigravity\hooks\agy-hook.cmd"   # no spaces / quotes: the CLI runs hooks via cmd /c

# Linux path -> Windows equivalent (order matters: most specific first)
PATH_MAP: list[tuple[str, str]] = [
    ("/data/projects/", f"{WS}/"),
    ("/etc/antigravity", "C:/ProgramData/Antigravity"),
    ("/etc/agy-credproxy", "C:/ProgramData/agy-credproxy"),
    ("/etc/shadow", "C:/Windows/System32/config"),
    ("/etc/gshadow", "C:/Windows/System32/config"),
    ("/etc/sudoers", "C:/Windows/System32/config"),
    ("/opt/corp-tools", "C:/Program Files/CorpTools"),
    ("/secure-admin", "C:/secure-admin"),
    ("/root", "C:/Users/Administrator"),
    ("/etc", "C:/Windows"),
    ("/var/tmp", "C:/Windows/Temp"),  # nosec B108 - path mapping for deny rules, not a temp file
    ("/tmp", "C:/Windows/Temp"),  # nosec B108 - path mapping for deny rules, not a temp file
]
HOME_SUBS: list[tuple[str, str]] = [
    (".config/gcloud", "AppData/Roaming/gcloud"),
    (".config/gh", "AppData/Roaming/GitHub CLI"),
]
# Windows-only additions (same intent as the Linux lists)
EXTRA_DENY = ["command(plink)", "command(pscp)", "command(psftp)", "command(putty)", "command(mstsc)",
              "command(certutil)", "command(bitsadmin)", "command(runas)", "command(psexec)", "command(reg add)",
              "command(netsh advfirewall)", "command(Set-MpPreference)", "command(Invoke-Expression)", "command(iex)",
              "command(msedge)", "command(chrome)"]
# Windows persistence / profile-script locations (same intent as ~/.bashrc, ~/.profile, ~/.local/bin on Linux)
EXTRA_WRITE_DENY = ["AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup", "Documents/WindowsPowerShell",
                    "Documents/PowerShell"]
EXTRA_ASK_DEV = ["command(Remove-Item)", "command(del)", "command(erase)", "command(rd)", "command(Move-Item)",
                 "command(move)"]
# read-only Windows commands developers use constantly (no sandbox on Windows Server -> otherwise every one prompts)
EXTRA_ALLOW_DEV = ["command(dir)", "command(type)", "command(echo)", "command(where)", "command(Get-ChildItem)",
                   "command(Get-Content)", "command(Get-Location)", "command(Select-String)"]
DROP = {"command(xfreerdp)", "command(xfreerdp3)", "command(rdesktop)", "command(google-chrome)",
        "command(google-chrome-stable)", "command(ping6)"}
# The Windows terminal sandbox enforces a write_file deny as a deny of ALL access for the sandboxed process. A deny on
# the OS folder blocks loading System32 DLLs (powershell.exe exits 0xC0000135 - found on the Windows 11 test device).
# Writes there stay blocked: NTFS (standard users), the sandbox token, and the hook's workspace-only write scope.
DROP_WIN = {"write_file(C:/Windows)"}


def win_path(p: str, user: str) -> str:
    home = f"C:/Users/{user}"
    m = re.match(rf"^/home/{re.escape(user)}(/.*)?$", p)
    if m:
        rest = (m.group(1) or "").lstrip("/")
        for a, b in HOME_SUBS:
            if rest == a or rest.startswith(a + "/"):
                rest = b + rest[len(a):]
        return f"{home}/{rest}".rstrip("/")
    for a, b in PATH_MAP:
        if p == a.rstrip("/") or p.startswith(a):
            return b.rstrip("/") + p[len(a.rstrip("/")):]
    return p


def win_rule(rule: str, user: str) -> str | None:
    """Windows form of a path rule; None for Linux-only paths (a non-absolute path breaks the Windows sandbox config)."""
    m = re.match(r"^(read_file|write_file)\((.*)\)$", rule)
    if not m:
        return rule
    p = win_path(m.group(2), user)
    return f"{m.group(1)}({p})" if re.match(r"^[A-Za-z]:/", p) or not p.startswith("/") else None


def convert_group(src: dict[str, Any], user: str) -> dict[str, Any]:
    out = dict(src)
    out["trustedWorkspaces"] = [f"{WS}/{user}"]
    perms = src["permissions"]
    deny = [w for w in (win_rule(r, user) for r in perms.get("deny", []) if r not in DROP) if w and w not in DROP_WIN]
    deny += [r for r in EXTRA_DENY if r not in deny]
    deny += [f"write_file(C:/Users/{user}/{p})" for p in EXTRA_WRITE_DENY if f"write_file(C:/Users/{user}/{p})" not in deny]
    ask = [w for w in (win_rule(r, user) for r in perms.get("ask", [])) if w]
    if user == "dev":
        ask += [r for r in EXTRA_ASK_DEV if r not in ask]
    else:   # contractors: destructive commands denied outright (same as Linux)
        deny += [r for r in EXTRA_ASK_DEV if r not in deny]
    allow = [w for w in (win_rule(r, user) for r in perms.get("allow", [])) if w]
    allow = ["command(python)" if r == "command(python3)" else r for r in allow]
    if user == "dev":
        allow += [r for r in EXTRA_ALLOW_DEV if r not in allow]
    dedup = lambda xs: list(dict.fromkeys(xs))   # noqa: E731 - keep order, drop duplicates (e.g. /tmp + /var/tmp)
    out["permissions"] = {"allow": dedup(allow), "deny": dedup(deny), "ask": dedup(ask)}
    return out


def hooks_json() -> dict[str, Any]:
    def cmd(event: str) -> dict[str, Any]:
        return {"type": "command", "command": f"{HOOK} {event}", "timeout": 10}
    return {
        "corp-policy-gate": {"PreToolUse": [{"matcher": ".*", "hooks": [cmd("PreToolUse")]}]},
        "corp-audit": {
            "PostToolUse": [{"matcher": ".*", "hooks": [cmd("PostToolUse")]}],
            "SessionStart": [cmd("SessionStart")],
            "PreInvocation": [cmd("PreInvocation")],
        },
    }


def render() -> dict[str, str]:
    files: dict[str, str] = {}
    for name in ("admin_settings.json", "admin_settings.seat.json"):
        files[name] = json.dumps(json.loads((SRC / name).read_text()), indent=2) + "\n"
    for grp, user in (("agy-dev", "dev"), ("agy-contractor", "contractor")):
        files[f"{grp}.settings.json"] = json.dumps(convert_group(json.loads((SRC / f"{grp}.settings.json").read_text()), user),
                                                   indent=2) + "\n"
        # managed MCP server config: platform-neutral, same content on both platforms
        files[f"{grp}.mcp_config.json"] = json.dumps(json.loads((SRC / f"{grp}.mcp_config.json").read_text()), indent=2) + "\n"
    files["hooks.json"] = json.dumps(hooks_json(), indent=2) + "\n"
    return files


def main() -> int:
    check = "--check" in sys.argv
    stale = []
    for name, text in render().items():
        dst = OUT / name
        if check:
            if not dst.exists() or dst.read_text() != text:
                stale.append(str(dst))
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            dst.write_text(text)
    if check:
        if not HOOK_OUT.exists() or HOOK_OUT.read_bytes() != HOOK_SRC.read_bytes():
            stale.append(str(HOOK_OUT))
        stale += [str(d) for d in MATRIX_OUT if not d.exists() or d.read_bytes() != MATRIX_SRC.read_bytes()]
        if not PROXY_OUT.exists() or PROXY_OUT.read_bytes() != PROXY_SRC.read_bytes():
            stale.append(str(PROXY_OUT))
        if stale:
            print("stale (run python3 windows/gen-policies.py):\n  " + "\n  ".join(stale))
            return 1
        return 0
    shutil.copyfile(HOOK_SRC, HOOK_OUT)
    for d in MATRIX_OUT:
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(MATRIX_SRC, d)
    PROXY_OUT.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PROXY_SRC, PROXY_OUT)
    print(f"wrote {OUT} and {HOOK_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
