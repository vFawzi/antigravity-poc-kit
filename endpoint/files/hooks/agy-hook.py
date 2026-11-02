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

"""agy-hook - root-owned Antigravity lifecycle hook (seat hardening profile; also active in gateway mode).

PreToolUse : deny tool calls that violate the per-group policy (commands, protected paths, tools). Fails CLOSED:
             any error while evaluating returns "deny".
             Audit mode: denies of rule classes listed in the policy's audit_classes are logged (AUDIT_ALLOW) and
             allowed; critical / tamper classes are always enforced (NON_AUDITABLE).
PostToolUse: audit record (tool name + target, never file contents) for SIEM correlation.
SessionStart: session record (conversation id, model).
Policy: /etc/antigravity/hooks/policy.json (root-owned). Events: syslog tag agy-hook -> Ops Agent -> Cloud Logging.
"""
from __future__ import annotations

import fnmatch
import json
import ntpath
import os
import posixpath
import re
import shlex
import subprocess
import sys
from collections.abc import Iterator
from typing import Any

# One hook for Linux, macOS and Windows. WIN can be forced (tests) with AGY_HOOK_OS=windows. macOS uses the posix
# policy; the hook also runs under the macOS system Python 3.9 (no 3.10+ syntax or APIs).
WIN = os.name == "nt" or os.environ.get("AGY_HOOK_OS", "").lower() == "windows"
MAC_POLICY_FILE = "/Library/Application Support/Antigravity/hooks/policy.json"
if os.name != "nt":
    import grp
    import pwd
    import syslog

POLICY_FILE = os.environ.get("AGY_HOOK_POLICY", r"C:\ProgramData\Antigravity\hooks\policy.json" if os.name == "nt"
                             else MAC_POLICY_FILE if sys.platform == "darwin" else "/etc/antigravity/hooks/policy.json")


def current_user() -> str:
    if os.name == "nt":
        return os.environ.get("USERNAME", "")
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return os.environ.get("USER") or str(os.getuid())


WARN_EVENTS = {"DENY", "AUDIT_ALLOW", "AUDIT_CLASS_IGNORED"}


def log(event: str, **kw: Any) -> None:
    msg = json.dumps({"event": event, "user": current_user(), **kw}, default=str)[:900]
    warn = event in WARN_EVENTS
    if os.name != "nt":
        syslog.openlog("agy-hook", 0, syslog.LOG_USER)
        syslog.syslog(syslog.LOG_WARNING if warn else syslog.LOG_INFO, msg)
        return
    try:   # Windows Application event log, source "agy-hook" (registered by the bootstrap) -> Ops Agent
        import ctypes
        from ctypes import wintypes
        adv = ctypes.windll.advapi32
        # explicit signatures: the default int return type truncates the 64-bit handle (access violation)
        adv.RegisterEventSourceW.restype = wintypes.HANDLE
        adv.RegisterEventSourceW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
        adv.ReportEventW.argtypes = [wintypes.HANDLE, wintypes.WORD, wintypes.WORD, wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.WORD, wintypes.DWORD, ctypes.POINTER(wintypes.LPCWSTR), ctypes.c_void_p]
        adv.DeregisterEventSource.argtypes = [wintypes.HANDLE]
        h = adv.RegisterEventSourceW(None, "agy-hook")
        if h:
            arr = (wintypes.LPCWSTR * 1)(msg)
            adv.ReportEventW(h, 2 if warn else 4, 0, 1000, None, 1, 0, arr, None)
            adv.DeregisterEventSource(h)
    except Exception:  # noqa: BLE001 - logging must never break the decision
        pass


def _posix_group_names() -> set[str]:
    """Names of the calling user's groups: the process groups plus the directory membership (getgrouplist - macOS
    caps getgroups); unknown gids by number."""
    gids = set(os.getgroups()) | {os.getgid()}
    try:
        gids |= set(os.getgrouplist(current_user(), os.getgid()))
    except (OSError, AttributeError):
        pass
    names: set[str] = set()
    for g in gids:
        try:
            names.add(grp.getgrgid(g).gr_name)
        except KeyError:
            names.add(str(g))
    return names


def group_name(known: tuple[str, ...] = ("agy-dev", "agy-contractor")) -> str:
    if os.name != "nt" and sys.platform == "darwin":
        # macOS: every user's primary group is staff - the persona is a supplementary local group (contractor wins)
        names = _posix_group_names()
        for g in ("agy-contractor", "agy-dev"):
            if g in known and g in names:
                return g
    if os.name != "nt":
        try:
            return grp.getgrgid(os.getgid()).gr_name
        except KeyError:
            return str(os.getgid())
    try:   # local group membership of the calling persona
        out = subprocess.run(["whoami", "/groups", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""
    rows = [line.split('","') for line in out.splitlines() if line]
    names = {r[0].strip('"').split("\\")[-1].lower() for r in rows}
    sids = {r[2].strip('"') for r in rows if len(r) > 2}
    # persona source = groups: directory (Entra ID / AD) group SIDs in the token, mapped by the device policy
    # (C:\ProgramData\Antigravity\persona-groups.json, admin-only write); contractor wins if both match
    try:
        with open(os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Antigravity", "persona-groups.json"),
                  encoding="utf-8") as f:
            pg = json.load(f)
    except (OSError, ValueError):
        pg = {}
    for g in ("agy-contractor", "agy-dev"):
        if g in known and (g in names or sids & set(pg.get(g) or [])):
            return g
    return ""


# ---- review guard: sessions that skip human review ------------------------------------------------------------------
# `agy --dangerously-skip-permissions` and `--mode auto|accept-edits` approve tool calls without a human. The admin
# console can't lock the permission mode, the launcher can be bypassed (the binary is executable), so the hook - which
# runs for every tool call however the CLI was started - checks the command line of the client process it runs under.
CLIENT_EXES = {"antigravity", "agy", "antigravity.exe", "agy.exe"}
BYPASS_ARG = re.compile(r"(?i)^--dangerously-skip-permissions(=.*)?$")
BYPASS_MODES = {"auto", "accept-edits"}


def bypass_in_args(argv: list[str]) -> str | None:
    """The review-bypass option in a client command line, else None."""
    for i, a in enumerate(argv):
        if BYPASS_ARG.match(a):
            return "--dangerously-skip-permissions"
        if a.lower().startswith("--mode="):
            if a.split("=", 1)[1].strip("\"'").lower() in BYPASS_MODES:
                return a
        elif a.lower() == "--mode" and i + 1 < len(argv) and argv[i + 1].strip("\"'").lower() in BYPASS_MODES:
            return f"--mode {argv[i + 1]}"
    return None


def _ancestors_linux(max_depth: int = 12) -> list[tuple[str, list[str]]]:
    out, pid = [], os.getppid()
    for _ in range(max_depth):
        if pid <= 1:
            break
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [x.decode("utf-8", "replace") for x in f.read().split(b"\0") if x]
            with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                stat = f.read()
            exe = os.path.basename(os.readlink(f"/proc/{pid}/exe")) if os.path.exists(f"/proc/{pid}/exe") else ""
        except OSError:
            break
        out.append((exe or os.path.basename(argv[0] if argv else ""), argv))
        pid = int(stat.rsplit(")", 1)[1].split()[1])   # field 4 = ppid (after the parenthesised comm)
    return out


def _ps_table(run: Any = subprocess.run) -> dict[int, tuple[int, str, str]]:
    """pid -> (ppid, executable name, command line) from ps, for systems without /proc (macOS)."""
    head = run(["ps", "-axww", "-o", "pid=", "-o", "ppid=", "-o", "comm="], capture_output=True, text=True,
               timeout=5).stdout
    full = run(["ps", "-axww", "-o", "pid=", "-o", "args="], capture_output=True, text=True, timeout=5).stdout
    args: dict[int, str] = {}
    for line in full.splitlines():
        f = line.split(None, 1)
        if f and f[0].isdigit():
            args[int(f[0])] = f[1].strip() if len(f) > 1 else ""
    out: dict[int, tuple[int, str, str]] = {}
    for line in head.splitlines():
        f = line.split(None, 2)
        if len(f) == 3 and f[0].isdigit() and f[1].isdigit():
            out[int(f[0])] = (int(f[1]), os.path.basename(f[2].strip()), args.get(int(f[0]), ""))
    return out


def _ancestors_ps(max_depth: int = 12, table: dict[int, tuple[int, str, str]] | None = None) -> list[tuple[str, list[str]]]:
    """Ancestor walk via ps (macOS). The command line is split on whitespace (enough to find the bypass options); an
    empty command line is reported as unreadable, which the review guard refuses for client processes."""
    procs = _ps_table() if table is None else table
    out, pid = [], os.getppid()
    for _ in range(max_depth):
        if pid <= 1 or pid not in procs:
            break
        ppid, exe, line = procs[pid]
        argv = line.split() if line else ["<unreadable>"]
        out.append((exe or os.path.basename(argv[0]), argv))
        pid = ppid
    return out


def _ancestors_windows(max_depth: int = 12) -> list[tuple[str, list[str]]]:
    import ctypes
    from ctypes import wintypes
    k32, ntdll = ctypes.windll.kernel32, ctypes.windll.ntdll

    class PE32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260)]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.Process32FirstW.argtypes = k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE32)]
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    ntdll.NtQueryInformationProcess.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.ULONG,
                                                ctypes.POINTER(wintypes.ULONG)]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)   # TH32CS_SNAPPROCESS
    procs: dict[int, tuple[int, str]] = {}
    e = PE32(); e.dwSize = ctypes.sizeof(PE32)
    ok = k32.Process32FirstW(snap, ctypes.byref(e))
    while ok:
        procs[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile)
        ok = k32.Process32NextW(snap, ctypes.byref(e))
    k32.CloseHandle(snap)

    def cmdline(pid: int) -> str | None:   # ProcessCommandLineInformation (60), Windows 8.1+
        h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            size = wintypes.ULONG(0)
            ntdll.NtQueryInformationProcess(h, 60, None, 0, ctypes.byref(size))
            if not size.value:
                return None
            buf = ctypes.create_string_buffer(size.value)
            if ntdll.NtQueryInformationProcess(h, 60, buf, size, ctypes.byref(size)) != 0:
                return None
            length = ctypes.c_ushort.from_buffer(buf, 0).value   # UNICODE_STRING{Length, MaximumLength, Buffer}
            ptr = ctypes.c_void_p.from_buffer(buf, 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 4).value
            return ctypes.wstring_at(ptr, length // 2) if ptr else None
        finally:
            k32.CloseHandle(h)

    out, pid = [], os.getppid()
    for _ in range(max_depth):
        if pid not in procs:
            break
        parent, exe = procs[pid]
        line = cmdline(pid)
        argv = _win_argv(line) if line else ["<unreadable>"]
        out.append((exe, argv))
        pid = parent
    return out


def _win_argv(line: str) -> list[str]:
    """Split a Windows command line exactly as the C runtime does (CommandLineToArgvW). shlex raised ValueError on
    real quoting (e.g. cmd /c "...agy.exe" args) and the guard then skipped the check. Fallback: whitespace split."""
    try:
        import ctypes
        from ctypes import wintypes
        sh, k32 = ctypes.windll.shell32, ctypes.windll.kernel32
        sh.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        sh.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        k32.LocalFree.argtypes = [ctypes.c_void_p]
        n = ctypes.c_int(0)
        arr = sh.CommandLineToArgvW(line, ctypes.byref(n))
        if not arr:
            raise OSError("CommandLineToArgvW failed")
        try:
            return [arr[i] for i in range(n.value)]
        finally:
            k32.LocalFree(arr)
    except Exception:  # noqa: BLE001 - never skip the check because of parsing
        return line.split()


def client_ancestors() -> list[tuple[str, list[str]]]:
    """(exe name, argv) of the client processes above the hook (CLI; the Desktop app has no such options)."""
    try:
        chain = (_ancestors_windows() if os.name == "nt" else _ancestors_linux() if os.path.isdir("/proc/self")
                 else _ancestors_ps())
    except Exception as e:  # noqa: BLE001 - reported by the caller
        log("REVIEW_GUARD_ERROR", error=type(e).__name__)
        return []
    return [(exe, argv) for exe, argv in chain if exe.lower() in CLIENT_EXES]


def review_bypass(data: dict[str, Any], policy: dict[str, Any],
                  ancestors: list[tuple[str, list[str]]] | None = None) -> str | None:
    """Denial reason when the session skips human review (client options, or a bypass mode in the hook payload)."""
    if not policy.get("deny_review_bypass"):
        return None
    for field, bad in (policy.get("review_bypass_payload") or {}).items():   # payload fields, if the client sends them
        v = data.get(field)
        if v is True and bad == [True] or isinstance(v, str) and v.lower() in {str(b).lower() for b in bad}:
            return f"sessions that skip human review are not permitted ({field}={v})"
    for exe, argv in (client_ancestors() if ancestors is None else ancestors):
        if argv == ["<unreadable>"]:
            return f"the client session could not be verified ({exe}) - start agy without review-bypass options"
        opt = bypass_in_args(argv[1:])
        if opt:
            return f"sessions that skip human review are not permitted ({opt}) - start agy without it"
    return None


# ---- elevated / admin sessions: agy must run as a standard user -----------------------------------------------------
# An agent that inherits an elevated token, local admin rights (even UAC-filtered: one prompt away) or a root-equivalent
# group (sudo, docker, libvirt …) can undo every endpoint control. Deny every tool call in such sessions.
def _windows_elevation() -> tuple[bool, bool]:
    """(token elevated, member of BUILTIN\\Administrators - enabled or deny-only)."""
    import ctypes
    from ctypes import wintypes
    adv, k32 = ctypes.windll.advapi32, ctypes.windll.kernel32
    adv.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.DWORD)]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):   # TOKEN_QUERY
        raise OSError("OpenProcessToken failed")
    try:
        etype, n = wintypes.DWORD(0), wintypes.DWORD(0)
        if not adv.GetTokenInformation(tok, 18, ctypes.byref(etype), 4, ctypes.byref(n)):   # TokenElevationType
            raise OSError("GetTokenInformation failed")
    finally:
        k32.CloseHandle(tok)
    out = subprocess.run(["whoami", "/groups", "/fo", "csv", "/nh"], capture_output=True, text=True, timeout=5).stdout
    return etype.value == 2, "S-1-5-32-544" in out   # 2 = TokenElevationTypeFull


def _gname(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def elevated_session(policy: dict[str, Any], probe: Any = None) -> str | None:
    """Denial reason when the hook (and so the agent) runs elevated, as an admin or with a root-equivalent group."""
    if not policy.get("deny_elevated_session"):
        return None
    if WIN and os.name != "nt" and probe is None:
        return None   # Windows policy evaluated off-Windows (tests): no token to inspect
    if WIN:
        elevated, admin = (probe or _windows_elevation)()
        if elevated:
            return "agy may not run elevated (Run as administrator) - start it as a standard user"
        if admin:
            return "agy may not run as a local administrator - use your standard (non-admin) account"
        return None
    if probe:
        euid, groups = probe()
    else:
        gids = set(os.getgroups()) | {os.getgid()}
        euid, groups = os.geteuid(), ({_gname(g) for g in gids} | (_posix_group_names() if sys.platform == "darwin"
                                                                     else set()))
    if euid == 0:
        return "agy may not run as root"
    bad = sorted(set(groups) & set(policy.get("elevated_groups") or []))
    if bad:
        return f"agy may not run for a user in a root-equivalent group ({', '.join(bad)}) - remove the membership"
    return None


# ---- OS-aware paths (Windows: case-insensitive, drive letters, UNC, \\ or /)
def _p():
    return ntpath if WIN else posixpath


def resolve(raw: str, home: str, cwd: str = "") -> str:
    p = _p()
    s = raw.strip().strip('"')
    if s.startswith("~"):
        s = home + s[1:]
    if cwd and not p.isabs(s):
        s = p.join(cwd, s)
    if os.name == "nt" or not WIN:
        s = os.path.realpath(s)          # resolves symlinks / junctions on the real OS
    else:
        s = ntpath.abspath(s) if ntpath.isabs(s) else ntpath.normpath(s)
    return p.normcase(p.normpath(s)) if WIN else s


def within(path: str, root: str) -> bool:
    sep = "\\" if WIN else "/"
    return path == root or path.startswith(root.rstrip(sep) + sep)


def load_policy(group: str) -> dict[str, Any]:
    with open(POLICY_FILE, encoding="utf-8") as fh:
        raw = json.load(fh)
    base, over = raw.get("default", {}), raw.get("groups", {}).get(group, {})
    pol: dict[str, Any] = {k: list(base.get(k, [])) + list(over.get(k, []))
                           for k in ("deny_commands", "deny_paths", "deny_tools", "ask_commands", "workspace_only_commands",
                                     "deny_file_globs", "allow_file_globs", "deny_write_dirnames", "deny_write_files",
                                     "exec_content_files", "exec_content_patterns", "deny_config_commands",
                                     "gcloud_deny_verbs")}
    pol["agent_service_account"] = str(over.get("agent_service_account", base.get("agent_service_account", "")) or "")
    pol["workspace"] = str(over.get("workspace") or base.get("workspace") or "")
    pol["write_tools"] = str(over.get("write_tools") or base.get("write_tools") or "")
    pol["write_also"] = list(base.get("write_also", [])) + list(over.get("write_also", []))
    pol["cli_ask_prefixes"] = list(base.get("cli_ask_prefixes", [])) + list(over.get("cli_ask_prefixes", []))
    pol["deny_sandbox_bypass"] = bool(over.get("deny_sandbox_bypass", base.get("deny_sandbox_bypass", False)))
    pol["deny_review_bypass"] = bool(over.get("deny_review_bypass", base.get("deny_review_bypass", False)))
    pol["ask_as_deny"] = bool(over.get("ask_as_deny", base.get("ask_as_deny", False)))
    pol["deny_elevated_session"] = bool(over.get("deny_elevated_session", base.get("deny_elevated_session", False)))
    pol["elevated_groups"] = list(base.get("elevated_groups", [])) + list(over.get("elevated_groups", []))
    pol["review_bypass_payload"] = {**(base.get("review_bypass_payload") or {}), **(over.get("review_bypass_payload") or {})}
    # audit mode: a group's list REPLACES the default list (so a group can also opt back into full enforcement with
    # []); anything that is not a list of strings means "enforce everything"
    aud = over["audit_classes"] if "audit_classes" in over else base.get("audit_classes", [])
    pol["audit_classes"] = [str(c).strip() for c in aud if isinstance(c, str)] if isinstance(aud, list) else []
    # MCP server allowlist: a group's list replaces the default list; [] = no MCP server; key absent (older policy
    # files) = no MCP check by the hook; anything else = no MCP server
    mcp = over["mcp_allowed_servers"] if "mcp_allowed_servers" in over else base.get("mcp_allowed_servers")
    pol["mcp_allowed_servers"] = None if mcp is None else ([str(x) for x in mcp] if isinstance(mcp, list) else [])
    pol["deny_write_secrets"] = list(base.get("deny_write_secrets", [])) + list(over.get("deny_write_secrets", []))
    return pol


# ---- audit mode (log-but-allow) for noisy rule classes, e.g. during the first tuning week of a POC ------------------
# Every policy decision carries a rule class. A deny whose class is listed in the policy's audit_classes is logged as
# AUDIT_ALLOW and the tool call is allowed. Critical / tamper classes can never be audited, whatever the policy says;
# neither can elevated sessions, review bypass or hook errors (those are decided before / outside the rule classes).
# deny_commands / deny_tools hold exfiltration, remote-code and privilege rules, so only the workspace-scope and
# destructive-command classes are auditable.
RULE_CLASSES = ("tools", "sandbox_bypass", "commands", "secret_files", "paths", "config_dir", "exec_config",
                "cloud_identity", "secret_content", "workspace_write", "workspace_commands", "destructive_critical",
                "destructive")
NON_AUDITABLE = frozenset({"tools", "commands", "secret_files", "paths", "sandbox_bypass", "config_dir", "exec_config",
                           "cloud_identity", "secret_content", "destructive_critical", "elevated_session",
                           "review_bypass", "hook_error"})
AUDITABLE = frozenset(RULE_CLASSES) - NON_AUDITABLE


def audit_classes(policy: dict[str, Any]) -> tuple[frozenset[str], list[str]]:
    """(effective auditable classes, ignored entries) of the policy's audit_classes list."""
    wanted = [c for c in policy.get("audit_classes") or [] if isinstance(c, str)]
    return frozenset(c for c in wanted if c in AUDITABLE), sorted({c for c in wanted if c not in AUDITABLE})


def cli_will_ask(cmd: str, prefixes: list[str]) -> bool:
    """True for a single plain command whose leading words match the CLI's own `ask` list (the CLI then prompts).
    The CLI ignores an `ask` decision from a PreToolUse hook (CLI 1.4.7), so approval must come from its own list."""
    try:
        segs = _segments(cmd)
    except ValueError:
        return False
    if len(segs) != 1 or any(c in cmd for c in ("$`\n%^" if WIN else "$`\n")):
        return False
    words = segs[0]
    if WIN:   # the CLI prefix match is on the literal command; compare case-insensitively on Windows
        words = [w.lower() for w in words]
        return any(words[:len(p.split())] == p.lower().split() for p in prefixes)
    return any(words[:len(p.split())] == p.split() for p in prefixes)


def seat_model_policy(group: str) -> tuple[list[str] | None, list[str]]:
    """(allowed patterns or None = no policy, helper models) from the root-owned policy file."""
    try:
        with open(POLICY_FILE, encoding="utf-8") as f:
            sm = json.load(f).get("seat_models") or {}
    except (OSError, ValueError):
        return None, []
    groups = sm.get("groups") or {}
    return (groups.get(group) if group in groups else None), list(sm.get("aux") or [])


def model_allowed(model: str, patterns: list[str] | None, aux: list[str] | None = None) -> bool:
    """Same rule as the prompt-log inspector: no policy -> allowed; helper model -> allowed; exact or prefix* match."""
    if patterns is None or not model:
        return True
    m = model.strip().lower()
    if m in {a.strip().lower() for a in (aux or [])}:
        return True
    return any((p.strip().lower().endswith("*") and m.startswith(p.strip().lower()[:-1])) or m == p.strip().lower()
               for p in patterns)


WRAPPERS = {"env", "command", "nohup", "time", "nice", "ionice", "stdbuf", "timeout", "xargs"}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
# Windows: shell -> flag that introduces an inline command string
WIN_SHELLS = {"cmd": ("/c", "/k"), "powershell": ("-command", "-c"), "pwsh": ("-command", "-c")}
WIN_WRAPPERS = {"start", "call", "&"}


def _base(tok: str) -> str:
    """Command name without directory (and, on Windows, without .exe / case)."""
    if not WIN:
        return os.path.basename(tok)
    b = ntpath.basename(tok.strip('"\'')).lower()
    return b[:-4] if b.endswith((".exe", ".com", ".bat", ".cmd")) else b


def _segments(cmd: str) -> list[list[str]]:
    """Shell-aware split into simple commands (;, &&, ||, |, &); raises ValueError on unparsable input.
    Windows: non-POSIX lexing (backslashes are path separators, not escapes); quotes are stripped from tokens."""
    lex = shlex.shlex(cmd, posix=not WIN, punctuation_chars=True)
    lex.whitespace_split = True
    segs, cur = [], []
    for tok in lex:
        if tok in (";", "&&", "||", "|", "&", ";;", "(", ")"):
            if cur:
                segs.append(cur)
            cur = []
        else:
            if WIN and len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
                tok = tok[1:-1]
            cur.append(tok)
    if cur:
        segs.append(cur)
    return segs


def _inline(toks: list[str]) -> str | None:
    """Inline command string of a nested shell (bash -c X / cmd /c X / powershell -Command X), else None."""
    head = _base(toks[0])
    if not WIN:
        return toks[toks.index("-c") + 1] if head in SHELLS and "-c" in toks[:-1] else None
    flags = WIN_SHELLS.get(head)
    if not flags:
        return None
    for i, t in enumerate(toks[1:-1], 1):
        if t.lower() in flags:
            return " ".join(toks[i + 1:])
    return None


def workspace_violation(cmd: str, names: list[str], workspace: str, cwd: str, depth: int = 0, home: str = "") -> str | None:
    """chmod/chown/chgrp (Windows: icacls/takeown) may only target paths inside the persona workspace.
    Fails closed on anything unclear."""
    if not names or not any(re.search(rf"(^|[^A-Za-z0-9_-]){re.escape(n)}([^A-Za-z0-9_-]|$)", cmd, re.I if WIN else 0)
                            for n in names):
        return None
    if not workspace or depth > 3:
        return f"{'/'.join(names)} not permitted here"
    p = _p()
    names_l = {n.lower() for n in names} if WIN else set(names)
    home = home or os.path.expanduser("~")
    ws = resolve(workspace, home)
    try:
        segs = _segments(cmd)
    except ValueError:
        return f"{'/'.join(names)}: command could not be verified"
    for toks in segs:
        i = 0
        wrappers = WIN_WRAPPERS if WIN else WRAPPERS
        while i < len(toks) and (_base(toks[i]) in wrappers or (not WIN and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]))
                                 or (i > 0 and _base(toks[i - 1]) == "timeout" and re.fullmatch(r"[0-9.]+[smhd]?", toks[i]))):
            i += 1
        toks = toks[i:]
        if not toks:
            continue
        head = _base(toks[0])
        inner = _inline(toks)
        if inner is not None:
            why = workspace_violation(inner, names, workspace, cwd, depth + 1, home)
            if why:
                return why
            continue
        if head not in names_l:
            if any(_base(t) in names_l or (WIN and t.split() and _base(t.split()[0]) in names_l) for t in toks[1:]):   # e.g. find ... -exec chmod / forfiles /c "icacls"
                return f"{head} {'/'.join(names)} indirection is not permitted - run it directly on workspace paths"
            continue
        if WIN:   # icacls <path> /grant ... ; takeown /f <path> [/r]
            if head == "takeown":
                paths = [toks[k + 1] for k, t in enumerate(toks[:-1]) if t.lower() == "/f"]
            else:
                paths = [t for t in toks[1:2] if not t.startswith(("/", "-"))]
                if any(t.lower() == "/restore" for t in toks):
                    return f"{head} /restore is not permitted"
            bad = "%!$`"
        else:
            ops = [t for t in toks[1:] if not t.startswith("-")]
            refs = [t.split("=", 1)[1] for t in toks[1:] if t.startswith("--reference=")]
            paths = refs + (ops if refs else ops[1:])          # first operand is the mode / owner
            bad = "$`"
        if not paths or any(c in t for t in paths for c in bad):
            return f"{head}: target could not be verified"
        for t in paths:
            full = resolve(t, home, cwd or ws)
            if not within(full, ws):
                return f"{head} outside your workspace ({ws}) is not permitted"
    return None


# ---- critical delete targets: recursive / forced deletion of the home folder, the workspace root (or its .git), a drive
# root or a system folder. Never auditable and never left to an approval prompt.
DELETE_HEADS = {"rm", "rmdir", "rd", "del", "erase", "remove-item", "ri", "rimraf", "find"}
RUNNERS = {"npx", "pnpx", "bunx"}
FIND_FILTERS = {"-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex", "-type", "-newer", "-mtime",
                "-mmin", "-size", "-empty", "-user", "-group", "-perm"}
SYSTEM_WITHIN_POSIX = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/System", "/Library")
SYSTEM_EXACT_POSIX = ("/var", "/opt", "/root", "/srv", "/tmp", "/private", "/Applications", "/home", "/Users")  # nosec B108 - protected paths for the delete guard, no temp file is used
SYSTEM_WITHIN_WIN = ("C:/Windows", "C:/Program Files", "C:/Program Files (x86)", "C:/ProgramData")
SYSTEM_EXACT_WIN = ("C:/Users",)
HOME_VARS = re.compile(r"(?i)^(?:\$\{?HOME\}?|%USERPROFILE%|\$env:USERPROFILE|\$env:HOME|%HOMEDRIVE%%HOMEPATH%)(?=$|[\\/])")
INLINE_DELETE = re.compile(r"(?:rmtree|rmSync|rmdirSync|removedirs|rm_rf)\s*\(([^)]*\)?)")


def _target_norm(raw: str, home: str) -> str:
    """Delete operand with home variables expanded and trailing separators / globs removed (~/* -> ~, C:\\* -> C:\\)."""
    s = HOME_VARS.sub(lambda _m: home, raw.strip().strip("'\""))
    if s in ("*", ".*", "./*", ".\\*"):
        return "."
    while True:
        n = re.sub(r"[\\/]+(?:\.?\*|\.)?$", "", s)
        if n == s:
            return s
        if not n or re.fullmatch(r"[A-Za-z]:", n):
            return "/" if not n else n + "\\"
        s = n


def critical_target(raw: str, home: str, workspace: str, cwd: str) -> str | None:
    """Why deleting this operand is critical (home, workspace root / .git, drive root, system folder), else None."""
    s = _target_norm(raw, home)
    if not s or "$" in s or "%" in s:
        return None   # unknown variable: not decidable here
    p = _p()
    t = resolve(s, home, cwd)

    def r(x: str) -> str:
        return resolve(x, home)

    if t == r(home):
        return "your home folder"
    if workspace:
        ws = r(workspace)
        if t == ws:
            return "the workspace root"
        if t == p.join(ws, ".git") or t == r(p.join(workspace, ".git")):
            return "the workspace repository (.git)"
    if p.dirname(t) == t:
        return "a drive / file-system root"
    if within(t, r(home)) or (workspace and within(t, r(workspace))):
        return None   # below the home folder / workspace root: ordinary destructive command (macOS: /System/Volumes/Data)
    within_l, exact_l = (SYSTEM_WITHIN_WIN, SYSTEM_EXACT_WIN) if WIN else (SYSTEM_WITHIN_POSIX, SYSTEM_EXACT_POSIX)
    if any(within(t, r(x)) for x in within_l) or any(t == r(x) for x in exact_l):
        return f"a system folder ({s})"
    if any(p.dirname(t) == r(x) for x in (("C:/Users",) if WIN else ("/home", "/Users"))):
        return "a user profile folder"
    return None


def critical_delete(cmd: str, home: str, workspace: str, cwd: str, depth: int = 0) -> str | None:
    """Denial reason when a recursive / forced delete targets a critical folder (see critical_target), else None."""
    if depth > 3:
        return None
    try:
        segs = _segments(cmd)
    except ValueError:
        return None
    wrappers = WIN_WRAPPERS if WIN else WRAPPERS
    for toks in segs:
        i = 0
        while i < len(toks) and (_base(toks[i]) in wrappers or _base(toks[i]) in RUNNERS or toks[i] == "sudo"
                                 or (not WIN and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]))):
            i += 1
        toks = toks[i:]
        if not toks:
            continue
        inner = _inline(toks)
        if inner is not None:
            why = critical_delete(inner, home, workspace, cwd, depth + 1)
            if why:
                return why
            continue
        head = _base(toks[0])
        if re.fullmatch(r"python[0-9.]*|py|node", head):
            code = " ".join(toks[1:])
            for m in INLINE_DELETE.finditer(code):
                args = m.group(1)
                lits = re.findall(r"['\"]([^'\"]*)['\"]", args)
                if re.search(r"Path\.home\(\)|os\.homedir\(\)|expanduser\(\s*['\"]~['\"]\s*\)", args):
                    lits.append("~")
                for lit in lits:
                    why = critical_target(lit, home, workspace, cwd)
                    if why:
                        return f"deleting {why} is not permitted - the agent may never do this"
            continue
        if head not in DELETE_HEADS:
            continue
        if head == "find" and any(t.lower() in FIND_FILTERS for t in toks):
            continue   # find with a filter deletes matches only
        for t in toks[1:]:
            if t.startswith("-") or (WIN and re.fullmatch(r"/[A-Za-z?]{1,2}", t)) or t in ("{}", "+", ";", "\\;"):
                continue
            why = critical_target(t, home, workspace, cwd)
            if why:
                return f"deleting {why} is not permitted - the agent may never do this"
    return None


def decide(call: dict[str, Any], policy: dict[str, Any], home: str, user: str = "") -> tuple[str, str] | None:
    """('deny' | 'cli_ask', reason), or None when the call is allowed by this policy."""
    ex = decide_ex(call, policy, home, user)
    return (ex[0], ex[1]) if ex else None


def decide_ex(call: dict[str, Any], policy: dict[str, Any], home: str, user: str = "",
              audit: frozenset[str] = frozenset()) -> tuple[str, str, str] | None:
    """('deny' | 'cli_ask', reason, rule class), or None when the call is allowed by this policy.

    Without audit classes this is the first matching rule (same result as decide). With audit classes, a deny of an
    audited class does not end the evaluation: the remaining rules still run, so a call that also matches an enforced
    rule (e.g. a protected path) is denied by that rule. The audited deny is returned only when nothing else matches."""
    audited: tuple[str, str, str] | None = None
    for hit in _decisions(call, policy, home, user):
        if hit[0] == "deny" and hit[2] in audit:
            audited = audited or hit
            continue
        return hit
    return audited


def _decisions(call: dict[str, Any], policy: dict[str, Any], home: str, user: str) -> Iterator[tuple[str, str, str]]:
    """Every matching rule (verdict, reason, rule class) in evaluation order; lazily, so the first hit costs no more
    than before."""
    yield from (("deny", why, cls) for why, cls in _evaluations(call, policy, home))
    for check, cls in ((lambda: config_dir_violation(call, policy, home, user), "config_dir"),
                       (lambda: exec_config_violation(call, policy, home, user), "exec_config"),
                       (lambda: cloud_identity_violation(call, policy), "cloud_identity"),
                       (lambda: secret_content_violation(call, policy), "secret_content")):
        why = check()
        if why:
            yield "deny", why, cls
    args = call.get("args") or {}
    ws_scope = policy.get("workspace", "").replace("{user}", user)
    wt = policy.get("write_tools", "")
    if wt and ws_scope and re.search(wt, str(call.get("name", "")), re.I):
        # agent file writes stay inside the persona workspace (plus explicitly allowed extras); fails closed
        roots = [resolve(x.replace("{user}", user), home) for x in [ws_scope] + policy.get("write_also", [])]
        for raw in path_args(args):   # no path argument = not a file-system write (e.g. memory / task tools)
            full = resolve(raw, home)
            if not any(within(full, r) for r in roots):
                yield "deny", f"writes outside your workspace ({roots[0]}) are not permitted", "workspace_write"
                break
    if call.get("name", "") == "run_command":
        cmd = str(args.get("CommandLine", ""))
        ws = ws_scope
        w = workspace_violation(cmd, policy.get("workspace_only_commands", []), ws,
                                str(args.get("Cwd") or args.get("cwd") or ws), home=home)
        if w:
            yield "deny", w, "workspace_commands"
        for pat in policy.get("ask_commands", []):
            if re.search(pat, cmd, re.I if WIN else 0):
                crit = critical_delete(cmd, home, ws, str(args.get("Cwd") or args.get("cwd") or ws))
                if crit:   # home / workspace root / system folders: always denied, never audited or left to a prompt
                    yield "deny", crit, "destructive_critical"
                    break
                # in-session Auto mode is invisible to hooks (verified 2026-10-29: no mode field in the payload) and
                # approves "safe" commands without a human - so destructive commands are not left to the CLI prompt
                if policy.get("ask_as_deny"):
                    yield "deny", ("destructive command - run it yourself in your terminal (the agent may not, because "
                                   "an approval prompt can be skipped by Auto mode)"), "destructive"
                elif cli_will_ask(cmd, policy.get("cli_ask_prefixes", [])):
                    yield "cli_ask", "destructive command - the CLI asks for your approval", "destructive"
                else:
                    yield "deny", ("destructive command in a wrapped or indirect form - run it directly as a single "
                                   "command (e.g. rm -r <path>) so you can approve it"), "destructive"
                break


def evaluate(call: dict[str, Any], policy: dict[str, Any], home: str) -> str | None:
    """Return a denial reason, or None when the call is allowed by this policy."""
    return next((why for why, _ in _evaluations(call, policy, home)), None)


def evaluate_ex(call: dict[str, Any], policy: dict[str, Any], home: str) -> tuple[str, str] | None:
    """(denial reason, rule class) of the first matching evaluate rule, or None."""
    return next(_evaluations(call, policy, home), None)


def _evaluations(call: dict[str, Any], policy: dict[str, Any], home: str) -> Iterator[tuple[str, str]]:
    """Every matching evaluate rule as (denial reason, rule class), in evaluation order (lazily)."""
    name, args = call.get("name", ""), call.get("args") or {}
    for pat in policy["deny_tools"]:
        if re.fullmatch(pat, name, re.I if WIN else 0):
            yield f"tool {name} not permitted", "tools"
            break
    why = mcp_violation(call, policy)
    if why:
        yield why, "tools"
    if name == "run_command" and policy.get("deny_sandbox_bypass") and \
            str(args.get("BypassSandbox", args.get("bypassSandbox", ""))).strip().lower() in ("true", "1", "yes"):
        yield "running a command outside the terminal sandbox is not permitted", "sandbox_bypass"
    if name == "run_command":
        cmd = str(args.get("CommandLine", ""))
        for pat in policy["deny_commands"]:
            if re.search(pat, cmd, re.I if WIN else 0):
                yield "command not permitted by corporate policy", "commands"
                break
    # secret files by name (.env, .env.local ...), anywhere: the terminal sandbox blocks them on Linux / Windows 11;
    # the hook covers platforms without a sandbox and the agent's own file tools (templates such as .env.example pass)
    why = secret_file(call, policy)
    if why:
        yield why, "secret_files"
    # every path-like argument of any tool (tool and argument names differ between CLI, App and IDE:
    # e.g. CLI read_file{Path}, docs view_file{AbsolutePath}); for run_command also the path-like words of the command
    raws = path_args(args)
    if name == "run_command":
        raws += command_paths(str(args.get("CommandLine", "")))
    for raw in raws:
        path = resolve(raw, home)
        for p in policy["deny_paths"]:
            prot = resolve(p, home)
            if within(path, prot):
                yield f"path {prot} is protected", "paths"
                return


WRITE_CMDS = {"mkdir", "md", "new-item", "ni", "set-content", "add-content", "ac", "out-file", "tee", "tee-object", "touch",
              "cp", "copy", "copy-item", "cpi", "xcopy", "robocopy", "mv", "move", "move-item", "mi", "ren", "rename",
              "rename-item", "rni", "install", "ln", "mklink", "rsync", "unzip", "expand-archive", "tar", "sed", "perl"}


def _has_config_dir(raw: str, names: set[str]) -> bool:
    parts = [x for x in re.split(r"[\\/]", raw.strip("'\"")) if x]
    return any((x.lower() if WIN else x) in names for x in parts)


def config_dir_violation(call: dict[str, Any], policy: dict[str, Any], home: str, user: str, depth: int = 0) -> str | None:
    """Agent writes into agent / editor configuration folders (.agents, .gemini, ...) anywhere - incl. the workspace -
    would let it change its own rules, skills, plugins or project-level overrides. Reading stays allowed."""
    names = {(n.lower() if WIN else n) for n in (policy.get("deny_write_dirnames") or [])}
    if not names or depth > 3:
        return None
    args = call.get("args") or {}
    roots = [resolve(x.replace("{user}", user), home) for x in policy.get("write_also", [])]   # e.g. the CLI brain
    wt = policy.get("write_tools", "")
    msg = "writing agent or editor configuration ({}) is not permitted - edit it yourself if needed"
    if wt and re.search(wt, str(call.get("name", "")), re.I):
        for raw in path_args(args):
            if _has_config_dir(raw, names) and not any(within(resolve(raw, home), r) for r in roots):
                return msg.format(raw)
    if call.get("name", "") != "run_command":
        return None
    cmd = str(args.get("CommandLine", ""))
    try:
        segs = _segments(cmd)
    except ValueError:
        return None
    for toks in segs:
        if not toks:
            continue
        inner = _inline(toks)
        if inner is not None:
            why = config_dir_violation({"name": "run_command", "args": {"CommandLine": inner}}, policy, home, user, depth + 1)
            if why:
                return why
            continue
        writeish = _base(toks[0]) in WRITE_CMDS
        targets = [t for i, t in enumerate(toks[1:], 1) if not t.startswith("-") and (writeish or toks[i - 1] in (">", ">>"))]
        targets += [t.lstrip(">") for t in toks if t.startswith(">") and len(t.lstrip(">")) > 0]
        for t in targets:
            if _has_config_dir(t, names) and not any(within(resolve(t, home, ""), r) for r in roots if _p().isabs(t)):
                return msg.format(t)
    return None


def _glob_hit(raw: str, globs: list[str]) -> bool:
    """Path (absolute or relative) matches a deny_write_files glob. One-part globs match the file name; multi-part
    globs match consecutive path parts ending at the file name; a trailing '**' matches anything below the folder.
    Case-insensitive on every OS: the tools reading these files (NuGet, MSBuild, IDEs) often are, so fail closed."""
    parts = [x.lower() for x in re.split(r"[\\/]", raw.strip("'\"")) if x and x != "."]
    if not parts:
        return False
    for g in globs:
        gp = [x.lower() for x in g.split("/") if x]
        if not gp:
            continue
        if gp[-1] == "**":
            k = len(gp) - 1
            if any(all(fnmatch.fnmatchcase(parts[i + j], gp[j]) for j in range(k)) for i in range(len(parts) - k)):
                return True
        elif len(gp) <= len(parts) and all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts[-len(gp):], gp)):
            return True
    return False


def _content_strings(args: Any) -> list[str]:
    """New file content of a write / edit tool call (argument names differ between CLI, App and IDE)."""
    out: list[str] = []
    if isinstance(args, dict):
        for k, v in args.items():
            if isinstance(v, str) and re.search(r"content|replacement|new_?str|text|code|patch|diff", k, re.I):
                out.append(v)
            elif isinstance(v, (dict, list)):
                out += _content_strings(v)
    elif isinstance(args, list):
        for v in args:
            out += _content_strings(v)
    return out


def _write_targets(toks: list[str]) -> list[str]:
    writeish = _base(toks[0]) in WRITE_CMDS
    targets = [t for i, t in enumerate(toks[1:], 1) if not t.startswith("-") and (writeish or toks[i - 1] in (">", ">>"))]
    return targets + [t.lstrip(">") for t in toks if t.startswith(">") and len(t.lstrip(">")) > 0]


def exec_config_violation(call: dict[str, Any], policy: dict[str, Any], home: str, user: str, depth: int = 0) -> str | None:
    """Agent writes to configuration that executes code or redirects the supply chain (git hooks / config, package
    manager config, IDE tasks, MSBuild props / targets, CI workflows, dev containers, agent rules / MCP config), and
    build-time code added to project files (<Exec>, <UsingTask>, npm lifecycle scripts). One prompt injection would
    otherwise give persistence or a supply-chain change. The developer edits these files manually."""
    if depth > 3:
        return None
    globs = policy.get("deny_write_files") or []
    cfiles, cpats = policy.get("exec_content_files") or [], policy.get("exec_content_patterns") or []
    flags = re.I if WIN else 0
    msg = "the agent may not change {} (configuration that runs code or changes package sources) - edit it yourself"
    cmsg = "the agent may not add build-time code ({}) to {} - edit it yourself"
    name, args = str(call.get("name", "")), call.get("args") or {}
    wt = policy.get("write_tools", "")
    if wt and re.search(wt, name, re.I):
        paths = path_args(args)
        for raw in paths:
            if _glob_hit(raw, globs):
                return msg.format(raw)
        if any(_glob_hit(raw, cfiles) for raw in paths):
            for text in _content_strings(args):
                for pat in cpats:
                    m = re.search(pat, text, flags)
                    if m:
                        return cmsg.format(m.group(0).strip(), next(r for r in paths if _glob_hit(r, cfiles)))
    if name != "run_command":
        return None
    cmd = str(args.get("CommandLine", ""))
    for pat in policy.get("deny_config_commands") or []:
        if re.search(pat, cmd, flags):
            return "the agent may not change git / package sources or open a tunnel - run it yourself if needed"
    try:
        segs = _segments(cmd)
    except ValueError:
        return None
    for toks in segs:
        if not toks:
            continue
        inner = _inline(toks)
        if inner is not None:
            why = exec_config_violation({"name": "run_command", "args": {"CommandLine": inner}}, policy, home, user, depth + 1)
            if why:
                return why
            continue
        for t in _write_targets(toks):
            if _glob_hit(t, globs):
                return msg.format(t)
            if _glob_hit(t, cfiles):
                for pat in cpats:
                    m = re.search(pat, cmd, flags)
                    if m:
                        return cmsg.format(m.group(0).strip(), t)
    return None


CLOUD_CLIS = {"gcloud", "bq", "gsutil", "terraform"}
IMPERSONATE_ENV = ("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT")


def cloud_identity_violation(call: dict[str, Any], policy: dict[str, Any], depth: int = 0) -> str | None:
    """Agent use of Google Cloud CLIs: never mint / export tokens or change gcloud configuration, and - when the
    persona has an agent service account - run only as that account (gcloud --impersonate-service-account=<sa>, or
    CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT / GOOGLE_IMPERSONATE_SERVICE_ACCOUNT=<sa> for bq, gsutil, terraform).
    The human's own session keeps its normal (PAM-elevated) rights; the agent gets the agent tier's rights only."""
    if call.get("name", "") != "run_command" or depth > 3:
        return None
    cmd = str((call.get("args") or {}).get("CommandLine", ""))
    sa = policy.get("agent_service_account", "").strip().lower()
    verbs = [v.lower().split() for v in policy.get("gcloud_deny_verbs") or []]
    try:
        segs = _segments(cmd)
    except ValueError:
        return "cloud CLI command could not be verified" if re.search(r"gcloud|\bbq\b|gsutil|terraform", cmd, re.I) else None
    env_sa = {m.group(2).lower() for m in re.finditer(
        r"(?:\$env:)?(" + "|".join(IMPERSONATE_ENV) + r")\s*=\s*['\"]?([\w.@-]+)", cmd, re.I)}
    for toks in segs:
        i = 0
        while i < len(toks) and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[i]) or _base(toks[i]) in WRAPPERS | WIN_WRAPPERS):
            i += 1
        toks = toks[i:]
        if not toks:
            continue
        inner = _inline(toks)
        if inner is not None:
            why = cloud_identity_violation({"name": "run_command", "args": {"CommandLine": inner}}, policy, depth + 1)
            if why:
                return why
            continue
        head = _base(toks[0])
        if head not in CLOUD_CLIS:
            continue
        words = [t.lower() for t in toks[1:] if not t.startswith("-")]
        for v in verbs:
            if any(words[j:j + len(v)] == v for j in range(len(words))):
                return f"the agent may not run '{head} {' '.join(v)}' (tokens, keys and gcloud configuration stay with you)"
        if not sa or (head == "terraform" and not (words and words[0] in ("plan", "apply", "destroy", "import", "refresh", "state"))):
            continue
        flag_sa = {t.split("=", 1)[1].lower() for t in toks if t.lower().startswith("--impersonate-service-account=")}
        flag_sa |= {toks[k + 1].lower() for k, t in enumerate(toks[:-1]) if t.lower() == "--impersonate-service-account"}
        used = flag_sa | env_sa
        if used != {sa}:
            how = f"--impersonate-service-account={sa}" if head == "gcloud" else f"{IMPERSONATE_ENV[0 if head != 'terraform' else 1]}={sa}"
            return f"agent {head} commands must run as the agent service account ({how})"
    return None


MCP_GENERIC_TOOLS = {"call_mcp_tool", "list_resources", "read_resource"}
MCP_SERVER_ARGS = ("ServerName", "server_name", "serverName", "server")


def _mcp_norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", s.strip().lower())


def mcp_violation(call: dict[str, Any], policy: dict[str, Any]) -> str | None:
    """Denial reason for a tool call to an MCP server that is not on mcp_allowed_servers. MCP calls arrive as generic
    tools with a server argument (call_mcp_tool{ServerName}, list_resources, read_resource) or as tools named
    mcp_<server>_<tool>; both are checked. No allowlist key in the policy = no check; '*' = every server."""
    allowed = policy.get("mcp_allowed_servers")
    if allowed is None or "*" in allowed:
        return None
    ok = {_mcp_norm(a) for a in allowed if a.strip()}
    name, args = str(call.get("name", "")), call.get("args") or {}
    if name.lower() in MCP_GENERIC_TOOLS:
        server = next((str(args[k]) for k in MCP_SERVER_ARGS if isinstance(args, dict) and args.get(k)), "")
        if not server:
            return f"MCP call {name} without a server name is not permitted"
        return None if _mcp_norm(server) in ok else f"MCP server {server} is not on the approved list"
    m = re.match(r"(?i)mcp_+(.+)", name)
    if m and not any(_mcp_norm(m.group(1)).startswith(s + "_") for s in ok):
        return f"MCP server tool {name} is not on the approved list (server {m.group(1).split('_')[0]})"
    return None


def secret_content_violation(call: dict[str, Any], policy: dict[str, Any]) -> str | None:
    """Agent file writes / edits whose new content contains a credential (deny_write_secrets: {name, regex}). Secrets
    in files end up in commits, backups and prompts; they belong in a secret manager."""
    rules = policy.get("deny_write_secrets") or []
    wt = policy.get("write_tools", "")
    if not rules or not wt or not re.search(wt, str(call.get("name", "")), re.I):
        return None
    texts = _content_strings(call.get("args") or {})
    for rule in rules:
        pat = str(rule["regex"])
        if any(re.search(pat, t) for t in texts):
            return f"the agent may not write a secret ({rule.get('name', 'credential')}) into a file - use a secret manager"
    return None


def secret_file(call: dict[str, Any], policy: dict[str, Any]) -> str | None:
    """Denial reason when a tool call names a secret file (deny_file_globs, minus allow_file_globs)."""
    deny, allow = policy.get("deny_file_globs") or [], policy.get("allow_file_globs") or []
    if not deny:
        return None
    args = call.get("args") or {}
    names = list(path_args(args))
    if call.get("name", "") == "run_command":
        cmd = str(args.get("CommandLine", ""))
        try:
            words = [w for seg in _segments(cmd) for w in seg]
        except ValueError:
            words = cmd.split()
        todo = [part.strip("'\"") for w in words for part in re.split(r"[=<>]", w) if part]
        while todo:                       # nested shell strings: bash -c "source .env && env"
            part = todo.pop()
            if any(c.isspace() for c in part) and len(names) < 2000:
                if part.startswith(("/", "~", "./")) or re.match(r"^([A-Za-z]:[\\/]|\\\\)", part):
                    names.append(part)    # quoted / escaped path with spaces: the file name is its last part
                try:
                    todo += [x.strip("'\"") for seg in _segments(part) for w in seg for x in re.split(r"[=<>]", w) if x]
                except ValueError:
                    todo += part.split()
            else:
                names.append(part)
    for raw in names:
        base = re.split(r"[\\/]", raw.rstrip("\\/"))[-1]
        b = base.lower() if WIN else base
        if any(fnmatch.fnmatchcase(b, g.lower() if WIN else g) for g in deny) and \
                not any(fnmatch.fnmatchcase(b, g.lower() if WIN else g) for g in allow):
            return f"secret file {base} is protected (use your own editor; the agent may not read or copy it)"
    return None


def command_paths(cmd: str) -> list[str]:
    """Path-like words of a shell command (also inside nested shells and after '=' / redirections), so protected
    paths in a command line are refused by the hook too - not only by file permissions and AppArmor."""
    try:
        words = [w for seg in _segments(cmd) for w in seg]
    except ValueError:
        words = cmd.split()
    out: list[str] = []
    for w in words:
        for part in re.split(r"[=<>]", w):
            part = part.strip("'\"")
            # a quoted / escaped path keeps its spaces ("~/Library/Application Support/..."): check it whole, and
            # still split it as a nested shell string (bash -c "cat /x")
            if part.startswith(("/", "~")) or re.match(r"^([A-Za-z]:[\\/]|\\\\)", part):
                out.append(part)
            if " " in part:                      # nested shell string: bash -c "cat /x"
                out += command_paths(part)
    return out


def path_args(args: Any) -> list[str]:
    """String values (nested) that look like file-system paths."""
    out: list[str] = []
    if isinstance(args, dict):
        for k, v in args.items():
            if k in ("CommandLine", "toolSummary", "Description", "Instruction", "CodeContent", "ReplacementContent",
                     "TargetContent", "Query", "Prompt"):
                continue
            out += path_args(v)
    elif isinstance(args, list):
        for v in args:
            out += path_args(v)
    elif isinstance(args, str):
        s = args.strip().strip('"')
        if (s.startswith(("/", "~")) or re.match(r"^([A-Za-z]:[\\/]|\\\\)", s)) and "\n" not in s and len(s) < 4096:
            out.append(s)
    return out


def sandbox_failure(transcript: str, tail: int = 8192) -> str | None:
    """The terminal-sandbox error of the latest tool result (end of the CLI transcript), else None."""
    if not transcript:
        return None
    try:
        with open(transcript, "rb") as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - tail))
            chunk = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    m = re.findall(r"exebox: [^\\\n\"]{0,200}", chunk)
    return m[-1] if m else None


def _state_dir() -> str:
    """Per-user private state folder (never a shared temp dir: predictable names there invite symlink attacks)."""
    base = os.environ.get("LOCALAPPDATA") if WIN else (os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"))
    d = os.path.join(base or os.path.expanduser("~"), "agy-hook")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def report_sandbox_failure(data: dict[str, Any], conv: str) -> None:
    """Log SANDBOX_FAILURE once per new sandbox error in this conversation (de-duplicated via a per-user state file;
    the file only suppresses repeats, it is not a control)."""
    try:
        sb = sandbox_failure(str(data.get("transcriptPath") or ""))
        if not sb:
            return
        safe = re.sub(r"[^A-Za-z0-9_-]", "", conv)[:64] or "none"   # conversation id comes from the payload
        state = os.path.join(_state_dir(), f"sbx-{safe}.txt")
        size = os.path.getsize(str(data.get("transcriptPath")))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(state, flags)
            with os.fdopen(fd, encoding="utf-8") as f:
                seen = f.read().split("|", 1)
        except OSError:
            seen = ["", ""]
        if len(seen) == 2 and seen[1] == sb and int(seen[0] or 0) >= size - 16384:
            return   # same error already reported for this part of the transcript
        fd = os.open(state, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{size}|{sb}")
        log("SANDBOX_FAILURE", conversation=conv, error=sb)
    except Exception as e:  # noqa: BLE001 - reporting must never break the session
        log("HOOK_ERROR", hook="sandbox_failure", error=type(e).__name__)


def main() -> int:
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError:
        data = {}
    conv = data.get("conversationId", "")
    if event == "PreToolUse":
        call = data.get("toolCall") or {}
        verdict: tuple[str, str] | None
        rule, audit = "", frozenset[str]()
        try:
            policy = load_policy(group_name())
            es = elevated_session(policy)
            rb = None if es else review_bypass(data, policy)
            if es or rb:   # never auditable: decided before the rule classes
                verdict, rule = ("deny", str(es or rb)), ("elevated_session" if es else "review_bypass")
            else:
                audit, ignored = audit_classes(policy)
                if ignored:   # critical / tamper / unknown classes stay enforced
                    log("AUDIT_CLASS_IGNORED", classes=ignored, auditable=sorted(AUDITABLE), conversation=conv)
                ex = decide_ex(call, policy, os.path.expanduser("~"), current_user(), audit)
                verdict, rule = ((ex[0], ex[1]), ex[2]) if ex else (None, "")
            if es:
                log("ELEVATED_SESSION", reason=es, conversation=conv)
            elif rb:
                log("REVIEW_BYPASS_ATTEMPT", reason=rb, conversation=conv)
        except Exception as e:  # noqa: BLE001 - fail closed
            verdict, rule, audit = ("deny", f"policy hook error ({type(e).__name__})"), "hook_error", frozenset[str]()
        target = str((call.get("args") or {}).get("CommandLine") or next(iter((call.get("args") or {}).values()), ""))[:200]
        audited = bool(verdict and verdict[0] == "deny" and rule in audit and rule not in NON_AUDITABLE)
        if audited and verdict:
            # audit mode: what would have been denied is recorded and allowed (tuning of noisy rule classes)
            log("AUDIT_ALLOW", tool=call.get("name"), rule=rule, reason=verdict[1], conversation=conv, target=target)
            print(json.dumps({"decision": "allow"}))
        elif verdict and verdict[0] == "deny":
            log("DENY", tool=call.get("name"), rule=rule, reason=verdict[1], conversation=conv, target=target)
            print(json.dumps({"decision": "deny", "reason": f"Blocked by corporate policy: {verdict[1]}."}))
        elif verdict:   # cli_ask: allowed through so the CLI's own ask rule prompts the user
            log("ASK_VIA_CLI", tool=call.get("name"), reason=verdict[1], conversation=conv, target=target)
            print(json.dumps({"decision": "allow"}))
        else:
            print(json.dumps({"decision": "allow"}))
        if os.environ.get("AGY_HOOK_TRACE") == "1":   # test harnesses only (attack pack): stderr, never stdout
            print(json.dumps({"trace": {"verdict": verdict[0] if verdict else "allow", "rule": rule,
                                        "audited": audited}}), file=sys.stderr)
    elif event == "PostToolUse":
        call = data.get("toolCall") or {}
        args = call.get("args") or {}
        target = args.get("CommandLine") or next(iter(path_args(args)), "") or ""
        log("TOOL", tool=call.get("name"), target=str(target)[:200], error=bool(data.get("error")), conversation=conv,
            keys=sorted(data.keys())[:30])
        # the terminal sandbox can fail on a device even where the OS supports it (e.g. no virtualization-based
        # security): the error only appears in the tool result, which the hook reads from the transcript tail
        if call.get("name") == "run_command":
            report_sandbox_failure(data, conv)
        print("{}")
    elif event == "SessionStart":
        # payload_keys: which fields the client sends (e.g. a permission / agent mode) - tunes review_bypass_payload
        log("SESSION", conversation=conv, model=data.get("modelName"), workspaces=data.get("workspacePaths"),
            payload_keys=sorted(data.keys())[:40])
        try:
            pol = load_policy(group_name())
            es = elevated_session(pol)
            if es:
                log("ELEVATED_SESSION", reason=es, conversation=conv, phase="session")
            rb = review_bypass(data, pol)
            if rb:
                log("REVIEW_BYPASS_ATTEMPT", reason=rb, conversation=conv, phase="session")
        except Exception as e:  # noqa: BLE001 - never break the session here; PreToolUse fails closed
            log("HOOK_ERROR", hook="SessionStart", error=type(e).__name__)
        print("{}")
    elif event == "PreInvocation":
        # the tool result may reach the transcript after PostToolUse: check again before the next model call
        report_sandbox_failure(data, conv)
        # Seat model policy: observe and (optionally) notify. The CLI does not support blocking here, so this is a
        # detective control; the preventive control is the Gemini Enterprise authorized-models list.
        model = str(data.get("modelName") or "")
        try:
            patterns, aux = seat_model_policy(group_name())
            ok = model_allowed(model, patterns, aux)
        except Exception as e:  # noqa: BLE001 - never break the session; record the failure
            log("HOOK_ERROR", hook="PreInvocation", error=type(e).__name__)
            print("{}")
            return 0
        log("MODEL" if ok else "MODEL_OFF_POLICY", model=model, conversation=conv,
            invocation=data.get("invocationNum"), policy="off" if patterns is None else "on")
        # No injectSteps: in-session notices were not delivered to the model in live tests, and an unrecognised
        # injected step aborts the user's run - so this hook only records (fail-safe for availability).
        print("{}")
    else:
        print("{}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
