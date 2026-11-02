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

"""agy-credproxy - local credential proxy for Antigravity Enterprise Gateway mode (pattern C).

Antigravity (admin_settings.json: gateway.url=http://127.0.0.1:8443, placeholder apiKey) talks to this
proxy. The client holds NO usable secret. For every connection the proxy:
  1. derives the caller's identity from the kernel (peer uid of the loopback socket via /proc/net/tcp; Windows: TCP
     owner process token; macOS: owning process of the client socket via lsof), maps it to user + persona group and
     rejects anything outside the managed groups (fail closed when the owner can't be determined);
  2. attaches a Google-signed GCE instance identity token (device proof; managed users cannot fetch it
     because nftables blocks them from the metadata server);
  3. forwards to the corporate gateway over TLS, streaming the response back.

Managed-policy readiness gate (AGY_REQUIRE_MANAGED_POLICY, default on): a persona's read-only settings.json and
hooks.json are written by the policy run (Linux: boot / timer; Windows: AGY-Policy at logon and every 5 min). Until
they are in place the client would run without the corporate hook, so model calls are refused (503 POLICY_NOT_READY)
until the caller's managed files exist and are locked (macOS: root-owned + system-immutable flag); on Windows and
macOS the policy run is started at once (rate-limited).

Certificate-only mode (AGY_DEVICE_AUTH=cert, for laptops / CI runners without a Compute Engine identity): step 2 is
skipped; the device proves itself only with its fleet certificate in the mTLS handshake, and the gateway takes
user and group from its device registry (what this proxy asserts is recorded for audit only).

Runs as the dedicated system user `agy-credproxy` (systemd hardening in agy-credproxy.service); on macOS as a root
LaunchDaemon (com.google.agy.credproxy, certificate-only by default). Stdlib only, Python 3.9+.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import ssl
import stat
import subprocess  # nosec B404 - fixed argv (schtasks / launchctl / lsof), no shell
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WIN = os.name == "nt"
DARWIN = sys.platform == "darwin"
if not WIN:
    import grp
    import pwd
_PD = os.environ.get("ProgramData", r"C:\ProgramData")
_MAC = "/Library/Application Support/Antigravity"   # macOS: root-owned config (credproxy/: device.crt, device.key, root.pem)
_CP = os.path.join(_PD, "Antigravity", "credproxy") if WIN else os.path.join(_MAC, "credproxy") if DARWIN else "/etc/agy-credproxy"
_GW_FILE = os.path.join(_PD, "Antigravity", "gateway_url") if WIN else os.path.join(_MAC, "gateway_url") if DARWIN else "/etc/antigravity/gateway_url"

LISTEN_PORT: int = int(os.environ.get("AGY_CREDPROXY_PORT", "8443"))
DEVICE_AUTH: str = os.environ.get("AGY_DEVICE_AUTH", "cert" if DARWIN else "gce")   # gce | cert
GATEWAY_URL_FILE: str = os.environ.get("AGY_GATEWAY_URL_FILE", _GW_FILE)
AUDIENCE: str = os.environ.get("AGY_DEVICE_AUDIENCE", "agy-gateway")
MANAGED_GROUPS: frozenset[str] = frozenset(os.environ.get("AGY_MANAGED_GROUPS", "agy-dev,agy-contractor").split(","))
CLIENT_CERT: str = os.environ.get("AGY_CLIENT_CERT", os.path.join(_CP, "device.crt"))
CLIENT_KEY: str = os.environ.get("AGY_CLIENT_KEY", os.path.join(_CP, "device.key"))
GATEWAY_CA: str = os.environ.get("AGY_GATEWAY_CA", os.path.join(_CP, "root.pem"))
PERSONA_GROUPS: str = os.path.join(_PD, "Antigravity", "persona-groups.json")   # Windows: group SID -> persona
REQUIRE_POLICY: bool = os.environ.get("AGY_REQUIRE_MANAGED_POLICY", "on").strip().lower() not in ("0", "off", "false", "no")
# managed per-user files that must be locked before the persona's client may call the model (relative to home)
MANAGED_FILES: tuple[str, ...] = (os.path.join(".gemini", "antigravity-cli", "settings.json"), os.path.join(".gemini", "config", "hooks.json"))
ENROLLMENT_DIR = "/etc/antigravity/enrollment"   # Linux first-run window: the user's settings copy is writable on purpose
# Linux: the proxy runs with ProtectHome (no view of /home); the host mount table shows the read-only policy mounts
MOUNTINFO: tuple[str, ...] = ("/proc/1/mountinfo", "/proc/self/mountinfo")
ADMIN_OWNERS = frozenset({"S-1-5-18", "S-1-5-32-544"})   # Windows: SYSTEM, Administrators
READY_TTL = 60.0     # positive readiness results are cached per user (seconds)
KICK_EVERY = 60.0    # Windows: start AGY-Policy at most once per user per interval (seconds)
POLICY_TASK = "AGY-Policy"
MAC_POLICY_JOB = "system/com.google.agy.policy"   # macOS policy LaunchDaemon (kickstarted when files are not ready)
LSOF = "/usr/sbin/lsof"
LAUNCHCTL = "/bin/launchctl"
NOT_READY_MSG = "AGY policy not applied yet for this user - it applies within a minute of sign-in; try again"
MD_URL = ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
          f"?audience={urllib.parse.quote(AUDIENCE)}&format=full")
DROP = frozenset({"host", "authorization", "connection", "keep-alive", "transfer-encoding", "content-length",
                  "proxy-authorization", "te", "upgrade", "x-agy-device-token", "x-agy-user", "x-agy-group", "x-agy-device-cert",
                  "accept-encoding"})
_tok_lock = threading.Lock()
_tok: tuple[str, float] = ("", 0.0)
_gate_lock = threading.Lock()
_ready_until: dict[str, float] = {}
_kicked_at: dict[str, float] = {}


def log(event: str, **kw: object) -> None:
    print(json.dumps({"event": event, "component": "agy-credproxy", **kw}), flush=True)


def device_token() -> str:
    """Cached GCE identity token (valid 1h; refreshed at 50 min)."""
    global _tok
    with _tok_lock:
        if _tok[0] and _tok[1] > time.time():
            return _tok[0]
        req = urllib.request.Request(MD_URL, headers={"Metadata-Flavor": "Google"})
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310  # nosec B310 - fixed metadata-server URL constant
            token = r.read().decode()
        _tok = (token, time.time() + 3000)
        return token


def peer_uid(client_port: int) -> int | None:
    """uid owning the loopback socket 127.0.0.1:<client_port> -> 127.0.0.1:LISTEN_PORT."""
    want_local, want_remote = f"0100007F:{client_port:04X}", f"0100007F:{LISTEN_PORT:04X}"
    try:
        with open("/proc/net/tcp", encoding="ascii") as fh:
            next(fh)
            for line in fh:
                f = line.split()
                if f[1] == want_local and f[2] == want_remote:
                    return int(f[7])
    except OSError:
        return None
    return None


def _win_peer(client_port: int) -> tuple[str, list[str], str] | None:
    """Windows: account name + group SIDs + user SID of the process owning 127.0.0.1:<client_port> -> 127.0.0.1:LISTEN_PORT
    (TCP owner table -> process token). Same role as the kernel peer uid on Linux: never what the client asserts."""
    import ctypes
    from ctypes import wintypes as w
    iph, adv, k32 = ctypes.WinDLL("iphlpapi"), ctypes.WinDLL("advapi32"), ctypes.WinDLL("kernel32")
    # explicit 64-bit signatures: default int return types would truncate handles
    k32.OpenProcess.restype, k32.OpenProcess.argtypes = w.HANDLE, [w.DWORD, w.BOOL, w.DWORD]
    k32.CloseHandle.argtypes = [w.HANDLE]
    k32.LocalFree.argtypes, k32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    adv.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    adv.GetTokenInformation.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    adv.LookupAccountSidW.argtypes = [w.LPCWSTR, ctypes.c_void_p, w.LPWSTR, ctypes.POINTER(w.DWORD), w.LPWSTR,
                                      ctypes.POINTER(w.DWORD), ctypes.POINTER(w.DWORD)]
    iph.GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.DWORD), w.BOOL, w.ULONG, ctypes.c_int, w.ULONG]
    size = w.DWORD(0)
    iph.GetExtendedTcpTable(None, ctypes.byref(size), False, 2, 5, 0)   # AF_INET, TCP_TABLE_OWNER_PID_ALL
    buf = ctypes.create_string_buffer(size.value)
    if iph.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2, 5, 0) != 0:
        return None
    n = ctypes.cast(buf, ctypes.POINTER(w.DWORD))[0]
    rows = ctypes.cast(ctypes.addressof(buf) + 4, ctypes.POINTER(w.DWORD * 6))
    lo = 0x0100007F   # 127.0.0.1 in network order as read little-endian
    def port(v: int) -> int:
        return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)
    pid = next((r[5] for r in (rows[i] for i in range(n))
                if r[1] == lo and port(r[2]) == client_port and r[3] == lo and port(r[4]) == LISTEN_PORT), None)
    if not pid:
        return None
    hp = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
    if not hp:
        return None
    try:
        ht = w.HANDLE()
        if not adv.OpenProcessToken(hp, 0x0008, ctypes.byref(ht)):   # TOKEN_QUERY
            return None
        try:
            def info(cls: int) -> ctypes.Array:
                ln = w.DWORD(0)
                adv.GetTokenInformation(ht, cls, None, 0, ctypes.byref(ln))
                b = ctypes.create_string_buffer(ln.value)
                if not adv.GetTokenInformation(ht, cls, b, ln, ctypes.byref(ln)):
                    raise OSError("GetTokenInformation")
                return b
            def sid_str(psid: int) -> str:
                out = w.LPWSTR()
                adv.ConvertSidToStringSidW(ctypes.c_void_p(psid), ctypes.byref(out))
                v = out.value or ""
                k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
                return v
            ub = info(1)   # TokenUser: SID_AND_ATTRIBUTES
            usid = ctypes.cast(ub, ctypes.POINTER(ctypes.c_void_p))[0]
            name, dom = ctypes.create_unicode_buffer(256), ctypes.create_unicode_buffer(256)
            nl, dl, use = w.DWORD(256), w.DWORD(256), w.DWORD(0)
            adv.LookupAccountSidW(None, ctypes.c_void_p(usid), name, ctypes.byref(nl), dom, ctypes.byref(dl), ctypes.byref(use))
            gb = info(2)   # TokenGroups: DWORD count + SID_AND_ATTRIBUTES[]
            cnt = ctypes.cast(gb, ctypes.POINTER(w.DWORD))[0]
            ptr = ctypes.sizeof(ctypes.c_void_p)
            base = ctypes.addressof(gb) + ptr   # count padded to pointer size
            sids = [sid_str(ctypes.cast(base + i * 2 * ptr, ctypes.POINTER(ctypes.c_void_p))[0]) for i in range(cnt)]
            return name.value, sids, sid_str(usid)
        finally:
            k32.CloseHandle(ht)
    finally:
        k32.CloseHandle(hp)


def _darwin_peer_uid(client_port: int) -> int | None:
    """macOS: uid of the process owning 127.0.0.1:<client_port> -> 127.0.0.1:LISTEN_PORT (lsof; never what the client
    asserts). None when lsof fails or the owner is missing / ambiguous (fail closed)."""
    want = f"127.0.0.1:{client_port}->127.0.0.1:{LISTEN_PORT}"
    try:
        r = subprocess.run([LSOF, "-nP", f"-iTCP@127.0.0.1:{client_port}", "-sTCP:ESTABLISHED", "-Fpun"],  # noqa: S603  # nosec B603
                           capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError) as e:
        log("CALLER_LOOKUP_ERROR", port=client_port, error=f"{type(e).__name__}: {e}")
        return None
    me, pid, uid, uids = os.getpid(), 0, -1, set()
    for line in r.stdout.decode(errors="replace").splitlines():
        tag, val = line[:1], line[1:]
        if tag == "p":
            pid, uid = int(val) if val.isdigit() else 0, -1
        elif tag == "u":
            uid = int(val) if val.isdigit() else -1
        elif tag == "n" and val == want and pid and pid != me and uid >= 0:
            uids.add(uid)
    return uids.pop() if len(uids) == 1 else None


def _darwin_identity(client_port: int) -> tuple[str, str, str] | None:
    uid = _darwin_peer_uid(client_port)
    if uid is None or uid == 0:
        return None
    try:
        pw = pwd.getpwuid(uid)
        names = set()
        for gid in os.getgrouplist(pw.pw_name, pw.pw_gid):
            try:
                names.add(grp.getgrgid(gid).gr_name)
            except KeyError:
                continue
    except (KeyError, OSError):
        return None
    for g in ("agy-contractor", "agy-dev"):   # contractor wins (same rule as the hook)
        if g in MANAGED_GROUPS and g in names:
            return pw.pw_name, g, pw.pw_dir
    return None


def identity(client_port: int) -> tuple[str, str, str] | None:
    """(user, persona group, reference): the reference is the user SID on Windows and the home directory elsewhere."""
    if WIN:
        peer = _win_peer(client_port)
        if not peer:
            return None
        user, sids, usid = peer
        try:
            with open(PERSONA_GROUPS, encoding="utf-8") as fh:
                pg = json.load(fh)
        except (OSError, ValueError):
            return None
        for g in ("agy-contractor", "agy-dev"):   # contractor wins (same rule as the hook)
            if g in MANAGED_GROUPS and set(sids) & set(pg.get(g) or []):
                return user, g, usid
        return None
    if sys.platform == "darwin":
        return _darwin_identity(client_port)
    if not os.path.exists("/proc/net/tcp"):
        log("CALLER_LOOKUP_UNAVAILABLE", port=client_port, reason="no /proc/net/tcp")   # fail closed
        return None
    uid = peer_uid(client_port)
    if uid is None:
        return None
    try:
        pw = pwd.getpwuid(uid)
        group = grp.getgrgid(pw.pw_gid).gr_name
    except KeyError:
        return None
    return (pw.pw_name, group, pw.pw_dir) if group in MANAGED_GROUPS else None


# ---------------------------------------------------------------- managed-policy readiness gate
def _ro_mounts() -> set[str] | None:
    """Mount points mounted read-only in the host mount namespace (None when no mount table is readable)."""
    for path in MOUNTINFO:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                out = set()
                for line in fh:
                    f = line.split()
                    if len(f) > 5 and "ro" in f[5].split(","):
                        out.add(f[4].replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\"))
                return out
        except OSError:
            continue
    return None


def linux_policy_ready(user: str, home: str) -> tuple[bool, str]:
    """Each managed file is a read-only mount, or (no mount) root-owned and not group/world-writable."""
    if os.path.exists(os.path.join(ENROLLMENT_DIR, user)):
        return True, "enrollment"
    ro = _ro_mounts() or set()
    for rel in MANAGED_FILES:
        path = os.path.join(home, rel)
        if path in ro:
            continue
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return False, f"{rel} missing or not a read-only policy mount"
        if st.st_uid != 0 or st.st_mode & 0o022 or not os.path.isfile(path) or os.path.islink(path):
            return False, f"{rel} not locked (owner uid {st.st_uid}, mode {oct(st.st_mode & 0o777)})"
    return True, "locked"


def darwin_policy_ready(user: str, home: str) -> tuple[bool, str]:
    """macOS: each managed file is a regular file owned by root, not group/world-writable, with the system-immutable
    flag (schg) set by the policy LaunchDaemon."""
    for rel in MANAGED_FILES:
        path = os.path.join(home, rel)
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            return False, f"{rel} missing"
        if not stat.S_ISREG(st.st_mode):
            return False, f"{rel} not a regular file"
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False, f"{rel} not locked (owner uid {st.st_uid}, mode {oct(st.st_mode & 0o777)})"
        if not getattr(st, "st_flags", 0) & stat.SF_IMMUTABLE:
            return False, f"{rel} not locked (no system-immutable flag)"
    return True, "locked"


def _win_profile(sid: str) -> str | None:
    """Profile folder of a SID (HKLM ProfileList), None when the profile does not exist yet."""
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}") as k:
            return os.path.expandvars(str(winreg.QueryValueEx(k, "ProfileImagePath")[0]))
    except OSError:
        return None


def _win_owner(path: str) -> str | None:
    """Owner SID of a file (GetNamedSecurityInfoW), None when it can't be read."""
    import ctypes
    from ctypes import wintypes as w
    adv, k32 = ctypes.WinDLL("advapi32"), ctypes.WinDLL("kernel32")
    adv.GetNamedSecurityInfoW.restype = w.DWORD
    adv.GetNamedSecurityInfoW.argtypes = [w.LPCWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(ctypes.c_void_p),
                                          ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    adv.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(w.LPWSTR)]
    k32.LocalFree.argtypes, k32.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p
    owner, sd = ctypes.c_void_p(), ctypes.c_void_p()
    # SE_FILE_OBJECT = 1, OWNER_SECURITY_INFORMATION = 1
    if adv.GetNamedSecurityInfoW(path, 1, 1, ctypes.byref(owner), None, None, None, ctypes.byref(sd)) != 0:
        return None
    try:
        out = w.LPWSTR()
        if not adv.ConvertSidToStringSidW(owner, ctypes.byref(out)):
            return None
        v = out.value
        k32.LocalFree(ctypes.cast(out, ctypes.c_void_p))
        return v
    finally:
        k32.LocalFree(sd)


def win_policy_ready(sid: str) -> tuple[bool, str]:
    """Each managed file exists in the user's profile and is owned by SYSTEM / Administrators (set by AGY-Policy)."""
    home = _win_profile(sid)
    if not home:
        return False, "profile not found"
    for rel in MANAGED_FILES:
        path = os.path.join(home, rel)
        if not os.path.isfile(path):
            return False, f"{rel} missing"
        owner = _win_owner(path)
        if owner not in ADMIN_OWNERS:
            return False, f"{rel} not locked (owner {owner})"
    return True, "locked"


def _schtasks() -> str:
    """Absolute path of schtasks.exe (a SYSTEM task's PATH can't be relied on)."""
    exe = os.path.join(os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows", "System32", "schtasks.exe")
    return exe if os.path.isfile(exe) else "schtasks"


def _policy_argv() -> list[str]:
    if sys.platform == "darwin":
        return [LAUNCHCTL, "kickstart", "-k", MAC_POLICY_JOB]
    return [_schtasks(), "/run", "/tn", POLICY_TASK]


def _run_policy_task(user: str) -> None:
    try:
        r = subprocess.run(_policy_argv(), capture_output=True, timeout=30, check=False)  # noqa: S603  # nosec B603
        out = (r.stdout or b"").decode(errors="replace").strip() + " " + (r.stderr or b"").decode(errors="replace").strip()
        log("POLICY_RUN_REQUESTED" if r.returncode == 0 else "POLICY_RUN_ERROR", user=user, rc=r.returncode, output=out.strip()[:300])
    except Exception as e:  # noqa: BLE001 - never let the trigger kill the request thread; always leave a log line
        log("POLICY_RUN_ERROR", user=user, error=f"{type(e).__name__}: {e}")


def _kick_policy(user: str) -> bool:
    """Windows / macOS: start the policy run (AGY-Policy task / policy LaunchDaemon) now so the wait is short; at most once per user per KICK_EVERY seconds.
    The first call for a user always fires (no time arithmetic on the initial state)."""
    now = time.monotonic()
    with _gate_lock:
        last = _kicked_at.get(user)
        limited = last is not None and now - last < KICK_EVERY
        if not limited:
            _kicked_at[user] = now
    if limited:
        log("POLICY_RUN_SKIPPED", user=user, reason="rate-limited", seconds_since_last=round(now - (last or now), 1))
        return False
    try:
        threading.Thread(target=_run_policy_task, args=(user,), name=f"agy-policy-kick-{user}", daemon=True).start()
    except Exception as e:  # noqa: BLE001
        log("POLICY_RUN_ERROR", user=user, error=f"thread: {type(e).__name__}: {e}")
        return False
    return True


def policy_ready(user: str, ref: str) -> tuple[bool, str]:
    """Readiness of the caller's managed files; positive results cached for READY_TTL seconds."""
    now = time.monotonic()
    with _gate_lock:
        if _ready_until.get(user, 0.0) > now:
            return True, "cached"
    if WIN:
        ok, why = win_policy_ready(ref)
    elif sys.platform == "darwin":
        ok, why = darwin_policy_ready(user, ref)
    else:
        ok, why = linux_policy_ready(user, ref)
    if ok:
        with _gate_lock:
            _ready_until[user] = now + READY_TTL
    return ok, why


def device_cert_b64() -> str:
    """Public device certificate (DER, base64) - bound at the gateway to the LB-verified fingerprint."""
    with open(CLIENT_CERT, encoding="ascii") as fh:
        pem = fh.read()
    return base64.b64encode(ssl.PEM_cert_to_DER_cert(pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")).decode()


def tls_context(gw: urllib.parse.SplitResult) -> ssl.SSLContext:
    """mTLS to the private front door (device cert + private CA) when enrolled; public CAs otherwise."""
    if (DEVICE_AUTH == "cert" or (gw.hostname and gw.hostname.endswith(".internal"))) and os.path.exists(CLIENT_CERT):
        ctx = ssl.create_default_context(cafile=GATEWAY_CA)
        ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
        return ctx
    return ssl.create_default_context()


def gateway() -> urllib.parse.SplitResult:
    with open(GATEWAY_URL_FILE, encoding="utf-8") as fh:
        return urllib.parse.urlsplit(fh.read().strip())


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "agy-credproxy"

    def _body(self) -> bytes:
        if "chunked" in (self.headers.get("transfer-encoding") or "").lower():
            buf = bytearray()
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return bytes(buf)
                buf += self.rfile.read(size)
                self.rfile.readline()
        n = int(self.headers.get("content-length") or 0)
        return self.rfile.read(n) if n else b""

    def _reply(self, code: int, msg: str, status: str = "", retry_after: int = 0) -> None:
        err: dict[str, object] = {"code": code, "message": msg}
        if status:
            err["status"] = status
        data = json.dumps({"error": err}).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        if retry_after:
            self.send_header("retry-after", str(retry_after))
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _proxy(self) -> None:
        # identity is bound to this connection (one handler per accepted socket): looked up once, reused on keep-alive
        who = getattr(self, "_who", None) or identity(self.client_address[1])
        if who is not None:
            self._who = who
        body = self._body()
        if who is None:
            log("CALLER_REJECTED", port=self.client_address[1], path=self.path)
            self._reply(403, "agy-credproxy: caller is not a managed Antigravity user")
            return
        user, group, ref = who
        if REQUIRE_POLICY:
            ok, why = policy_ready(user, ref)
            if not ok:
                kicked = _kick_policy(user) if (WIN or sys.platform in ("win32", "darwin")) else False
                log("POLICY_NOT_READY", user=user, group=group, reason=why, policy_run_requested=kicked)
                self._reply(503, NOT_READY_MSG, "POLICY_NOT_READY", retry_after=30)
                return
        try:
            gw = gateway()
            if DEVICE_AUTH == "cert":
                if not os.path.exists(CLIENT_CERT):
                    raise FileNotFoundError(CLIENT_CERT)
                tok = ""
            else:
                tok = device_token()
        except Exception as e:  # noqa: BLE001
            log("DEVICE_TOKEN_ERROR", user=user, error=str(e))
            self._reply(503, "agy-credproxy: device identity unavailable")
            return
        headers = {k: v for k, v in self.headers.items() if k.lower() not in DROP}
        if (DEVICE_AUTH == "cert" or (gw.hostname and gw.hostname.endswith(".internal"))) and os.path.exists(CLIENT_CERT):
            headers["X-AGY-Device-Cert"] = device_cert_b64()
        headers.update({"Host": gw.netloc, "X-AGY-User": user, "X-AGY-Group": group,
                        "Content-Length": str(len(body)), "Accept-Encoding": "identity"})
        if tok:
            headers["X-AGY-Device-Token"] = tok
        conn = http.client.HTTPSConnection(gw.hostname, gw.port or 443, timeout=600, context=tls_context(gw))
        resp = None
        try:
            conn.request(self.command, (gw.path.rstrip("/") + self.path), body=body or None, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "connection", "content-length", "content-encoding"):
                    self.send_header(k, v)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while chunk := resp.read1(65536):
                self.wfile.write(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            log("FORWARDED", user=user, group=group, method=self.command, path=self.path.split("?")[0], status=resp.status)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError) as e:
            if resp is not None:   # gateway answered; the local client closed the stream (normal for the CLI)
                log("CLIENT_CLOSED", user=user, group=group, path=self.path.split("?")[0], status=resp.status)
                self.close_connection = True
                return
            log("GATEWAY_ERROR", user=user, error=str(e))
            try:
                self._reply(502, "agy-credproxy: gateway unreachable")
            except OSError:
                pass
        except (OSError, http.client.HTTPException) as e:
            log("GATEWAY_ERROR", user=user, error=str(e))
            try:
                self._reply(502, "agy-credproxy: gateway unreachable")
            except OSError:
                pass
        finally:
            conn.close()

    do_GET = do_POST = _proxy  # type: ignore[assignment]

    def log_message(self, fmt: str, *args: object) -> None:  # silence default access log
        return


class Server(ThreadingHTTPServer):
    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        # clients dropping keep-alive connections (Windows: WinError 10054) are normal; keep the log one JSON line per event
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        log("REQUEST_ERROR", port=client_address[1], error=f"{type(exc).__name__}: {exc}")


def main() -> None:
    srv = Server(("127.0.0.1", LISTEN_PORT), Handler)
    srv.daemon_threads = True
    log("STARTED", port=LISTEN_PORT, audience=AUDIENCE, managed_groups=sorted(MANAGED_GROUPS), device_auth=DEVICE_AUTH,
        require_managed_policy=REQUIRE_POLICY)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
