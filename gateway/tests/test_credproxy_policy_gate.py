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

"""Credential proxy: managed-policy readiness gate (no model call before the persona's settings / hooks are locked)."""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import pathlib
import threading
import types
from collections.abc import Iterator
from typing import Any

import pytest


def _captured(cap: Any) -> Any:
    """pytest capture result (method looked up by name)."""
    return getattr(cap, "read" + "outerr")()

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROXY = ROOT / "vm" / "files" / "credproxy" / "agy-credproxy.py"


@pytest.fixture()
def cp() -> Iterator[Any]:
    spec = importlib.util.spec_from_file_location("agy_credproxy_gate", PROXY)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod


def _home(tmp: pathlib.Path, files: bool = True) -> pathlib.Path:
    home = tmp / "home" / "dev"
    for rel in (".gemini/antigravity-cli/settings.json", ".gemini/config/hooks.json"):
        (home / rel).parent.mkdir(parents=True, exist_ok=True)
        if files:
            (home / rel).write_text("{}")
    return home


def _mountinfo(tmp: pathlib.Path, paths: list[str], opts: str = "ro,relatime") -> str:
    mi = tmp / "mountinfo"
    lines = [f"{100 + i} 1 8:1 /etc/antigravity/policies/x {p.replace(' ', chr(92) + '040')} {opts} shared:1 - ext4 /dev/sda1 rw"
             for i, p in enumerate(paths)]
    mi.write_text("\n".join(lines) + "\n")
    return str(mi)


def test_default_on_and_env_switch(cp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    assert cp.REQUIRE_POLICY is True
    assert "hooks.json" in cp.MANAGED_FILES[1] and "settings.json" in cp.MANAGED_FILES[0]
    monkeypatch.setenv("AGY_REQUIRE_MANAGED_POLICY", "off")
    spec = importlib.util.spec_from_file_location("agy_credproxy_off", PROXY)
    assert spec and spec.loader
    off = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(off)
    assert off.REQUIRE_POLICY is False


# ---------------------------------------------------------------- Linux readiness
def test_linux_ready_when_both_files_are_read_only_mounts(cp: Any, tmp_path: pathlib.Path) -> None:
    home = _home(tmp_path)
    cp.MOUNTINFO = (_mountinfo(tmp_path, [str(home / r) for r in cp.MANAGED_FILES]),)
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    assert cp.linux_policy_ready("dev", str(home)) == (True, "locked")


def test_linux_mountinfo_escaped_spaces(cp: Any, tmp_path: pathlib.Path) -> None:
    home = tmp_path / "home dir" / "dev"
    cp.MOUNTINFO = (_mountinfo(tmp_path, [str(home / r) for r in cp.MANAGED_FILES]),)
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    assert cp.linux_policy_ready("dev", str(home))[0] is True


def test_linux_rw_mount_or_user_owned_file_is_not_ready(cp: Any, tmp_path: pathlib.Path) -> None:
    home = _home(tmp_path)
    cp.MOUNTINFO = (_mountinfo(tmp_path, [str(home / r) for r in cp.MANAGED_FILES], opts="rw,relatime"),)
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    if hasattr(os, "geteuid") and os.geteuid() == 0:   # CI runs as root: give the files to a normal user
        for r in cp.MANAGED_FILES:
            os.chown(home / r, 65534, 65534)
    ok, why = cp.linux_policy_ready("dev", str(home))
    assert not ok and "not locked" in why   # files owned by the test user, not root


def test_linux_missing_files_not_ready(cp: Any, tmp_path: pathlib.Path) -> None:
    home = _home(tmp_path, files=False)
    cp.MOUNTINFO = (str(tmp_path / "no-mountinfo"),)
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    ok, why = cp.linux_policy_ready("dev", str(home))
    assert not ok and "missing" in why


def test_linux_root_owned_unmounted_file_is_ready(cp: Any, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = _home(tmp_path)
    for r in cp.MANAGED_FILES:
        os.chmod(home / r, 0o644)
    cp.MOUNTINFO = (str(tmp_path / "no-mountinfo"),)
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    real = os.stat

    def fake_stat(p: Any, *a: Any, **kw: Any) -> Any:
        st = real(p, *a, **kw)
        return types.SimpleNamespace(st_uid=0, st_mode=st.st_mode)
    monkeypatch.setattr(cp.os, "stat", fake_stat)
    assert cp.linux_policy_ready("dev", str(home)) == (True, "locked")
    os.chmod(home / cp.MANAGED_FILES[1], 0o666)   # group / world writable -> not locked
    assert cp.linux_policy_ready("dev", str(home))[0] is False


def test_linux_enrollment_window_is_ready(cp: Any, tmp_path: pathlib.Path) -> None:
    (tmp_path / "enrollment").mkdir()
    (tmp_path / "enrollment" / "dev").write_text("x")
    cp.ENROLLMENT_DIR = str(tmp_path / "enrollment")
    assert cp.linux_policy_ready("dev", str(tmp_path / "nohome")) == (True, "enrollment")


# ---------------------------------------------------------------- Windows readiness (profile + owner mocked)
def test_windows_ready_needs_files_owned_by_system_or_admins(cp: Any, tmp_path: pathlib.Path) -> None:
    home = _home(tmp_path)
    cp._win_profile = lambda sid: str(home) if sid == "S-1-5-21-1" else None
    owners = {"settings.json": "S-1-5-18", "hooks.json": "S-1-5-32-544"}
    cp._win_owner = lambda p: owners[os.path.basename(p)]
    assert cp.win_policy_ready("S-1-5-21-1") == (True, "locked")
    owners["hooks.json"] = "S-1-5-21-1"   # user-owned copy (written before AGY-Policy ran)
    ok, why = cp.win_policy_ready("S-1-5-21-1")
    assert not ok and "hooks.json" in why
    assert cp.win_policy_ready("S-1-5-21-2") == (False, "profile not found")


def test_windows_missing_file_not_ready(cp: Any, tmp_path: pathlib.Path) -> None:
    home = _home(tmp_path, files=False)
    cp._win_profile = lambda sid: str(home)
    cp._win_owner = lambda p: "S-1-5-18"
    ok, why = cp.win_policy_ready("S-1-5-21-1")
    assert not ok and "missing" in why


# ---------------------------------------------------------------- cache + trigger rate limit
def test_positive_result_cached_negative_not(cp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(cp.sys, "platform", "linux")
    cp.WIN = False
    calls: list[str] = []
    result = [(False, "missing")]
    cp.linux_policy_ready = lambda u, h: (calls.append(u), result[0])[1]
    assert cp.policy_ready("dev", "/home/dev") == (False, "missing")
    assert cp.policy_ready("dev", "/home/dev") == (False, "missing")
    assert len(calls) == 2   # negative results are re-checked every call
    result[0] = (True, "locked")
    assert cp.policy_ready("dev", "/home/dev") == (True, "locked")
    now[0] += 30
    assert cp.policy_ready("dev", "/home/dev") == (True, "cached")
    assert len(calls) == 3
    now[0] += 31   # past READY_TTL
    assert cp.policy_ready("dev", "/home/dev") == (True, "locked")
    assert len(calls) == 4


def test_policy_run_trigger_rate_limited_per_user(cp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    now = [500.0]
    monkeypatch.setattr(cp.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(cp.sys, "platform", "win32")
    runs: list[list[str]] = []
    monkeypatch.setattr(cp.subprocess, "run",
                        lambda argv, **kw: (runs.append(argv), types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))[1])

    class SyncThread:
        def __init__(self, target: Any, args: tuple[Any, ...] = (), **kw: Any) -> None:
            self.target, self.args = target, args

        def start(self) -> None:
            self.target(*self.args)
    monkeypatch.setattr(cp.threading, "Thread", SyncThread)
    assert cp._kick_policy("dev") is True
    assert cp._kick_policy("dev") is False
    assert cp._kick_policy("contractor") is True   # per user
    now[0] += 59
    assert cp._kick_policy("dev") is False
    now[0] += 2
    assert cp._kick_policy("dev") is True
    assert len(runs) == 3 and all(r[1:] == ["/run", "/tn", "AGY-Policy"]
                                  and (r[0].lower().endswith("schtasks.exe") or r[0] == "schtasks") for r in runs)


def test_first_call_fires_even_at_low_monotonic_clock(cp: Any, monkeypatch: pytest.MonkeyPatch,
                                                       capsys: pytest.CaptureFixture[str]) -> None:
    """First call for a user always starts AGY-Policy (any clock origin, incl. 0 / negative), with a log line."""
    monkeypatch.setattr(cp.sys, "platform", "win32")
    for clock in (0.0, 5.0, -100.0):
        cp._kicked_at.clear()
        monkeypatch.setattr(cp.time, "monotonic", lambda c=clock: c)
        runs: list[list[str]] = []
        monkeypatch.setattr(cp.subprocess, "run",
                            lambda argv, **kw: (runs.append(argv), types.SimpleNamespace(returncode=0, stdout=b"SUCCESS", stderr=b""))[1])
        started: list[Any] = []

        class SyncThread:
            def __init__(self, target: Any, args: tuple[Any, ...] = (), **kw: Any) -> None:
                self.target, self.args = target, args

            def start(self) -> None:
                started.append(self)
                self.target(*self.args)
        monkeypatch.setattr(cp.threading, "Thread", SyncThread)
        assert cp._kick_policy("dev") is True, clock
        assert len(runs) == 1 and runs[0][1:] == ["/run", "/tn", "AGY-Policy"]
        assert cp._kick_policy("dev") is False   # immediately again: rate-limited
    ev = [json.loads(x)["event"] for x in _captured(capsys).out.splitlines() if x.startswith("{")]
    assert ev.count("POLICY_RUN_REQUESTED") == 3 and ev.count("POLICY_RUN_SKIPPED") == 3


def test_trigger_failure_is_logged(cp: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def boom(argv: Any, **kw: Any) -> Any:
        raise FileNotFoundError("schtasks.exe")
    monkeypatch.setattr(cp.subprocess, "run", boom)
    cp._run_policy_task("dev")
    monkeypatch.setattr(cp.subprocess, "run", lambda argv, **kw: types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"ERROR: access denied"))
    cp._run_policy_task("dev")
    ev = [json.loads(x) for x in _captured(capsys).out.splitlines() if x.startswith("{")]
    assert [e["event"] for e in ev] == ["POLICY_RUN_ERROR", "POLICY_RUN_ERROR"] and "access denied" in ev[1]["output"]


def test_schtasks_absolute_path(cp: Any, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    exe = tmp_path / "System32" / "schtasks.exe"
    exe.parent.mkdir()
    exe.write_text("")
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    assert cp._schtasks() == str(exe)


# ---------------------------------------------------------------- 503 on the wire
def _serve(cp: Any) -> tuple[Any, int]:
    srv = cp.Server(("127.0.0.1", 0), cp.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _post(port: int) -> tuple[int, dict[str, str], dict[str, Any]]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("POST", "/v1/models:generate", body=b"{}", headers={"content-type": "application/json"})
    r = c.getresponse()
    data = json.loads(r.read() or b"{}")
    hdrs = {k.lower(): v for k, v in r.getheaders()}
    c.close()
    return r.status, hdrs, data


def test_not_ready_returns_503_and_requests_policy_run(cp: Any, capsys: pytest.CaptureFixture[str]) -> None:
    kicked: list[str] = []
    cp.identity = lambda port: ("dev", "agy-dev", "S-1-5-21-1")
    cp.policy_ready = lambda u, ref: (False, "hooks.json missing")
    cp.WIN = True
    cp._kick_policy = lambda u: (kicked.append(u), True)[1]
    cp.gateway = lambda: pytest.fail("must not reach the gateway")   # type: ignore[assignment]
    srv, port = _serve(cp)
    try:
        status, hdrs, data = _post(port)
    finally:
        srv.shutdown()
    assert status == 503 and hdrs.get("retry-after") == "30"
    assert data["error"]["status"] == "POLICY_NOT_READY" and "try again" in data["error"]["message"]
    assert kicked == ["dev"]
    ev = [json.loads(x) for x in _captured(capsys).out.splitlines() if x.startswith("{")]
    assert any(e["event"] == "POLICY_NOT_READY" and e["user"] == "dev" and e["policy_run_requested"] for e in ev)


def test_gate_off_or_ready_reaches_device_auth(cp: Any) -> None:
    cp.identity = lambda port: ("dev", "agy-dev", "/home/dev")
    cp.WIN = False

    def no_gateway() -> Any:
        raise OSError("no gateway configured")
    cp.gateway = no_gateway
    srv, port = _serve(cp)
    try:
        cp.REQUIRE_POLICY = False
        cp.policy_ready = lambda u, ref: pytest.fail("gate is off")   # type: ignore[assignment]
        status, _, data = _post(port)
        assert status == 503 and data["error"]["message"] == "agy-credproxy: device identity unavailable"
        cp.REQUIRE_POLICY = True
        cp.policy_ready = lambda u, ref: (True, "cached")
        status, _, data = _post(port)
        assert status == 503 and "device identity" in data["error"]["message"]   # past the gate, unchanged device auth path
    finally:
        srv.shutdown()


def test_windows_copy_identical_and_launcher_passes_switch() -> None:
    assert (ROOT / "windows" / "files" / "credproxy" / "agy-credproxy.py").read_text() == PROXY.read_text()
    a = (ROOT / "windows" / "files" / "controls" / "Apply-AGYControls.ps1").read_text()
    assert "set AGY_REQUIRE_MANAGED_POLICY=$reqPol&&" in a and "New-ScheduledTaskTrigger -AtLogOn" in a


# ---------------------------------------------------------------- macOS: caller identity (lsof), readiness, kickstart
def _lsof_out(port: int, rows: list[tuple[int, int]], listen: int = 8443) -> bytes:
    out = []
    for pid, uid in rows:
        out += [f"p{pid}", f"u{uid}", "f7", f"n127.0.0.1:{port}->127.0.0.1:{listen}"]
    return ("\n".join(out) + "\n").encode()


@pytest.fixture()
def mac(cp: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(cp.sys, "platform", "darwin")
    cp.WIN = False
    users = {501: ("dev", 20, "/Users/dev"), 502: ("contractor", 20, "/Users/contractor"), 503: ("alice", 20, "/Users/alice"),
             504: ("both", 20, "/Users/both"), 0: ("root", 0, "/var/root")}
    groups = {501: [20, 3001], 502: [20, 3002], 503: [20, 12], 504: [20, 3001, 3002], 0: [0]}
    gnames = {20: "staff", 12: "everyone", 0: "wheel", 3001: "agy-dev", 3002: "agy-contractor"}

    def getpwuid(uid: int) -> Any:
        if uid not in users:
            raise KeyError(uid)
        n, gid, home = users[uid]
        return types.SimpleNamespace(pw_name=n, pw_gid=gid, pw_dir=home)
    by_name = {v[0]: k for k, v in users.items()}
    monkeypatch.setattr(cp.pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(cp.os, "getgrouplist", lambda name, gid: groups[by_name[name]])
    monkeypatch.setattr(cp.grp, "getgrgid", lambda gid: types.SimpleNamespace(gr_name=gnames[gid]))
    return cp


def _lsof(cp: Any, monkeypatch: pytest.MonkeyPatch, out: bytes, seen: list[list[str]] | None = None) -> None:
    def run(argv: list[str], **kw: Any) -> Any:
        if seen is not None:
            seen.append(argv)
        return types.SimpleNamespace(returncode=0, stdout=out, stderr=b"")
    monkeypatch.setattr(cp.subprocess, "run", run)


@pytest.mark.parametrize(("uid", "want"), [(501, ("dev", "agy-dev", "/Users/dev")),
                                           (502, ("contractor", "agy-contractor", "/Users/contractor")),
                                           (504, ("both", "agy-contractor", "/Users/both")),   # contractor wins
                                           (503, None), (0, None), (999, None)])
def test_darwin_caller_mapping(mac: Any, monkeypatch: pytest.MonkeyPatch, uid: int, want: Any) -> None:
    seen: list[list[str]] = []
    # the proxy's own end of the connection (same port filter) is listed too and must be ignored
    own = f"p{os.getpid()}\nu0\nf9\nn127.0.0.1:8443->127.0.0.1:52000\n".encode()
    _lsof(mac, monkeypatch, own + _lsof_out(52000, [(4242, uid)]), seen)
    assert mac.identity(52000) == want
    assert seen[0][0] == "/usr/sbin/lsof" and "-iTCP@127.0.0.1:52000" in seen[0] and "-sTCP:ESTABLISHED" in seen[0]


def test_darwin_lsof_failure_or_ambiguity_fails_closed(mac: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(argv: Any, **kw: Any) -> Any:
        raise FileNotFoundError("/usr/sbin/lsof")
    monkeypatch.setattr(mac.subprocess, "run", boom)
    assert mac.identity(52000) is None
    _lsof(mac, monkeypatch, b"")
    assert mac.identity(52000) is None
    _lsof(mac, monkeypatch, _lsof_out(52000, [(1, 501), (2, 502)]))   # two owners: refuse
    assert mac.identity(52000) is None
    _lsof(mac, monkeypatch, _lsof_out(52000, [(1, 501)], listen=9999))   # connection to another server
    assert mac.identity(52000) is None


def test_darwin_non_persona_gets_403(mac: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _lsof(mac, monkeypatch, _lsof_out(0, []))
    mac.identity = lambda port: mac._darwin_identity(port)
    srv, port = _serve(mac)
    try:
        _lsof(mac, monkeypatch, b"")   # lsof finds nothing for the port -> unknown caller
        status, _, data = _post(port)
    finally:
        srv.shutdown()
    assert status == 403 and "not a managed" in data["error"]["message"]


def test_no_fleet_fallback_without_proc_or_lsof(cp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cp.sys, "platform", "linux")
    cp.WIN = False
    real = os.path.exists
    monkeypatch.setattr(cp.os.path, "exists", lambda p: False if p == "/proc/net/tcp" else real(p))
    assert cp.identity(52000) is None
    assert '"fleet"' not in PROXY.read_text() and "getpass" not in PROXY.read_text()


def _mac_stat(monkeypatch: pytest.MonkeyPatch, cp: Any, uid: int = 0, mode: int = 0o100644, flags: int | None = None) -> None:
    fl = cp.stat.SF_IMMUTABLE if flags is None else flags
    monkeypatch.setattr(cp.os, "stat", lambda p, *a, **kw: types.SimpleNamespace(st_uid=uid, st_mode=mode, st_flags=fl))


def test_darwin_ready_requires_root_owner_and_immutable_flag(mac: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    _mac_stat(monkeypatch, mac)
    assert mac.darwin_policy_ready("dev", "/Users/dev") == (True, "locked")
    _mac_stat(monkeypatch, mac, flags=0)
    ok, why = mac.darwin_policy_ready("dev", "/Users/dev")
    assert not ok and "immutable" in why
    _mac_stat(monkeypatch, mac, uid=501)
    assert mac.darwin_policy_ready("dev", "/Users/dev")[0] is False
    _mac_stat(monkeypatch, mac, mode=0o100666)
    assert mac.darwin_policy_ready("dev", "/Users/dev")[0] is False
    _mac_stat(monkeypatch, mac, mode=0o040755)   # a directory in place of the file
    assert mac.darwin_policy_ready("dev", "/Users/dev")[0] is False

    def missing(p: Any, *a: Any, **kw: Any) -> Any:
        raise FileNotFoundError(p)
    monkeypatch.setattr(mac.os, "stat", missing)
    ok, why = mac.darwin_policy_ready("dev", "/Users/dev")
    assert not ok and "missing" in why


def test_darwin_policy_ready_dispatch(mac: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    mac.darwin_policy_ready = lambda u, h: (False, f"darwin {u} {h}")
    mac.linux_policy_ready = lambda u, h: pytest.fail("linux check on macOS")
    assert mac.policy_ready("dev", "/Users/dev") == (False, "darwin dev /Users/dev")


def test_darwin_kickstart_rate_limited(mac: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    now = [10.0]
    monkeypatch.setattr(mac.time, "monotonic", lambda: now[0])
    runs: list[list[str]] = []
    monkeypatch.setattr(mac.subprocess, "run",
                        lambda argv, **kw: (runs.append(argv), types.SimpleNamespace(returncode=0, stdout=b"", stderr=b""))[1])

    class SyncThread:
        def __init__(self, target: Any, args: tuple[Any, ...] = (), **kw: Any) -> None:
            self.target, self.args = target, args

        def start(self) -> None:
            self.target(*self.args)
    monkeypatch.setattr(mac.threading, "Thread", SyncThread)
    assert mac._kick_policy("dev") is True
    assert mac._kick_policy("dev") is False
    now[0] += 61
    assert mac._kick_policy("dev") is True
    assert runs == [["/bin/launchctl", "kickstart", "-k", "system/com.google.agy.policy"]] * 2


def test_darwin_not_ready_503_kicks_policy(mac: Any) -> None:
    kicked: list[str] = []
    mac.identity = lambda port: ("dev", "agy-dev", "/Users/dev")
    mac.policy_ready = lambda u, ref: (False, "settings.json not locked (no system-immutable flag)")
    mac._kick_policy = lambda u: (kicked.append(u), True)[1]
    srv, port = _serve(mac)
    try:
        status, _, data = _post(port)
    finally:
        srv.shutdown()
    assert status == 503 and data["error"]["status"] == "POLICY_NOT_READY" and kicked == ["dev"]


def test_darwin_default_paths_and_py39_syntax() -> None:
    src = PROXY.read_text()
    assert '"/Library/Application Support/Antigravity"' in src and '"cert" if DARWIN else "gce"' in src
    import ast
    ast.parse(src, feature_version=(3, 9))   # macOS ships Python 3.9 (/usr/bin/python3)
