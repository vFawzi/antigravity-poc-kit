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

"""agy-hook on macOS (posix policy): policy path, persona from supplementary groups, ps-based ancestor walk, the
admin-group session guard, quoted / escaped paths with spaces, and Python 3.9 compatibility. Darwin is simulated, so
these tests run on any OS."""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOOK = ROOT / "vm" / "files" / "hooks" / "agy-hook.py"
POLICY = HOOK.with_name("policy.json")
WIN_POLICY = ROOT / "windows" / "files" / "hooks" / "policy.windows.json"
MAC_POLICY = "/Library/Application Support/Antigravity/hooks/policy.json"
GROUPS = {20: "staff", 80: "admin", 0: "wheel", 701: "agy-dev", 702: "agy-contractor", 12: "everyone"}


def load(name: str = "agy_hook_mac") -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, HOOK)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def fake_grp(gid: int) -> SimpleNamespace:
    if gid not in GROUPS:
        raise KeyError(gid)
    return SimpleNamespace(gr_name=GROUPS[gid])


@pytest.fixture()
def mac(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    if os.name == "nt":
        pytest.skip("posix module layout (grp / pwd)")
    mod = load()
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(mod.grp, "getgrgid", fake_grp)
    monkeypatch.setattr(mod, "current_user", lambda: "dev")
    monkeypatch.setattr(os, "getgid", lambda: 20)
    return mod


def set_groups(monkeypatch: pytest.MonkeyPatch, proc: list[int], directory: list[int] | None = None) -> None:
    monkeypatch.setattr(os, "getgroups", lambda: list(proc))
    monkeypatch.setattr(os, "getgrouplist", lambda user, gid: list(directory if directory is not None else proc))


# ---------------------------------------------------------------- policy path
def test_policy_path_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.name == "nt":
        pytest.skip("posix")
    monkeypatch.delenv("AGY_HOOK_POLICY", raising=False)
    monkeypatch.setattr(sys, "platform", "darwin")
    assert load("agy_hook_mac_p1").POLICY_FILE == MAC_POLICY
    monkeypatch.setattr(sys, "platform", "linux")
    assert load("agy_hook_mac_p2").POLICY_FILE == "/etc/antigravity/hooks/policy.json"
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setenv("AGY_HOOK_POLICY", "/tmp/custom policy.json")
    assert load("agy_hook_mac_p3").POLICY_FILE == "/tmp/custom policy.json"


# ---------------------------------------------------------------- persona from supplementary groups
@pytest.mark.parametrize("proc,directory,persona", [
    ([20, 12, 701], None, "agy-dev"),
    ([20, 12, 702], None, "agy-contractor"),
    ([20, 701, 702], None, "agy-contractor"),          # contractor wins
    ([20, 12], [20, 12, 701], "agy-dev"),               # only in the directory membership (getgroups capped)
    ([20, 12, 80], None, "staff"),                      # no persona group: primary group, default policy only
])
def test_macos_persona(mac: ModuleType, monkeypatch: pytest.MonkeyPatch, proc: list[int], directory: list[int] | None,
                       persona: str) -> None:
    set_groups(monkeypatch, proc, directory)
    assert mac.group_name() == persona


def test_linux_persona_unchanged(mac: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    set_groups(monkeypatch, [20, 701])
    assert mac.group_name() == "staff"                 # Linux: primary group, as before


# ---------------------------------------------------------------- elevated sessions with macOS group names
@pytest.mark.parametrize("proc,directory,bad", [([20, 12, 80], None, "admin"), ([20, 0], None, "wheel"),
                                                ([20, 12], [20, 12, 80], "admin"), ([20, 12, 701], None, None)])
def test_macos_admin_session(mac: ModuleType, monkeypatch: pytest.MonkeyPatch, proc: list[int],
                             directory: list[int] | None, bad: str | None) -> None:
    set_groups(monkeypatch, proc, directory)
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    pol = json.loads(POLICY.read_text())["default"]
    why = mac.elevated_session(pol)
    assert (why is None) if bad is None else (bad in str(why)), why


# ---------------------------------------------------------------- ancestor walk without /proc
def fake_ps(pids: dict[int, tuple[int, str, str]]) -> Any:
    def run(cmd: list[str], **kw: Any) -> SimpleNamespace:
        if "comm=" in cmd:
            return SimpleNamespace(stdout="\n".join(f"{p:>6} {pp:>6} {c}" for p, (pp, c, _) in pids.items()) + "\n")
        return SimpleNamespace(stdout="\n".join(f"{p:>6} {a}" for p, (_, _, a) in pids.items()) + "\n")
    return run


TREE = {300: (200, "/usr/bin/python3", "/usr/bin/python3 /usr/local/libexec/agy/agy-hook.py PreToolUse"),
        200: (150, "/usr/local/bin/agy", "agy --mode auto"),
        150: (100, "-zsh", "-zsh"), 100: (1, "/usr/bin/login", "login -pf dev"), 1: (0, "/sbin/launchd", "/sbin/launchd")}


def test_ps_table_and_walk(mac: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    table = mac._ps_table(fake_ps(TREE))
    assert table[200] == (150, "agy", "agy --mode auto") and table[300][1] == "python3"
    monkeypatch.setattr(os, "getppid", lambda: 200)
    chain = mac._ancestors_ps(table=table)
    assert [c[0] for c in chain] == ["agy", "-zsh", "login"]
    assert mac.review_bypass({}, {"deny_review_bypass": True}, [c for c in chain if c[0] in mac.CLIENT_EXES])


def test_ps_walk_unreadable_client_is_refused(mac: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    tree = {**TREE, 200: (150, "/usr/local/bin/agy", "")}
    monkeypatch.setattr(os, "getppid", lambda: 200)
    chain = mac._ancestors_ps(table=mac._ps_table(fake_ps(tree)))
    assert chain[0] == ("agy", ["<unreadable>"])
    assert "could not be verified" in str(mac.review_bypass({}, {"deny_review_bypass": True}, chain[:1]))
    tree = {**TREE, 200: (150, "/usr/local/bin/agy", "agy --mode default")}
    chain = mac._ancestors_ps(table=mac._ps_table(fake_ps(tree)))
    assert mac.review_bypass({}, {"deny_review_bypass": True}, chain[:1]) is None


def test_client_ancestors_uses_ps_without_proc(mac: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/proc/self" else real_isdir(p))
    monkeypatch.setattr(mac, "_ancestors_ps", lambda: [("agy", ["agy", "--dangerously-skip-permissions"]), ("zsh", [])])
    monkeypatch.setattr(mac, "_ancestors_linux", lambda: pytest.fail("no /proc"))
    assert mac.client_ancestors() == [("agy", ["agy", "--dangerously-skip-permissions"])]
    monkeypatch.setattr(os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p))
    monkeypatch.setattr(mac, "_ancestors_linux", lambda: [("agy", ["agy"])])
    monkeypatch.setattr(mac, "_ancestors_ps", lambda: pytest.fail("Linux keeps /proc"))
    assert mac.client_ancestors() == [("agy", ["agy"])]


def test_ps_failure_is_reported(mac: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    logs: list[str] = []
    monkeypatch.setattr(mac, "log", lambda ev, **kw: logs.append(ev))
    real_isdir = os.path.isdir
    monkeypatch.setattr(os.path, "isdir", lambda p: False if p == "/proc/self" else real_isdir(p))

    def boom() -> list[tuple[str, list[str]]]:
        raise OSError("ps")
    monkeypatch.setattr(mac, "_ancestors_ps", boom)
    assert mac.client_ancestors() == [] and logs == ["REVIEW_GUARD_ERROR"]   # same as the /proc walk failing


# ---------------------------------------------------------------- quoted / escaped paths with spaces
def pol(mod: ModuleType, group: str = "agy-dev") -> dict[str, Any]:
    mod.POLICY_FILE = str(POLICY)
    return mod.load_policy(group)


def cmd(c: str) -> dict[str, Any]:
    return {"name": "run_command", "args": {"CommandLine": c}}


@pytest.mark.parametrize("c,cls", [
    ('cat "~/Library/Application Support/Google/Chrome/Default/Login Data"', "paths"),
    ("cp '~/Library/Keychains/login.keychain-db' /tmp/x", "paths"),
    ("cat ~/Library/Application\\ Support/Firefox/Profiles/x/logins.json", "paths"),
    ('tar czf /tmp/x.tgz "/Library/Application Support/Antigravity/hooks"', "paths"),
    ("cd /tmp && cat \"/home/dev/.mozilla/firefox/my profile/logins.json\" | head", "paths"),
    ('cat "/home/dev/.ssh/my key"', "paths"),
    ('cat "/data/projects/dev/my dir/.env"', "secret_files"),
    ("cat /data/projects/dev/my\\ dir/id_rsa", "secret_files"),
])
def test_quoted_paths_with_spaces_denied(c: str, cls: str) -> None:
    mod = load("agy_hook_mac_q")
    ex = mod.decide_ex(cmd(c), pol(mod), "/home/dev", "dev")
    assert ex and ex[0] == "deny" and ex[2] == cls, (c, ex)


@pytest.mark.parametrize("c", [
    'cat "/data/projects/dev/my notes.txt"', "ls ~/Library/Application\\ Support/Code/User",
    'echo "hello world"', 'git commit -m "fix ~ handling in paths"', 'cat "/data/projects/dev/my dir/.env.example"',
    'open "/Applications/Visual Studio Code.app"', "cp 'a b.txt' 'c d.txt'",
])
def test_quoted_paths_with_spaces_allowed(c: str) -> None:
    mod = load("agy_hook_mac_q2")
    assert mod.decide_ex(cmd(c), pol(mod), "/home/dev", "dev") is None, c


def test_windows_quoted_path_with_spaces(monkeypatch: pytest.MonkeyPatch) -> None:
    mod = load("agy_hook_mac_w")
    monkeypatch.setattr(mod, "WIN", True)
    mod.POLICY_FILE = str(WIN_POLICY)
    p = mod.load_policy("agy-dev")
    c = 'type "C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Credentials\\a b"'
    assert mod.decide_ex(cmd(c), p, "C:\\Users\\dev", "dev")[2] == "paths"
    assert mod.decide_ex(cmd('type "C:\\Program Files\\App\\read me.txt"'), p, "C:\\Users\\dev", "dev") is None


def test_command_paths_keeps_quoted_path_whole() -> None:
    mod = load("agy_hook_mac_cp")
    out = mod.command_paths('cat "~/Library/Application Support/x" && bash -c "cat /etc/hosts"')
    assert "~/Library/Application Support/x" in out and "/etc/hosts" in out


# ---------------------------------------------------------------- Python 3.9 (macOS system python)
def test_hook_parses_as_python39() -> None:
    tree = ast.parse(HOOK.read_text(encoding="utf-8"), feature_version=(3, 9))
    assert not [n for n in ast.walk(tree) if type(n).__name__ == "Match"]


def _python39() -> str | None:
    for c in ("python3.9", "/usr/bin/python3"):
        exe = shutil.which(c) or (c if os.path.exists(c) else None)
        if exe:
            v = subprocess.run([exe, "-c", "import sys; print(sys.version_info[:2] == (3, 9))"], capture_output=True,
                               text=True).stdout.strip()
            if v == "True":
                return exe
    return None


def test_hook_runs_under_python39(tmp_path: pathlib.Path) -> None:
    exe = _python39()
    if not exe:
        pytest.skip("no Python 3.9 interpreter on this host")
    d = json.loads(POLICY.read_text())
    d["default"]["deny_elevated_session"] = False
    pf = tmp_path / "p.json"
    pf.write_text(json.dumps(d))
    env = {**os.environ, "AGY_HOOK_POLICY": str(pf), "AGY_HOOK_TRACE": "1"}

    def run(event: str, payload: dict[str, Any]) -> dict[str, Any]:
        out = subprocess.run([exe, str(HOOK), event], input=json.dumps(payload), capture_output=True, text=True,
                             env=env, timeout=30)
        assert "Traceback" not in out.stderr, out.stderr
        return json.loads(out.stdout)
    assert run("PreToolUse", {"toolCall": cmd("ls -la")}) == {"decision": "allow"}
    assert run("PreToolUse", {"toolCall": cmd('cat "~/Library/Keychains/login.keychain-db"')})["decision"] == "deny"
    assert run("PreToolUse", {"toolCall": {"name": "write_file", "args": {"TargetFile": "notes.txt",
                                                                          "CodeContent": "AKIA" + "IOSFODNN7EXAMPLE "
                                                                          "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"}}}
               )["decision"] == "deny"
    assert run("SessionStart", {}) == {} and run("PostToolUse", {"toolCall": cmd("ls")}) == {}
