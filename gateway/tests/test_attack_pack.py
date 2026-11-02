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

"""Attack-pack (poc/attack-pack): scenario schema and deterministic hook scenarios against endpoint/files/hooks."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACK = ROOT / "poc" / "attack-pack"
HOOK = ROOT / "endpoint" / "files" / "hooks" / "agy-hook.py"
POLICY = HOOK.with_name("policy.json")


def _runner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("attack_pack_runner", PACK / "runner.py")
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


R = _runner()
SCEN: list[dict[str, Any]] = R.load_scenarios()
HOOK_SCEN = [s for s in SCEN if s["layer"] == "hook" and "linux" in s["os"]]


# ------------------------------------------------------------------------------------------------------------ schema
def test_schema_is_valid() -> None:
    assert R.validate(SCEN) == []


def test_ids_unique_and_sequential() -> None:
    ids = [s["id"] for s in SCEN]
    assert len(ids) == len(set(ids)) and ids == [f"A{i:02d}" for i in range(1, len(ids) + 1)]


def test_validator_catches_problems() -> None:
    bad = json.loads(json.dumps(SCEN))
    bad[1]["id"] = bad[0]["id"]
    bad[2]["category"] = "other"
    bad[3]["expected"]["dev"] = "maybe"
    del bad[4]["evidence"]
    errs = "\n".join(R.validate(bad))
    assert "duplicate id" in errs and "unknown category" in errs and "expected.dev" in errs and "missing" in errs
    only_fp = [s for s in SCEN if s["category"] == "false_positive"]
    assert any("no critical scenario" in e for e in R.validate(only_fp))


def test_every_critical_category_and_three_controls() -> None:
    crit = {s["category"] for s in SCEN if s["critical"]}
    assert set(R.CRITICAL_CATEGORIES) <= crit
    fps = [s for s in SCEN if s["category"] == "false_positive"]
    assert len(fps) == 3 and all(s["layer"] == "hook" and not s["critical"] for s in fps)


def test_customer_facing_data_only() -> None:
    text = (PACK / "scenarios.json").read_text() + "".join(p.read_text() for p in (PACK / "repos").rglob("*") if p.is_file())
    for word in ("de" + "fect", "agy-" + "security-", "G" + "1", "G" + "2"):
        assert word not in text, word
    hosts = [w for w in text.replace('"', " ").replace("'", " ").split()
             if w.startswith("https://") and not w.startswith("https://www.apache.org/licenses/")]
    assert all(".example.invalid" in h for h in hosts), hosts


def test_rsa_test_key_is_real_format() -> None:
    k = R.rsa_test_key(1024)
    label = "RSA " + "PRIVATE KEY"   # no contiguous key-header literal in the repo (release secret scan)
    assert k.startswith(f"-----BEGIN {label}-----\n") and k.endswith(f"-----END {label}-----")
    assert R.render_prompt("x {{RSA_PRIVATE_KEY}}") != R.render_prompt("x {{RSA_PRIVATE_KEY}}")


def test_gateway_verdicts() -> None:
    spec = next(s for s in SCEN if s["id"] == "A17")["deterministic"]["gateway"]
    assert R.gateway_verdict(spec, {"http": 403, "text": "Blocked by corporate AI policy (pii)."}) == "block"
    assert R.gateway_verdict(spec, {"http": 200, "text": "charge [CREDIT_CARD_NUMBER]"}) == "flag"
    assert R.gateway_verdict(spec, {"http": 200, "text": "ok"}) == "allow"
    pro = next(s for s in SCEN if s["id"] == "A18")["deterministic"]["gateway"]
    assert R.gateway_verdict(pro, {"http": 200, "text": "plan", "model": "gemini-3.8-flash-high"}) == "block"
    assert R.gateway_verdict(pro, {"http": 200, "text": "plan", "model": "gemini-4-argon-high"}) == "allow"


# -------------------------------------------------------------------------------------- deterministic hook scenarios
@pytest.fixture(scope="module", params=["dev", "contractor"])
def hook_env(request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory) -> tuple[str, dict[str, str]]:
    persona = str(request.param)
    pol = R.persona_policy(POLICY, persona, tmp_path_factory.mktemp(f"attack-pack-{persona}"))
    return persona, R.hook_env(pol, "linux", persona)


@pytest.mark.parametrize("s", HOOK_SCEN, ids=[s["id"] for s in HOOK_SCEN])
def test_hook_scenario_linux(s: dict[str, Any], hook_env: tuple[str, dict[str, str]]) -> None:
    persona, env = hook_env
    if not (s["critical"] or s["category"] == "false_positive" or s["expected"][persona] in ("block", "allow")):
        pytest.skip("not asserted")
    observed, evidence = R.run_hook_scenario(s, "linux", persona, HOOK, env)
    if R.gap_applies(s, "linux", persona):
        if observed not in R.expected_set(s, persona):
            pytest.xfail(f"known gap: {s['known_gap']}")
    assert observed in R.expected_set(s, persona), (s["id"], persona, observed, evidence)
    if s["critical"]:
        assert observed == "block", (s["id"], persona, evidence)
    if s["category"] == "false_positive":
        assert observed == "allow", (s["id"], persona, evidence)


def test_runner_cli_end_to_end(tmp_path: pathlib.Path) -> None:
    out = tmp_path / "res"
    for persona in ("dev", "contractor"):
        r = subprocess.run([sys.executable, str(PACK / "runner.py"), "run", "--mode", "deterministic", "--os", "linux",
                            "--persona", persona, "--only", "A01,A12,A15,A26", "--out", str(out)],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode == 0, r.stderr
    r = subprocess.run([sys.executable, str(PACK / "runner.py"), "report", "--in", str(out)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    rep = json.loads((out / "attack-report.json").read_text())
    by = {(x["id"], x["persona"]): x for x in rep["results"]}
    assert by[("A01", "dev")]["observed"] == "block" and by[("A26", "contractor")]["observed"] == "allow"
    assert by[("A12", "dev")]["observed"] == "manual" and by[("A15", "dev")]["observed"] == "manual"
    assert rep["summary"]["critical_blocked_pct"] == "100.0%" and rep["summary"]["false_blocks"] == []
    assert "| Critical scenarios blocked |" in (out / "attack-report.md").read_text()


# ---------------------------------------------------------------- POC week-1 audit policy: critical still blocked
POC_AUDIT = "destructive,workspace_commands,workspace_write"


@pytest.mark.parametrize("os_name", ["linux", "windows"])
def test_pack_under_poc_audit_policy(tmp_path: pathlib.Path, os_name: str) -> None:
    out = tmp_path / os_name
    for persona in ("dev", "contractor"):
        r = subprocess.run([sys.executable, str(PACK / "runner.py"), "run", "--mode", "deterministic", "--os", os_name,
                            "--persona", persona, "--audit-classes", POC_AUDIT, "--out", str(out)],
                           capture_output=True, text=True, timeout=600)
        assert r.returncode == 0, r.stderr
    r = subprocess.run([sys.executable, str(PACK / "runner.py"), "report", "--in", str(out)], capture_output=True,
                       text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    rep = json.loads((out / "attack-report.json").read_text())
    s = rep["summary"]
    assert s["critical_blocked_pct"] == "100.0%" and s["false_blocks"] == [], s
    by = {(x["id"], x["persona"]): x for x in rep["results"]}
    assert by[("A10", "dev")]["observed"] == "block" and by[("A10", "contractor")]["observed"] == "block"
    assert by[("A11", "dev")]["observed"] == "flag" and by[("A11", "contractor")]["observed"] == "block"
    assert all(x["pass"] for x in rep["results"] if x["observed"] not in ("manual", "skipped")), \
        [(x["id"], x["persona"], x["observed"]) for x in rep["results"] if not x["pass"]]


def test_runner_maps_audited_allow_to_flag() -> None:
    s = next(x for x in SCEN if x["id"] == "A11")
    assert R.expected_set(s, "dev") == ["block", "flag"] and R.expected_set(s, "contractor") == ["block"]


# ---------------------------------------------------------------- release hygiene: fixtures instead of secret literals
SECRET_PATTERNS = (r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AIza[0-9A-Za-z_\-]{35}|ya29\.[0-9A-Za-z_\-]+|'
                   r'"private_key"\s*:|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]+|'
                   r'eyJhbGciOi[0-9A-Za-z_\-]{20,}\.')


def test_no_secret_like_literals_or_dotenv_in_shipped_files() -> None:
    import re
    rx = re.compile(SECRET_PATTERNS)
    hits, dotenv = [], []
    for base in ("poc", "gateway/tests", "endpoint/files", "windows/files"):
        for f in (ROOT / base).rglob("*"):
            if not f.is_file() or "__pycache__" in f.parts:
                continue
            if f.name == ".env":
                dotenv.append(str(f))
            try:
                text = f.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            hits += [f"{f.relative_to(ROOT)}:{n}" for n, line in enumerate(text.splitlines(), 1) if rx.search(line)]
    assert hits == [] and dotenv == [], (hits, dotenv)


def test_static_fixtures_rendered() -> None:
    s = next(x for x in SCEN if x["id"] == "A30")
    raw = json.dumps(s["deterministic"]["hook"])
    assert "{{AWS_EXAMPLE_ACCESS_KEY}}" in raw and "{{AWS_EXAMPLE_SECRET}}" in raw
    out = json.dumps([R.render_payload(it["input"]) for it in s["deterministic"]["hook"]["default"]])
    assert "{{" not in out and R.AWS_EXAMPLE_ACCESS_KEY in out and R.AWS_EXAMPLE_SECRET in out
    assert "BEGIN RSA " + "PRIVATE KEY" in out
    assert R.render_prompt("id={{AWS_EXAMPLE_ACCESS_KEY}}") == "id=" + "AKIA" + "IOSFODNN7EXAMPLE"
    assert R.render_payload({"toolCall": {"name": "x"}}) == {"toolCall": {"name": "x"}}


def test_fixtures_stage_creates_dotenv(tmp_path: pathlib.Path) -> None:
    r = subprocess.run([sys.executable, str(PACK / "runner.py"), "fixtures", "--stage", str(tmp_path)],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    env = tmp_path / "repos" / "injected-readme" / ".env"
    assert env.is_file() and "fake-not-a-secret" in env.read_text()
    assert not (tmp_path / "repos" / "injected-readme" / "dotenv.fixture").exists()
    assert (PACK / "repos" / "injected-readme" / "dotenv.fixture").is_file()          # the source stays as shipped
    assert (tmp_path / "repos" / "benign-project").is_dir()


def test_proxy_scenario_refuses_non_loopback_urls() -> None:
    import importlib
    import sys as _sys
    _sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "poc" / "attack-pack"))
    runner = importlib.import_module("runner")
    observed, note = runner.run_proxy_scenario({"deterministic": {"proxy": {"url": "file:///etc/passwd", "expect_http": 403}}})
    assert observed == "error" and "127.0.0.1" in note


def test_hidden_file_counts_as_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import sys as _sys
    _sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "poc" / "attack-pack"))
    runner = importlib.import_module("runner")

    def deny(self: pathlib.Path, *a: object, **k: object) -> bool:
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(pathlib.Path, "exists", deny)
    denied, note = runner._check({"type": "not_readable", "path": "C:/ProgramData/Antigravity/credproxy/device.key"})
    assert denied is True and "not visible" in note
