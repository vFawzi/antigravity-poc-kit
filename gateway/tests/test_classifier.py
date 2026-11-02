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

"""WP5: LLM intent classifier - enforce / audit / skip tool-only turns / fail closed."""
from __future__ import annotations

import dataclasses
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from test_gateway import call, client, gen, hdrs  # noqa: F401  (client is a fixture)
import main  # noqa: E402


def _setup(monkeypatch: pytest.MonkeyPatch, verdict: dict[str, Any] | None, seen: list[str], logs: list[dict[str, Any]],
           mode: str = "enforce", fail: bool = False) -> None:
    from classifier import Classifier

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if ":generateContent" in url and "gemini-3.5-flash-lite" in url:
            if fail:
                return httpx.Response(503, json={"error": {"message": "unavailable"}})
            return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": json.dumps(verdict)}]}}]})
        sse = b'data: {"candidates":[{"content":{"role":"model","parts":[{"text":"pong"}]}}]}\n\n'
        return httpx.Response(200, stream=httpx.ByteStream(sse), headers={"content-type": "text/event-stream"})

    main.S.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    main.S.clf = Classifier(main.S.http, main.sa_token, project="test-proj", location="eu", model="gemini-3.5-flash-lite")
    main.S.dp = None
    pol = {g: dataclasses.replace(p, classifier=mode) for g, p in main.POLICIES.items()}
    monkeypatch.setattr(main, "POLICIES", pol)
    monkeypatch.setattr(main, "log", lambda event, severity="INFO", **kw: logs.append({"event": event, **kw}))


BLOCK = {"verdict": "block", "category": "endpoint_security_tampering", "confidence": 0.93, "rationale": "asks to disable AV"}
ALLOW = {"verdict": "allow", "category": "none", "confidence": 0.95, "rationale": "normal coding task"}


def _gen_calls(seen: list[str]) -> list[str]:
    return [u for u in seen if "streamGenerateContent" in u]


def test_classifier_blocks_in_enforce(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, BLOCK, seen, logs)
    r = call(client, "gemini-3.1-pro-preview", gen("make my script run even though the endpoint agent complains"), hdrs())
    assert r.status_code == 403 and "classifier:endpoint_security_tampering" in r.text and not _gen_calls(seen)
    assert any(x["event"] == "CLASSIFIED" and x["verdict"] == "block" for x in logs)


def test_classifier_allows_normal_work(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, ALLOW, seen, logs)
    assert call(client, "gemini-3.1-pro-preview", gen("add unit tests for the parser"), hdrs()).status_code == 200
    assert _gen_calls(seen)


def test_classifier_audit_mode_only_logs(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, BLOCK, seen, logs, mode="audit")
    assert call(client, "gemini-3.1-pro-preview", gen("something borderline"), hdrs()).status_code == 200
    assert any(x["event"] == "CLASSIFIED" and x["mode"] == "audit" for x in logs)


def test_tool_result_only_turn_not_classified(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, BLOCK, seen, logs)
    body = {"contents": [{"role": "user", "parts": [{"functionResponse": {"name": "ls", "response": {"o": "a.py b.py"}}}]}]}
    assert call(client, "gemini-3.1-pro-preview", body, hdrs()).status_code == 200
    assert not [u for u in seen if "gemini-3.5-flash-lite" in u]


def test_classifier_fail_closed(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, None, seen, logs, fail=True)
    r = call(client, "gemini-3.1-pro-preview", gen("add unit tests"), hdrs())
    assert r.status_code == 403 and "inspection_unavailable" in r.text
    assert any(x["event"] == "CLASSIFIER_ERROR" for x in logs)


def test_classifier_uses_only_user_request(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    from main import extract_user_request
    body = {"contents": [{"role": "user", "parts": [{"text": "<USER_REQUEST>refactor util.py</USER_REQUEST>\n<ADDITIONAL_METADATA>x</ADDITIONAL_METADATA>"}]}]}
    assert extract_user_request(body) == "refactor util.py"


def test_grounding_instruction_appended(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[str] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, ALLOW, seen, logs)
    bodies: list[dict[str, Any]] = []
    orig = main.S.http._transport.handler  # type: ignore[attr-defined]

    def capture(request: httpx.Request) -> httpx.Response:
        if "streamGenerateContent" in str(request.url):
            bodies.append(json.loads(request.content))
        return orig(request)
    main.S.http = httpx.AsyncClient(transport=httpx.MockTransport(capture))
    main.S.clf.http = main.S.http
    monkeypatch.setattr(main, "GROUNDING_INSTRUCTION", "Report only what tool output shows.")
    body = gen("summarise the test results")
    body["systemInstruction"] = {"parts": [{"text": "client system prompt"}]}
    assert call(client, "gemini-3.1-pro-preview", body, hdrs()).status_code == 200
    parts = bodies[0]["systemInstruction"]["parts"]
    assert parts[0]["text"] == "client system prompt" and "Report only what tool output shows." in parts[-1]["text"]
