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

"""WP2: sensitive-data masking (requests, tool results, streamed and unary responses) and PCI-scope blocking."""
from __future__ import annotations

import dataclasses
import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from test_gateway import call, client, gen, hdrs  # noqa: F401  (client is a fixture)
import main  # noqa: E402

PAN = "4111111111111111"


def _dlp_mask(values: list[str]) -> dict[str, Any]:
    rows, hits = [], 0
    for v in values:
        hits += v.count(PAN)
        rows.append({"values": [{"stringValue": v.replace(PAN, "[CREDIT_CARD_NUMBER]")}]})
    summ = [{"infoType": {"name": "CREDIT_CARD_NUMBER"}, "results": [{"count": str(hits)}]}] if hits else []
    return {"item": {"table": {"rows": rows}}, "overview": {"transformationSummaries": summ}}


def _sse(text_chunks: list[str]) -> list[bytes]:
    out = [b"data: " + json.dumps({"candidates": [{"content": {"role": "model", "parts": [{"text": t}]}}]}).encode() + b"\r\n\r\n"
           for t in text_chunks]
    out.append(b"data: " + json.dumps({"candidates": [{"content": {"role": "model", "parts": []}, "finishReason": "STOP"}],
                                       "usageMetadata": {"totalTokenCount": 9}}).encode() + b"\r\n\r\n")
    return out


def _setup(monkeypatch: pytest.MonkeyPatch, seen: list[dict[str, Any]], logs: list[dict[str, Any]],
           answer: list[str] | None = None, dlp_down: bool = False, unary: dict[str, Any] | None = None) -> None:
    from dataprotect import DataProtect

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        body = json.loads(request.content) if request.content else None
        seen.append({"url": url, "body": body})
        if "content:deidentify" in url:
            if dlp_down:
                return httpx.Response(503, json={"error": {"message": "down"}})
            return httpx.Response(200, json=_dlp_mask([r["values"][0]["stringValue"] for r in body["item"]["table"]["rows"]]))
        if "modelarmor" in url:
            st = "MATCH_FOUND" if PAN in json.dumps(body) else "NO_MATCH_FOUND"
            return httpx.Response(200, json={"sanitizationResult": {"filterMatchState": st, "filterResults": {
                "sdp": {"sdpFilterResult": {"inspectResult": {"matchState": st}}}}}})
        if unary is not None:
            return httpx.Response(200, json=unary)
        return httpx.Response(200, stream=httpx.ByteStream(b"".join(_sse(answer or ["pong"]))),
                              headers={"content-type": "text/event-stream"})

    main.S.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    main.S.dp = DataProtect(main.S.http, main.sa_token, project="test-proj", location="europe-west4",
                            inspect_template="projects/p/locations/l/inspectTemplates/agy-sensitive",
                            deidentify_template="projects/p/locations/l/deidentifyTemplates/agy-mask")
    monkeypatch.setattr(main, "MA_ENABLED", True)
    monkeypatch.setattr(main, "AUDIT_RESPONSES", False)
    pol = dict(main.POLICIES)
    pol["agy-contractor"] = dataclasses.replace(pol["agy-contractor"], pci_scope=True)
    monkeypatch.setattr(main, "POLICIES", pol)
    monkeypatch.setattr(main, "log", lambda event, severity="INFO", **kw: logs.append({"event": event, **kw}))


def _vertex(seen: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [x for x in seen if "aiplatform" in x["url"]]


def test_request_pan_masked_for_dev(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs)
    r = call(client, "gemini-3.1-pro-preview", gen(f"summarise this customer record, card {PAN}"), hdrs())
    assert r.status_code == 200
    sent = json.dumps(_vertex(seen)[0]["body"])
    assert PAN not in sent and "[CREDIT_CARD_NUMBER]" in sent
    assert any(x["event"] == "REQUEST_MASKED" and x["infotypes"] == ["CREDIT_CARD_NUMBER"] for x in logs)


def test_tool_result_pan_masked(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs)
    body = {"contents": [{"role": "user", "parts": [{"functionResponse": {"name": "read_file",
                                                                          "response": {"output": f"name,card\nA,{PAN}"}}}]}]}
    assert call(client, "gemini-3.1-pro-preview", body, hdrs()).status_code == 200
    sent = _vertex(seen)[0]["body"]["contents"][-1]["parts"][0]["functionResponse"]["response"]
    assert PAN not in json.dumps(sent) and "[CREDIT_CARD_NUMBER]" in sent["output"]


def test_request_pan_blocked_for_pci_scope(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs)
    r = call(client, "gemini-3.1-pro-preview", gen(f"card {PAN}"), hdrs("contractor", "agy-contractor"))
    assert r.status_code == 403 and "sensitive_data:pci_scope" in r.text and not _vertex(seen)


def test_stream_response_masked_even_when_split(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs, answer=["The card on file is 41111111", "11111111 and it expires soon."])
    r = call(client, "gemini-3.1-pro-preview", gen("show the record"), hdrs())
    assert r.status_code == 200
    assert PAN not in r.text and "[CREDIT_CARD_NUMBER]" in r.text and '"finishReason": "STOP"' in r.text
    assert any(x["event"] == "RESPONSE_MASKED" for x in logs)


def test_stream_response_blocked_for_pci_scope(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs, answer=[f"Here it is: {PAN} "])
    r = call(client, "gemini-3.1-pro-preview", gen("show the record"), hdrs("contractor", "agy-contractor"))
    assert PAN not in r.text and "sensitive_data_in_response" in r.text
    assert any(x["event"] == "RESPONSE_BLOCKED" for x in logs)


def test_stream_fails_closed_when_inspection_down(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs, answer=[f"value {PAN} "], dlp_down=True)
    r = call(client, "gemini-3.1-pro-preview", gen("show the record"), hdrs())
    assert PAN not in r.text and "Blocked by corporate AI policy" in r.text
    assert any(x["event"] == "DATA_PROTECTION_ERROR" for x in logs)


def test_clean_stream_passes_unchanged(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs, answer=["hello ", "world"])
    r = call(client, "gemini-3.1-pro-preview", gen("say hi"), hdrs())
    assert "hello world" in r.text.replace('", "', "") or ("hello" in r.text and "world" in r.text)
    assert not any(x["event"].startswith("RESPONSE_") for x in logs)


def test_unary_response_masked(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    seen: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    _setup(monkeypatch, seen, logs, unary={"candidates": [{"content": {"role": "model", "parts": [{"text": f"card {PAN}"}]}}]})
    r = client.post("/v1beta/models/gemini-3.1-pro-preview:generateContent", json=gen("record"), headers=hdrs())
    assert r.status_code == 200 and PAN not in r.text and "[CREDIT_CARD_NUMBER]" in r.text


# ---------------------------------------------------------------- time-bound flush (official "don't buffer" contract)
def _dp(window: int = 1200, flush_ms: int = 100) -> Any:
    from dataprotect import DataProtect

    dp = DataProtect(httpx.AsyncClient(), main.sa_token, project="p", location="l", inspect_template="i",
                     deidentify_template="d", window=window, flush_ms=flush_ms)

    async def fake_mask(values: list[str]) -> tuple[list[str], list[str]]:
        found = ["CREDIT_CARD_NUMBER"] if any(PAN in v for v in values) else []
        return [v.replace(PAN, "[CREDIT_CARD_NUMBER]") for v in values], found
    dp.mask_values = fake_mask  # type: ignore[method-assign]
    return dp


def test_stream_flushes_on_time_while_model_is_slow() -> None:
    import asyncio
    import time

    async def slow() -> Any:
        yield _sse(["The deployment finished without errors and all checks passed as expected today. "])[0]
        await asyncio.sleep(1.0)                      # model stalls: text must not wait for the window
        for c in _sse(["Done."]):
            yield c

    async def run() -> tuple[float, list[bytes], dict[str, Any]]:
        stats: dict[str, Any] = {}
        t0, first, out = time.monotonic(), 0.0, []
        async for o in _dp(flush_ms=100).guard_stream(slow(), "mask", lambda f: None, lambda: b"N", None, stats):
            first = first or time.monotonic() - t0
            out.append(o)
        return first, out, stats

    first, out, stats = asyncio.run(run())
    assert first < 0.6, f"first text after {first:.2f}s - stream was buffered"
    assert stats["timed_flushes"] >= 1 and stats["max_hold_ms"] < 600
    assert b"deployment" in b"".join(out) and b"Done." in b"".join(out)


def test_timed_flush_keeps_tail_so_split_values_are_still_masked() -> None:
    import asyncio

    async def split() -> Any:
        yield _sse(["This is a long preamble about the customer account and its current billing status. Card on file is 41111111"])[0]
        await asyncio.sleep(0.4)                      # timed flush fires mid-value
        for c in _sse(["11111111 and it expires soon."]):
            yield c

    async def run() -> bytes:
        hits: list[list[str]] = []
        out = [o async for o in _dp(flush_ms=100).guard_stream(split(), "mask", hits.append, lambda: b"N")]
        assert hits
        return b"".join(out)

    body = asyncio.run(run())
    assert PAN.encode() not in body and b"[CREDIT_CARD_NUMBER]" in body
