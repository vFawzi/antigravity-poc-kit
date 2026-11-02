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

"""Sensitive-data protection in the request and response path (Sensitive Data Protection templates, EU region).

Request side : sensitive values in the latest user turn and in tool results are MASKED before the prompt goes to
               the model (for groups in PCI scope the request is blocked instead - decided by the caller).
Response side: streamed model output is inspected in windows. mask -> values replaced by [INFO_TYPE];
               block -> the stream stops with a policy notice. A short tail is carried between windows so a value
               split across two chunks is still detected. A window is flushed when it reaches `window` chars OR
               when its oldest text has been held for `flush_ms` (time-bound: the client never waits on a full
               window while the model is slow - the official gateway contract asks gateways not to buffer).
Masking is irreversible (replace-with-infotype); reversible tokens are only used for blocked-prompt evidence.
"""
from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx

WINDOW = 1200      # default max chars of model text held back before inspection (latency vs. coverage)
FLUSH_MS = 500     # default max time the oldest held text waits before it is inspected and sent
TAIL = 64          # chars carried into the next window (values split across chunks)
MAX_VALUE = 50_000


class DataProtect:
    def __init__(self, http: httpx.AsyncClient, token: Callable[[], Awaitable[str]], *, project: str, location: str,
                 inspect_template: str, deidentify_template: str, window: int = WINDOW,
                 flush_ms: int = FLUSH_MS) -> None:
        self.http, self.token = http, token
        self.window, self.flush_s = max(window, TAIL * 2), max(flush_ms, 50) / 1000
        self.url = f"https://dlp.googleapis.com/v2/projects/{project}/locations/{location}/content:deidentify"
        self.inspect_template, self.deidentify_template = inspect_template, deidentify_template

    @property
    def enabled(self) -> bool:
        return bool(self.inspect_template and self.deidentify_template)

    async def mask_values(self, values: list[str]) -> tuple[list[str], list[str]]:
        """Mask a batch of strings in one call (table item). Returns (masked values, info types found)."""
        if not values:
            return values, []
        body = {"inspectTemplateName": self.inspect_template, "deidentifyTemplateName": self.deidentify_template,
                "item": {"table": {"headers": [{"name": "v"}],
                                   "rows": [{"values": [{"stringValue": v[:MAX_VALUE]}]} for v in values]}}}
        r = await self.http.post(self.url, json=body, timeout=30,
                                 headers={"Authorization": f"Bearer {await self.token()}", "Content-Type": "application/json"})
        r.raise_for_status()
        out = r.json()
        rows = out.get("item", {}).get("table", {}).get("rows", [])
        masked = [(row.get("values") or [{}])[0].get("stringValue", "") for row in rows] or values
        found = sorted({s.get("infoType", {}).get("name", "") for s in out.get("overview", {}).get("transformationSummaries", [])
                        if s.get("infoType") and any(int(r.get("count", 0)) > 0 for r in s.get("results", [{"count": 1}]))})
        return masked, found

    # ------------------------------------------------------------------ request
    async def mask_request(self, body: dict[str, Any]) -> list[str]:
        """Mask text parts and tool results of the latest user turn in place. Returns info types masked."""
        contents = body.get("contents") or []
        turn = next((c for c in reversed(contents) if c.get("role", "user") == "user"), None)
        if not turn:
            return []
        refs: list[tuple[dict[str, Any], str]] = []
        values: list[str] = []
        for part in turn.get("parts", []) or []:
            if isinstance(part.get("text"), str):
                refs.append((part, "text")); values.append(part["text"])
            elif isinstance(part.get("functionResponse"), dict):
                refs.append((part["functionResponse"], "response"))
                values.append(json.dumps(part["functionResponse"].get("response", ""), ensure_ascii=False, default=str))
        masked, found = await self.mask_values(values)
        if not found:
            return []
        for (obj, key), new, old in zip(refs, masked, values):
            if new == old:
                continue
            if key == "text":
                obj["text"] = new
            else:
                try:
                    obj["response"] = json.loads(new)
                except json.JSONDecodeError:
                    obj["response"] = {"content": new}
        return found

    # ------------------------------------------------------------------ response (SSE stream)
    async def guard_stream(self, upstream: AsyncIterator[bytes], mode: str, on_hit: Callable[[list[str]], None],
                           notice: Callable[[], bytes],
                           on_error: Callable[[Exception], None] | None = None,
                           stats: dict[str, Any] | None = None) -> AsyncIterator[bytes]:
        """Fail-closed wrapper: if inspection is unavailable the stream ends with a policy notice.
        `stats` (optional) is filled with flushes, timed_flushes and max_hold_ms for the latency audit."""
        try:
            async for out in self._guard(upstream, mode, on_hit, notice, stats if stats is not None else {}):
                yield out
        except (httpx.HTTPError, KeyError, ValueError) as e:
            if on_error:
                on_error(e)
            yield notice()

    async def _guard(self, upstream: AsyncIterator[bytes], mode: str, on_hit: Callable[[list[str]], None],
                     notice: Callable[[], bytes], stats: dict[str, Any]) -> AsyncIterator[bytes]:
        """Re-emit an SSE stream with model text inspected in windows. Non-text events keep their order.

        Upstream chunks are pumped into a queue so the consumer can wait with a deadline (cancelling a queue
        read is safe; cancelling the HTTP read itself is not)."""
        buf = b""
        pending = ""
        carry = ""
        held_since: float | None = None        # arrival time of the oldest text not yet sent
        meta: dict[str, Any] | None = None
        stats.update(flushes=0, timed_flushes=0, max_hold_ms=0)
        q: asyncio.Queue[bytes | BaseException | None] = asyncio.Queue()

        async def pump() -> None:
            try:
                async for c in upstream:
                    await q.put(c)
                await q.put(None)
            except Exception as e:  # noqa: BLE001 - re-raised in the consumer (fail closed)
                await q.put(e)

        async def flush(final: bool, timed: bool = False) -> tuple[list[bytes], bool]:
            nonlocal pending, carry, held_since
            text = carry + pending
            pending = ""
            if not text:
                held_since = None
                return [], False
            if final:
                head, carry = text, ""
            else:
                cut = max(text.rfind(" ", 0, len(text) - TAIL), text.rfind("\n", 0, len(text) - TAIL))
                if cut <= 0 and timed:          # too short to keep a safe tail: wait for more text
                    carry = text
                    held_since = time.monotonic()
                    return [], False
                head, carry = (text[:cut + 1], text[cut + 1:]) if cut > 0 else (text, "")
            if held_since is not None:
                stats["max_hold_ms"] = max(stats["max_hold_ms"], int((time.monotonic() - held_since) * 1000))
            held_since = time.monotonic() if carry else None
            if not head:
                return [], False
            stats["flushes"] += 1
            stats["timed_flushes"] += int(timed)
            masked, found = await self.mask_values([head])
            if found:
                on_hit(found)
                if mode == "block":
                    return [notice()], True
                head = masked[0]
            return [sse_text(head)], False

        task = asyncio.create_task(pump())
        try:
            while True:
                timeout = None if held_since is None else max(0.0, held_since + self.flush_s - time.monotonic())
                try:
                    item = await asyncio.wait_for(q.get(), timeout)
                except asyncio.TimeoutError:
                    out, stop = await flush(final=False, timed=True)
                    for o in out:
                        yield o
                    if stop:
                        return
                    continue
                if item is None:
                    break
                if isinstance(item, BaseException):
                    raise item
                buf = (buf + item).replace(b"\r\n", b"\n")   # Vertex SSE uses CRLF separators
                while b"\n\n" in buf:
                    raw, buf = buf.split(b"\n\n", 1)
                    line = raw.decode(errors="replace")
                    if not line.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(line[5:].strip())
                    except json.JSONDecodeError:
                        continue
                    text, rest, kind = split_text(ev)
                    if text and held_since is None:
                        held_since = time.monotonic()
                    pending += text
                    if kind == "meta":
                        meta = rest
                    if kind == "other":   # function calls, thoughts, finish reason: flush text first, keep order
                        out, stop = await flush(final=False)
                        for o in out:
                            yield o
                        if stop:
                            return
                        if not await self._mask_parts(rest, mode, on_hit):
                            yield notice()
                            return
                        yield b"data: " + json.dumps(rest, ensure_ascii=False).encode() + b"\n\n"
                    elif len(carry) + len(pending) >= self.window:
                        out, stop = await flush(final=False)
                        for o in out:
                            yield o
                        if stop:
                            return
            out, stop = await flush(final=True)
            for o in out:
                yield o
            if meta and not stop:
                yield b"data: " + json.dumps(meta, ensure_ascii=False).encode() + b"\n\n"
        finally:
            task.cancel()

    async def _mask_parts(self, ev: dict[str, Any], mode: str, on_hit: Callable[[list[str]], None]) -> bool:
        """Mask thought text and function-call arguments of an event in place. False = block."""
        refs: list[tuple[dict[str, Any], str]] = []
        for cand in ev.get("candidates", []):
            for p in cand.get("content", {}).get("parts") or []:
                if isinstance(p.get("text"), str):
                    refs.append((p, "text"))
                elif isinstance(p.get("functionCall"), dict):
                    refs.append((p["functionCall"], "args"))
        if not refs:
            return True
        vals = [r[0]["text"] if r[1] == "text" else json.dumps(r[0].get("args", {}), ensure_ascii=False) for r in refs]
        masked, found = await self.mask_values(vals)
        if not found:
            return True
        on_hit(found)
        if mode == "block":
            return False
        for (obj, key), new in zip(refs, masked):
            if key == "text":
                obj["text"] = new
            else:
                try:
                    obj["args"] = json.loads(new)
                except json.JSONDecodeError:
                    pass
        return True

    async def mask_unary(self, payload: dict[str, Any], mode: str) -> tuple[dict[str, Any] | None, list[str]]:
        """Non-streaming response. Returns (payload or None when blocked, info types)."""
        parts = [p for c in payload.get("candidates", []) for p in (c.get("content", {}).get("parts") or [])
                 if isinstance(p.get("text"), str)]
        masked, found = await self.mask_values([p["text"] for p in parts])
        if not found:
            return payload, []
        if mode == "block":
            return None, found
        for p, m in zip(parts, masked):
            p["text"] = m
        return payload, found


def split_text(ev: dict[str, Any]) -> tuple[str, dict[str, Any] | None, str]:
    """Split an SSE event into (answer text, remainder, kind).

    kind: "text"  - only answer text (buffered)
          "meta"  - text and/or usage / model metadata only (metadata is deferred to the end of the stream)
          "other" - function calls, thoughts or a finish reason (text is flushed first, then the remainder emitted)
    """
    text = ""
    other = False
    rest = json.loads(json.dumps(ev))
    for cand in rest.get("candidates", []):
        parts = cand.get("content", {}).get("parts") or []
        keep = []
        for p in parts:
            if isinstance(p.get("text"), str) and not p.get("thought"):
                text += p["text"]
            else:
                keep.append(p)
        if "content" in cand:
            cand["content"]["parts"] = keep
        if keep or cand.get("finishReason"):
            other = True
    if other:
        return text, rest, "other"
    meta = {k: v for k, v in rest.items() if k != "candidates"}
    return text, (meta or None), ("meta" if meta else "text")


def sse_text(text: str) -> bytes:
    ev = {"candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "index": 0}]}
    return b"data: " + json.dumps(ev, ensure_ascii=False).encode() + b"\n\n"
