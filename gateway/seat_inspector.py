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

"""Seat-mode prompt-log inspector (detect and respond).

In seat mode Antigravity calls Google directly, so nothing can be blocked inline. Gemini Enterprise writes every
inference request and response to the customer project's Cloud Logging
(businessaicode.googleapis.com/inference_request | inference_response, with labels user_id, trajectory_id, model).
A log sink forwards them to Pub/Sub; this module turns each entry into the text the gateway engines already
inspect. Detection, flagging and evidence live in main.py (same rules, Model Armor, classifier, SDP).
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import Any

USER_REQUEST = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.S)
REQUEST_LOG = "businessaicode.googleapis.com%2Finference_request"
RESPONSE_LOG = "businessaicode.googleapis.com%2Finference_response"
MAX_CHARS = 50_000


@dataclass
class SeatEntry:
    kind: str                     # "request" | "response"
    user: str                     # e-mail (labels.user_id without the "user:" prefix)
    text: str                     # what the user typed (request) or what the model answered (response)
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    location: str = ""
    experience: str = ""          # catalogue model ID incl. effort (jsonPayload.experience), e.g. gemini-3.8-flash-low


def decode_push(envelope: dict[str, Any]) -> dict[str, Any]:
    """Pub/Sub push envelope -> Cloud Logging LogEntry (dict). Raises ValueError on malformed input."""
    data = (envelope.get("message") or {}).get("data")
    if not data:
        raise ValueError("no message.data")
    return json.loads(base64.b64decode(data))


def _content(msg: dict[str, Any]) -> str:
    c = msg.get("content", "")
    return c if isinstance(c, str) else json.dumps(c, ensure_ascii=False, default=str)


def parse_entry(entry: dict[str, Any]) -> SeatEntry | None:
    """LogEntry -> SeatEntry, or None for entries the inspector ignores."""
    log_name = str(entry.get("logName", ""))
    labels = {k: str(v) for k, v in (entry.get("labels") or {}).items()}
    user = labels.get("user_id", "").removeprefix("user:")
    payload = entry.get("jsonPayload") or {}
    loc = str(((entry.get("resource") or {}).get("labels") or {}).get("location", ""))
    if log_name.endswith(REQUEST_LOG):
        msgs = ((payload.get("input") or {}).get("messages")) or []
        # latest user turn + anything after it that isn't the model (tool output fed back to the model)
        last_model = max((i for i, m in enumerate(msgs) if str(m.get("author", "")).upper() == "MODEL"), default=-1)
        tail = [m for m in msgs[last_model + 1:] if str(m.get("author", "")).upper() != "MODEL"]
        chunks: list[str] = []
        for m in tail:
            c = _content(m)
            reqs = USER_REQUEST.findall(c)
            chunks.extend(r.strip() for r in reqs) if reqs else chunks.append(c)
        text = "\n".join(x for x in chunks if x)[:MAX_CHARS]
        kind = "request"
    elif log_name.endswith(RESPONSE_LOG):
        cands = ((payload.get("output") or {}).get("candidates")) or []
        text = "\n".join(_content(m) for c in cands for m in (c.get("messages") or [])
                         if str(m.get("author", "MODEL")).upper() == "MODEL")[:MAX_CHARS]
        kind = "response"
    else:
        return None
    if not text.strip():
        return None
    return SeatEntry(kind=kind, user=user, text=text, labels=labels, timestamp=str(entry.get("timestamp", "")),
                     location=loc, experience=str(payload.get("experience", "")))



def model_allowed(model: str, patterns: list[str] | None, aux: list[str] | None = None) -> bool:
    """True when `model` (catalogue ID incl. effort) is allowed: no policy for the group (None), an auxiliary helper
    model, an exact match, or a prefix match for entries ending in '*'. An empty pattern list allows nothing."""
    if patterns is None or not model:
        return True
    m = model.strip().lower()
    if m in {a.strip().lower() for a in (aux or [])}:
        return True
    for p in patterns:
        p = p.strip().lower()
        if (p.endswith("*") and m.startswith(p[:-1])) or m == p:
            return True
    return False


class ViolationCounter:
    """Per-user sliding-window counter (in memory, per instance) for the containment threshold."""

    def __init__(self, window_s: float = 3600.0) -> None:
        self.window_s = window_s
        self._hits: dict[str, list[tuple[float, str]]] = {}

    def add(self, user: str, now: float, key: str = "") -> int:
        """Record a violation; returns the number of distinct keys (e.g. conversation turns) in the window.
        Without a key every call counts."""
        hits = [(t, k) for t, k in self._hits.get(user, []) if t > now - self.window_s]
        if not key or all(k != key for _, k in hits):
            hits.append((now, key or f"_{now}"))
        self._hits[user] = hits
        return len(hits)


VPCSC_TYPE = "type.googleapis.com/google.cloud.audit.VpcServiceControlAuditMetadata"


def parse_vpcsc_violation(entry: dict[str, Any]) -> dict[str, str] | None:
    """VPC-SC denial of a seat API call (e.g. a stolen refresh token used off the perimeter) -> facts, else None."""
    pp = entry.get("protoPayload") or {}
    meta = pp.get("metadata") or {}
    if meta.get("@type") != VPCSC_TYPE or pp.get("serviceName") != "businessaicode.googleapis.com":
        return None
    user = str((pp.get("authenticationInfo") or {}).get("principalEmail", ""))
    if not user:
        return None
    return {"user": user, "caller_ip": str((pp.get("requestMetadata") or {}).get("callerIp", "")),
            "method": str(pp.get("methodName", "")).rsplit(".", 1)[-1],
            "reason": str(meta.get("violationReason", "")), "timestamp": str(entry.get("timestamp", "")),
            "dry_run": "true" if meta.get("dryRun") else "false"}


def unassign_body(user: str, delete_user: bool = False) -> dict[str, Any]:
    """Gemini Enterprise batchUpdateUserLicenses body that removes the licence from one user."""
    return {"inlineSource": {"userLicenses": [{"userPrincipal": user}], "updateMask": "userPrincipal,licenseConfig"},
            "deleteUnassignedUserLicenses": delete_user}


def severity(findings: list[str], pci_scope: bool) -> str:
    """high = act now (containment candidate); medium = review."""
    high = ("category:", "classifier:", "model_armor:pi_and_jailbreak", "model_armor:malicious_uris")
    if any(f.startswith(high) for f in findings):
        return "high"
    if pci_scope and any("sensitive_data" in f or f == "model_armor:sdp" for f in findings):
        return "high"
    return "medium"
