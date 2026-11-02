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

"""LLM policy classifier (WP5b): a small Gemini model judges the INTENT of the user's request.

Runs after the deterministic topic rules and Model Armor, only on turns that contain user text (tool-result-only
turns of the agent loop are skipped). Structured output: {verdict, category, confidence, rationale}.
Per group: enforce (block on verdict=block at or above the threshold) | audit (log only) | off.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

CATEGORIES: tuple[str, ...] = (
    "none", "access_control_evasion", "endpoint_security_tampering", "mail_impersonation", "data_exfiltration",
    "ransomware_like_file_handling", "phishing_or_site_cloning", "network_attack", "credential_theft", "dlp_evasion",
    "malware_development",
)

SYSTEM = (
    "You are the security policy classifier of a bank's AI coding assistant gateway. Judge only the intent of the "
    "user's request to a coding agent. Answer verdict=block only when the request clearly seeks a prohibited outcome: "
    "weakening access controls or authentication; disabling or evading security software (antivirus, EDR, DLP, MDM, "
    "proxies); sending mail as another person; moving data out of approved channels; ransomware-like encryption or "
    "destruction of files; hosting look-alike websites or login pages; attacking, scanning or flooding systems; "
    "harvesting credentials; building malware. Ordinary software engineering, defensive security work on the user's "
    "own code, explanations of concepts and code review are allowed (verdict=allow, category=none). When unsure, "
    "prefer allow with low confidence. Keep the rationale under 20 words and never repeat sensitive values."
)

SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "verdict": {"type": "STRING", "enum": ["allow", "block"]},
        "category": {"type": "STRING", "enum": list(CATEGORIES)},
        "confidence": {"type": "NUMBER"},
        "rationale": {"type": "STRING"},
    },
    "required": ["verdict", "category", "confidence", "rationale"],
}


class Classifier:
    def __init__(self, http: httpx.AsyncClient, token: Callable[[], Awaitable[str]], *, project: str, location: str,
                 model: str, threshold: float = 0.7, max_chars: int = 8000, cache_ttl: float = 600.0) -> None:
        self.http, self.token = http, token
        self.model, self.threshold, self.max_chars = model, threshold, max_chars
        host = "aiplatform.googleapis.com" if location == "global" else f"aiplatform.{location}.rep.googleapis.com" \
            if location in ("eu", "us") else f"{location}-aiplatform.googleapis.com"
        self.url = f"https://{host}/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent"
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self.cache_ttl = cache_ttl

    @property
    def enabled(self) -> bool:
        return bool(self.model)

    async def classify(self, text: str) -> dict[str, Any]:
        key = hashlib.sha256(text[: self.max_chars].encode()).hexdigest()
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < self.cache_ttl:
            return hit[1]
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM}]},
            "contents": [{"role": "user", "parts": [{"text": "User request to classify:\n<<<\n" + text[: self.max_chars] + "\n>>>"}]}],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 200, "responseMimeType": "application/json",
                                 "responseSchema": SCHEMA, "thinkingConfig": {"thinkingLevel": "low"}},
        }
        r = await self.http.post(self.url, json=body, timeout=15,
                                 headers={"Authorization": f"Bearer {await self.token()}", "Content-Type": "application/json"})
        r.raise_for_status()
        parts = r.json().get("candidates", [{}])[0].get("content", {}).get("parts", [])
        out = json.loads("".join(p.get("text", "") for p in parts if not p.get("thought")))
        out["confidence"] = float(out.get("confidence", 0))
        if out.get("category") not in CATEGORIES:
            out["category"] = "none"
        self._cache[key] = (time.monotonic(), out)
        if len(self._cache) > 2000:
            self._cache.clear()
        return out

    def blocks(self, result: dict[str, Any]) -> bool:
        return result.get("verdict") == "block" and result.get("confidence", 0) >= self.threshold
