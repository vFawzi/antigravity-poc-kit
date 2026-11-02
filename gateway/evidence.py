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

"""Prompt evidence for BLOCKED prompts (PROMPT_LOGGING = deidentified | evidence).

Tier 1 (triage, goes into the audit event / BigQuery):
  the prompt with sensitive values replaced by reversible SDP tokens (CryptoDeterministicConfig, surrogate
  AGY_TOKEN, token key wrapped by a Cloud HSM key). Same value -> same token, so incidents correlate.
Tier 2 (forensics, evidence mode only):
  the exact original, encrypted directly with a Cloud HSM key in <=48 KiB chunks (AAD = incident:chunk) and
  written create-only to a retention-locked bucket. The gateway identity can encrypt but never decrypt or read.

Restore happens outside the gateway (scripts/investigate.sh) under a Privileged Access Manager grant.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

TOKEN_INFOTYPE = "AGY_TOKEN"
# EU banking + PCI + credentials. Extend in one place; restore uses the surrogate type, not this list.
INFO_TYPES: tuple[str, ...] = (
    "CREDIT_CARD_NUMBER", "CREDIT_CARD_TRACK_NUMBER", "IBAN_CODE", "SWIFT_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "PERSON_NAME", "STREET_ADDRESS", "DATE_OF_BIRTH", "PASSPORT", "NETHERLANDS_BSN_NUMBER", "BELGIUM_NATIONAL_ID_CARD_NUMBER",
    "GERMANY_IDENTITY_CARD_NUMBER", "FRANCE_NIR", "IP_ADDRESS", "GCP_CREDENTIALS", "GCP_API_KEY", "AUTH_TOKEN",
    "AWS_CREDENTIALS", "AZURE_AUTH_TOKEN", "ENCRYPTION_KEY", "PASSWORD", "JSON_WEB_TOKEN", "HTTP_COOKIE",
)
CHUNK = 48 * 1024          # Cloud KMS direct encryption accepts up to 64 KiB plaintext
DLP_MAX_CHARS = 400_000    # SDP content request limit is 0.5 MB
TIER1_MAX_CHARS = 60_000   # keeps the audit entry well below the 256 KB Cloud Logging limit


class Evidence:
    def __init__(self, http: httpx.AsyncClient, token: Callable[[], Awaitable[str]], *, project: str, location: str,
                 token_key: str, wrapped_secret: str, bucket: str, evidence_key: str) -> None:
        self.http, self.token = http, token
        self.project, self.location = project, location
        self.token_key, self.wrapped_secret = token_key, wrapped_secret
        self.bucket, self.evidence_key = bucket, evidence_key
        self._wrapped: str | None = None

    @property
    def tier1(self) -> bool:
        return bool(self.token_key and self.wrapped_secret)

    @property
    def tier2(self) -> bool:
        return bool(self.bucket and self.evidence_key)

    async def _h(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {await self.token()}", "Content-Type": "application/json"}

    async def _wrapped_key(self) -> str:
        """base64 of the KMS-wrapped token key (Secret Manager payload is the raw ciphertext)."""
        if self._wrapped is None:
            r = await self.http.get(f"https://secretmanager.googleapis.com/v1/{self.wrapped_secret}/versions/latest:access",
                                    headers=await self._h(), timeout=15)
            r.raise_for_status()
            self._wrapped = r.json()["payload"]["data"]
        return self._wrapped

    async def crypto_config(self) -> dict[str, Any]:
        return {"cryptoKey": {"kmsWrapped": {"wrappedKey": await self._wrapped_key(), "cryptoKeyName": self.token_key}},
                "surrogateInfoType": {"name": TOKEN_INFOTYPE}}

    async def deidentify(self, text: str) -> tuple[str, list[str]]:
        body = {
            "inspectConfig": {"infoTypes": [{"name": n} for n in INFO_TYPES], "minLikelihood": "POSSIBLE"},
            "deidentifyConfig": {"infoTypeTransformations": {"transformations": [
                {"primitiveTransformation": {"cryptoDeterministicConfig": await self.crypto_config()}}]}},
            "item": {"value": text[:DLP_MAX_CHARS]},
        }
        url = f"https://dlp.googleapis.com/v2/projects/{self.project}/locations/{self.location}/content:deidentify"
        r = await self.http.post(url, headers=await self._h(), json=body, timeout=30)
        r.raise_for_status()
        out = r.json()
        found = sorted({s.get("infoType", {}).get("name", "")
                        for s in out.get("overview", {}).get("transformationSummaries", []) if s.get("infoType")})
        return out.get("item", {}).get("value", "")[:TIER1_MAX_CHARS], found

    async def seal(self, incident: str, record: dict[str, Any]) -> str:
        """Encrypt the record with the HSM evidence key and store it create-only. Returns the gs:// URI."""
        raw = json.dumps(record, ensure_ascii=False, default=str).encode()
        chunks: list[dict[str, str]] = []
        h = await self._h()
        for i in range(0, max(len(raw), 1), CHUNK):
            aad = f"{incident}:{i // CHUNK}".encode()
            r = await self.http.post(f"https://cloudkms.googleapis.com/v1/{self.evidence_key}:encrypt", headers=h, timeout=20,
                                     json={"plaintext": base64.b64encode(raw[i:i + CHUNK]).decode(),
                                           "additionalAuthenticatedData": base64.b64encode(aad).decode()})
            r.raise_for_status()
            j = r.json()
            chunks.append({"aad": aad.decode(), "key_version": j.get("name", ""), "ciphertext": j["ciphertext"]})
        now = dt.datetime.now(dt.timezone.utc)
        name = f"{now:%Y/%m/%d}/{incident}.json"
        doc = {"format": "agy-evidence/v1", "incident": incident, "created": now.isoformat(), "key": self.evidence_key,
               "chunks": chunks}
        r = await self.http.post(f"https://storage.googleapis.com/upload/storage/v1/b/{self.bucket}/o",
                                 params={"uploadType": "media", "name": name, "ifGenerationMatch": "0"},
                                 headers={**h, "Content-Type": "application/json"},
                                 content=json.dumps(doc).encode(), timeout=30)
        r.raise_for_status()
        return f"gs://{self.bucket}/{name}"
