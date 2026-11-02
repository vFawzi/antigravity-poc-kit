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

"""AGY Enterprise Gateway (reference implementation) - Antigravity Enterprise Gateway mode, Gemini wire protocol.

Client side: /etc/antigravity/admin_settings.json with
  {"gateway": {"enabled": true, "url": "http://127.0.0.1:8443", "apiKey": "<placeholder>"}}
(gateway.wireProtocol "genai" - the default - is what this gateway serves; "openai" is refused)
points Antigravity at the local agy-credproxy, which adds:
  X-AGY-Device-Token  Google-signed GCE instance identity token (aud=DEVICE_AUDIENCE) - proves a managed device
  X-AGY-User / X-AGY-Group  identity derived by the proxy from the kernel peer uid (never from the client)

Pipeline per generate call:
  device check -> group policy -> category rules + Model Armor (latest user turn + tool results)
  -> tier routing (requested model -> light/default/complex -> per-group Vertex model)
  -> Vertex AI native API (locations/eu) with the gateway SA, client User-Agent forwarded unchanged
  -> streamed response + post-stream Model Armor audit.
"""
from __future__ import annotations

import asyncio
import hashlib
import base64
import hmac
import json
import os
import random
import re
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import google.auth
import google.auth.transport.requests
import httpx

from classifier import Classifier
import seat_inspector as seat
from dataprotect import DataProtect
from evidence import Evidence
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from google.oauth2 import id_token as google_id_token

# --------------------------------------------------------------------------- config


def _env_json(name: str, default: Any) -> Any:
    raw = os.environ.get(name)
    return json.loads(raw) if raw else default


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).lower() == "true"


PROJECT_ID: str = os.environ.get("PROJECT_ID", "")
# Project whose Vertex AI quota and billing model calls use (official contract: when it differs from the gateway's own
# project, the gateway injects X-Goog-User-Project with it). Gateway controls (Model Armor, SDP, classifier) stay in
# PROJECT_ID. Clients never choose it.
INFERENCE_PROJECT: str = os.environ.get("INFERENCE_PROJECT", "") or PROJECT_ID
VERTEX_LOCATION: str = os.environ.get("VERTEX_LOCATION", "eu")
MA_LOCATION: str = os.environ.get("MA_LOCATION", "europe-west4")
MA_TEMPLATE: str = os.environ.get("MA_TEMPLATE", "agy-prompt-guard")
MA_ENABLED: bool = _env_bool("MA_ENABLED", True)
MA_FAIL_CLOSED: bool = _env_bool("MA_FAIL_CLOSED", True)
MA_MAX_CHARS: int = int(os.environ.get("MA_MAX_CHARS", "50000"))
SCAN_TOOL_RESULTS: bool = _env_bool("SCAN_TOOL_RESULTS", True)
AUDIT_RESPONSES: bool = _env_bool("AUDIT_RESPONSES", True) and MA_ENABLED
# blocked-prompt audit trail: none | hash | deidentified (SDP tokens) | evidence (tokens + HSM-encrypted original)
PROMPT_LOGGING: str = os.environ.get("PROMPT_LOGGING", "hash")
DLP_LOCATION: str = os.environ.get("DLP_LOCATION", "europe-west4")
# sensitive-data protection (SDP templates): mask requests/responses; block for groups with pci_scope
SDP_INSPECT_TEMPLATE: str = os.environ.get("SDP_INSPECT_TEMPLATE", "")
SDP_DEID_TEMPLATE: str = os.environ.get("SDP_DEID_TEMPLATE", "")
# LLM policy classifier (intent): model id empty = off; per-group mode enforce | audit | off
CLASSIFIER_MODEL: str = os.environ.get("CLASSIFIER_MODEL", "")
CLASSIFIER_THRESHOLD: float = float(os.environ.get("CLASSIFIER_THRESHOLD", "0.7"))
CLASSIFIER_FAIL_CLOSED: bool = _env_bool("CLASSIFIER_FAIL_CLOSED", True)
# output grounding (WP6): short corporate instruction appended to the client's system instruction ("" = off)
GROUNDING_INSTRUCTION: str = os.environ.get("GROUNDING_INSTRUCTION", "")
# "message": blocks are returned as a normal model reply (visible in CLI and Desktop UI, which hides 403 text)
# "error":   blocks are returned as HTTP 403 PERMISSION_DENIED
BLOCK_RESPONSE_MODE: str = os.environ.get("BLOCK_RESPONSE_MODE", "message")
# Seat mode: the same image runs as the prompt-log inspector (Pub/Sub push of Gemini Enterprise inference logs).
# Off on the gateway service. SEAT_USER_GROUPS maps seat users to policy groups (else SEAT_DEFAULT_GROUP).
SEAT_INSPECTOR: bool = _env_bool("SEAT_INSPECTOR", False)
SEAT_DEFAULT_GROUP: str = os.environ.get("SEAT_DEFAULT_GROUP", "agy-dev")
SEAT_USER_GROUPS: dict[str, str] = _env_json("SEAT_USER_GROUPS", {})
# Automated containment on high-risk findings / stolen-token signals: off | dry_run | enforce (licence unassignment,
# validated: access stops in about 1-2 minutes). Exempt principals are never auto-contained (break-glass, admins).
SEAT_CONTAINMENT: str = os.environ.get("SEAT_CONTAINMENT", "dry_run")
SEAT_CONTAIN_EXEMPT: frozenset[str] = frozenset(u.lower() for u in _env_json("SEAT_CONTAIN_EXEMPT", []))
SEAT_PROJECT: str = os.environ.get("SEAT_PROJECT", "") or PROJECT_ID
SEAT_LOCATION: str = os.environ.get("SEAT_LOCATION", "eu")
# Seat model policy (group -> allowed catalogue IDs / prefix*), helper models never flagged, containment threshold per hour.
SEAT_MODEL_POLICY: dict[str, list[str]] = _env_json("SEAT_MODEL_POLICY", {})
SEAT_AUX_MODELS: list[str] = _env_json("SEAT_AUX_MODELS", [])
SEAT_MODEL_CONTAIN_AFTER: int = max(1, int(os.environ.get("SEAT_MODEL_CONTAIN_AFTER", "3") or 3))
MODEL_VIOLATIONS = seat.ViolationCounter(window_s=3600)   # per instance; counts distinct conversation turns
CONTAINED: dict[str, float] = {}                          # user -> time contained (de-duplicates repeated signals)
# streamed-response inspection: a window is sent at RESPONSE_WINDOW_CHARS or after RESPONSE_FLUSH_MS, whichever first
RESPONSE_WINDOW_CHARS: int = int(os.environ.get("RESPONSE_WINDOW_CHARS", "1200"))
RESPONSE_FLUSH_MS: int = int(os.environ.get("RESPONSE_FLUSH_MS", "500"))

REQUIRE_DEVICE: bool = _env_bool("REQUIRE_DEVICE", True)
# Device mTLS at the internal LB. The LB injects verified client-cert facts + a shared secret header;
# the certificate's SPIFFE device identity must equal the identity token's instance (two bound factors).
REQUIRE_MTLS: bool = _env_bool("REQUIRE_MTLS", False)
LB_HEADER_SECRET: str = os.environ.get("LB_HEADER_SECRET", "")
SPIFFE_PREFIX: str = os.environ.get("SPIFFE_PREFIX", "")
DEVICE_AUDIENCE: str = os.environ.get("DEVICE_AUDIENCE", "agy-gateway")
ALLOWED_DEVICE_PROJECTS: frozenset[str] = frozenset(_env_json("ALLOWED_DEVICE_PROJECTS", [PROJECT_ID]))
ALLOWED_INSTANCE_PREFIXES: tuple[str, ...] = tuple(_env_json("ALLOWED_INSTANCE_PREFIXES", ["agy-dev-ws"]))
# Device proof modes: "gce" = Google-signed Compute Engine identity token (+ device-bound mTLS when REQUIRE_MTLS);
# "cert" = certificate-only fleet device (laptops): the internal LB verified a certificate from the FLEET CA pool
# whose SPIFFE id is FLEET_SPIFFE_PREFIX<device-id>, and the device is in the FLEET_DEVICES registry, which also
# fixes its user and group (client-asserted identity is recorded but never trusted). Removing a device revokes it.
DEVICE_AUTH_MODES: frozenset[str] = frozenset(_env_json("DEVICE_AUTH_MODES", ["gce"]))
FLEET_SPIFFE_PREFIX: str = os.environ.get("FLEET_SPIFFE_PREFIX", "")
FLEET_DEVICE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{1,62}$")


def _load_categories() -> dict[str, re.Pattern[str]]:
    return {k: re.compile(v, re.IGNORECASE) for k, v in _env_json("PROMPT_CATEGORIES", {}).items()}


CATEGORIES: dict[str, re.Pattern[str]] = _load_categories()
TIERS: tuple[str, ...] = ("light", "default", "complex")
LEVELS: tuple[str, ...] = ("high", "medium", "low")


@dataclass(frozen=True)
class PickerModel:
    picker_id: str        # e.g. gemini-4-argon-high (what the client sees and requests)
    vertex_model: str     # e.g. gemini-4-argon
    level: str            # thinkingLevel sent to Vertex AI
    display: str          # e.g. "Gemini 4 Argon (High)" - same wording as the Gemini Enterprise console


def _load_authorized() -> dict[str, PickerModel]:
    """AUTHORIZED_MODELS mirrors the console 'Antigravity authorized models' list (single policy source)."""
    out: dict[str, PickerModel] = {}
    for vm, spec in _env_json("AUTHORIZED_MODELS", {}).items():
        for lvl in spec.get("levels", ["medium"]):
            pid = f"{vm}-{lvl}"
            out[pid] = PickerModel(pid, vm, lvl, f"{spec.get('display', vm)} ({lvl.capitalize()})")
    return out


AUTHORIZED: dict[str, PickerModel] = _load_authorized()


@dataclass(frozen=True)
class GroupPolicy:
    tiers: dict[str, str]                    # tier -> picker id (the group's cost cap lives here)
    allowed: tuple[str, ...]                 # picker ids this group may select (subset of AUTHORIZED)
    smart_route: bool = False                # re-tier explicit selections by request complexity
    blocked_categories: frozenset[str] = field(default_factory=frozenset)  # empty = all categories
    pci_scope: bool = False                  # sensitive data in requests/responses is BLOCKED instead of masked
    classifier: str = "enforce"              # LLM intent classifier: enforce | audit | off


def _load_policies() -> dict[str, GroupPolicy]:
    out: dict[str, GroupPolicy] = {}
    for grp, p in _env_json("GROUP_POLICY", {}).items():
        allowed = tuple(m for m in p.get("allowed", list(AUTHORIZED)) if m in AUTHORIZED)
        tiers = {t: p["tiers"][t] for t in TIERS}
        bad = [m for m in tiers.values() if m not in allowed]
        if bad:  # misconfiguration must not silently widen access
            raise ValueError(f"group {grp}: tier models {bad} not in its authorized allowlist")
        out[grp] = GroupPolicy(tiers=tiers, allowed=allowed, smart_route=bool(p.get("smart_route", False)),
                               blocked_categories=frozenset(p.get("blocked_categories", [])),
                               pci_scope=bool(p.get("pci_scope", False)),
                               classifier=str(p.get("classifier", "enforce")))
    return out


POLICIES: dict[str, GroupPolicy] = _load_policies()


def load_fleet_devices(raw: dict[str, Any], modes: frozenset[str], policies: dict[str, GroupPolicy],
                       fleet_prefix: str, lb_secret: str) -> dict[str, dict[str, str]]:
    """Validate the device registry at startup: a misconfiguration must never widen access."""
    if not modes or not modes <= {"gce", "cert"}:
        raise ValueError(f"DEVICE_AUTH_MODES must be a non-empty subset of gce, cert: {sorted(modes)}")
    if "cert" not in modes:
        return {}
    if not fleet_prefix or not lb_secret:
        raise ValueError("cert device mode needs FLEET_SPIFFE_PREFIX and the mTLS load balancer (LB_HEADER_SECRET)")
    out: dict[str, dict[str, str]] = {}
    for dev, e in raw.items():
        if not FLEET_DEVICE_ID.match(dev):
            raise ValueError(f"fleet device id {dev!r} invalid (lowercase letters, digits, . _ -)")
        if not isinstance(e, dict) or not e.get("user") or e.get("group") not in policies:
            raise ValueError(f"fleet device {dev!r}: needs a user and a group defined in GROUP_POLICY")
        out[dev] = {"user": str(e["user"]), "group": str(e["group"])}
    return out


FLEET_DEVICES: dict[str, dict[str, str]] = load_fleet_devices(
    _env_json("FLEET_DEVICES", {}), DEVICE_AUTH_MODES, POLICIES, FLEET_SPIFFE_PREFIX,
    os.environ.get("LB_HEADER_SECRET", ""))
GENERATE_METHODS = frozenset({"streamGenerateContent", "generateContent"})
PASS_METHODS = frozenset({"countTokens"})
# Official contract: simplified paths AND full Agent Platform paths. The client's project/region in a full path is
# ignored - the gateway always calls Vertex AI in its own project and configured location.
MODEL_CALL = re.compile(
    r"^/v1(?:beta1?|alpha)?(?:/projects/[^/]+/locations/[^/]+/publishers/google)?"
    r"/models/(?P<model>[A-Za-z0-9._-]+):(?P<method>[A-Za-z]+)$")
# Client telemetry (official: POST /v1beta:*; older clients: /v1internal:*) - acknowledged with 200 {}.
TELEMETRY_CALL = re.compile(r"^/v1(?:beta1?|internal):[A-Za-z]+$")
RETRYABLE = frozenset({429, 500, 502, 503, 504})
# Upstream model capacity (Vertex 429 / 503): bounded retries with backoff, then fallback to another model in the
# group's own allowlist (never outside it). Nothing has been streamed to the client at that point, so it is safe.
CAPACITY_STATUSES = frozenset({429, 503})
UPSTREAM_RETRIES: int = max(0, int(os.environ.get("UPSTREAM_RETRIES", "2") or 0))
UPSTREAM_FALLBACK: bool = os.environ.get("UPSTREAM_FALLBACK", "true").lower() != "false"
COMPLEX_HINT = re.compile(r"\b(plan|architect|design|refactor|root cause|migrate|threat model)\b", re.IGNORECASE)
TEXT_FIELD = re.compile(rb'"text"\s*:\s*"((?:[^"\\]|\\.)*)"')
# Token usage reported by Vertex AI (last usageMetadata block of the response wins: streams repeat it cumulatively)
USAGE_FIELD = re.compile(rb'"(promptTokenCount|candidatesTokenCount|thoughtsTokenCount|cachedContentTokenCount|totalTokenCount)"'
                         rb'\s*:\s*(\d+)')
# Billing labels on Vertex AI calls (cost per persona / device, billing budgets per persona). Set by the gateway from
# the authenticated identity; labels the client sends are replaced, never trusted. Off by default.
BILLING_LABELS: bool = os.environ.get("BILLING_LABELS", "false").lower() == "true"
LABEL_UNSAFE = re.compile(r"[^a-z0-9_-]")
USER_REQUEST = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.S)
AUTO_MODEL = "agy-auto"
# Headers forwarded to Vertex AI (attribution). Base set + the admin customHeaders names (FORWARD_CUSTOM_HEADERS,
# derived by Terraform from admin_settings.json). Identity, billing, routing and gateway-internal headers can never be
# configured: X-Goog-User-Project in particular is always set by the gateway, never taken from a client.
BASE_FORWARD_HEADERS = frozenset({"user-agent", "content-type", "x-goog-api-client"})
RESERVED_HEADER = re.compile(
    r"^(authorization|proxy-.*|host|cookie|content-length|content-encoding|transfer-encoding|connection|te|upgrade"
    r"|x-goog-(?!api-client$).*|x-agy-.*|x-client-cert-.*|x-forwarded-.*|forwarded|x-real-ip|x-serverless-.*"
    r"|x-cloud-trace-context|traceparent|tracestate)$")
HEADER_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")


def load_forward_headers(raw: list[str]) -> frozenset[str]:
    names = [str(h).strip().lower() for h in raw]
    bad = [h for h in names if not HEADER_NAME.match(h) or RESERVED_HEADER.match(h)]
    if bad:  # fail at startup rather than forward identity/billing headers chosen by a client
        raise ValueError(f"FORWARD_CUSTOM_HEADERS contains reserved or invalid header names: {bad}")
    return BASE_FORWARD_HEADERS | frozenset(names)


FORWARD_HEADERS: frozenset[str] = load_forward_headers(_env_json("FORWARD_CUSTOM_HEADERS", ["x-cost-center"]))

# --------------------------------------------------------------------------- logging


def log(event: str, severity: str = "INFO", **kw: Any) -> None:
    print(json.dumps({"severity": severity, "event": event, "component": "agy-gateway", **kw}, default=str), flush=True)

# --------------------------------------------------------------------------- clients


class State:
    http: httpx.AsyncClient
    creds: Any = None
    creds_lock: asyncio.Lock
    google_req: Any = None
    evidence: Any = None
    dp: Any = None
    clf: Any = None
    device_cache: dict[str, tuple[dict[str, Any], float]] = {}


S = State()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # bounded timeouts; read = max gap between bytes of a streamed answer (bandit B113 misreads httpx.Timeout itself)
    S.http = httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=300.0, write=60.0, pool=10.0),  # nosec B113
                               limits=httpx.Limits(max_connections=200, max_keepalive_connections=50))
    S.creds_lock = asyncio.Lock()
    S.google_req = google.auth.transport.requests.Request()
    if PROJECT_ID:
        S.creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    S.evidence = Evidence(S.http, sa_token, project=PROJECT_ID, location=DLP_LOCATION,
                          token_key=os.environ.get("TOKEN_KEY", ""), wrapped_secret=os.environ.get("TOKEN_WRAPPED_SECRET", ""),
                          bucket=os.environ.get("EVIDENCE_BUCKET", ""), evidence_key=os.environ.get("EVIDENCE_KEY", ""))
    S.dp = DataProtect(S.http, sa_token, project=PROJECT_ID, location=DLP_LOCATION,
                       inspect_template=SDP_INSPECT_TEMPLATE, deidentify_template=SDP_DEID_TEMPLATE,
                       window=RESPONSE_WINDOW_CHARS, flush_ms=RESPONSE_FLUSH_MS)
    S.clf = Classifier(S.http, sa_token, project=PROJECT_ID, location=VERTEX_LOCATION, model=CLASSIFIER_MODEL,
                       threshold=CLASSIFIER_THRESHOLD)
    yield
    await S.http.aclose()


app = FastAPI(title="agy-gateway", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


async def sa_token() -> str:
    async with S.creds_lock:
        if not S.creds.valid:
            await asyncio.to_thread(S.creds.refresh, google.auth.transport.requests.Request())
        return str(S.creds.token)


async def post_with_retry(url: str, *, headers: dict[str, str], body: dict[str, Any],
                          attempts: int = 4, timeout: float = 20.0) -> httpx.Response:
    """POST with exponential backoff + jitter on 429/5xx and transport errors."""
    last: Exception | None = None
    for i in range(attempts):
        try:
            r = await S.http.post(url, headers=headers, json=body, timeout=timeout)
            if r.status_code not in RETRYABLE:
                return r
            last = httpx.HTTPStatusError(f"retryable {r.status_code}", request=r.request, response=r)
        except httpx.TransportError as e:
            last = e
        if i < attempts - 1:
            await asyncio.sleep(min(8.0, (2 ** i) * 0.25) + random.uniform(0, 0.25))
    assert last is not None
    raise last

# --------------------------------------------------------------------------- device identity


def _verify_google_token(token: str) -> dict[str, Any]:
    return dict(google_id_token.verify_token(token, S.google_req, audience=DEVICE_AUDIENCE))


async def verify_device(token: str | None) -> tuple[dict[str, Any] | None, str]:
    """Validate the GCE instance identity token. Returns (device, reason)."""
    if not token:
        return None, "missing_device_token"
    key = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    hit = S.device_cache.get(key)
    if hit and hit[1] > now:
        return hit[0], "ok"
    try:
        claims = await asyncio.to_thread(_verify_google_token, token)
    except Exception as e:  # noqa: BLE001 - any verification failure is a rejection
        return None, f"invalid_device_token:{type(e).__name__}"
    gce = (claims.get("google") or {}).get("compute_engine") or {}
    device = {"project": gce.get("project_id"), "instance": gce.get("instance_name"),
              "instance_id": gce.get("instance_id"), "zone": gce.get("zone")}
    if device["project"] not in ALLOWED_DEVICE_PROJECTS:
        return None, "device_project_not_allowed"
    if not str(device["instance"] or "").startswith(ALLOWED_INSTANCE_PREFIXES):
        return None, "device_not_allowed"
    S.device_cache[key] = (device, min(float(claims.get("exp", now + 60)), now + 600))
    if len(S.device_cache) > 2000:
        for k in [k for k, (_, exp) in S.device_cache.items() if exp < now]:
            S.device_cache.pop(k, None)
    return device, "ok"

# --------------------------------------------------------------------------- inspection


def extract_inspectable_text(body: dict[str, Any]) -> str:
    """Latest user turn, plus tool results (functionResponse) in that turn.

    Antigravity wraps the typed prompt in <USER_REQUEST>...</USER_REQUEST> followed by client scaffolding
    (<ADDITIONAL_METADATA>, ephemeral reminders). That scaffolding is instruction-like and triggers Model
    Armor prompt-injection false positives, so only the user request itself (and tool output) is inspected.
    """
    for content in reversed(body.get("contents", []) or []):
        if content.get("role") not in (None, "user", "function", "tool"):
            continue
        chunks: list[str] = []
        for part in content.get("parts", []) or []:
            if isinstance(part.get("text"), str):
                reqs = USER_REQUEST.findall(part["text"])
                chunks.extend(r.strip() for r in reqs) if reqs else chunks.append(part["text"])
            elif SCAN_TOOL_RESULTS and isinstance(part.get("functionResponse"), dict):
                chunks.append(json.dumps(part["functionResponse"].get("response", ""), default=str)[:MA_MAX_CHARS])
        if chunks:
            return "\n".join(chunks)
    return ""


def extract_user_request(body: dict[str, Any]) -> str:
    """Only what the human typed in the latest user turn ("" for tool-result-only turns of the agent loop)."""
    for content in reversed(body.get("contents", []) or []):
        if content.get("role") not in (None, "user"):
            continue
        texts = [p["text"] for p in content.get("parts", []) or [] if isinstance(p.get("text"), str)]
        if not texts:
            return ""
        reqs = [r.strip() for t in texts for r in USER_REQUEST.findall(t)]
        return "\n".join(reqs) if reqs else "\n".join(texts)
    return ""


async def classify_intent(body: dict[str, Any], policy: GroupPolicy, ctx: dict[str, Any]) -> str | None:
    """LLM intent classifier. Returns a block reason or None."""
    clf = S.clf
    if clf is None or not clf.enabled or policy.classifier == "off":
        return None
    utext = extract_user_request(body)
    if not utext:
        return None
    t0 = time.monotonic()
    try:
        res = await clf.classify(utext)
    except Exception as e:  # noqa: BLE001
        log("CLASSIFIER_ERROR", "ERROR", error=type(e).__name__, detail=str(e)[:200], **ctx)
        return "inspection_unavailable" if (CLASSIFIER_FAIL_CLOSED and policy.classifier == "enforce") else None
    would_block = clf.blocks(res)
    log("CLASSIFIED", "WARNING" if would_block else "INFO", verdict=res.get("verdict"), category=res.get("category"),
        confidence=res.get("confidence"), rationale=str(res.get("rationale", ""))[:200], mode=policy.classifier,
        latency_ms=int((time.monotonic() - t0) * 1000), **ctx)
    return f"classifier:{res.get('category')}" if (would_block and policy.classifier == "enforce") else None


async def model_armor(kind: str, text: str) -> dict[str, Any]:
    method, fld = (("sanitizeUserPrompt", "userPromptData") if kind == "prompt"
                   else ("sanitizeModelResponse", "modelResponseData"))
    url = (f"https://modelarmor.{MA_LOCATION}.rep.googleapis.com/v1/projects/{PROJECT_ID}"
           f"/locations/{MA_LOCATION}/templates/{MA_TEMPLATE}:{method}")
    r = await post_with_retry(url, headers={"Authorization": f"Bearer {await sa_token()}"},
                              body={fld: {"text": text[:MA_MAX_CHARS]}})
    r.raise_for_status()
    return r.json().get("sanitizationResult", {})


def matched_filters(result: dict[str, Any]) -> list[str]:
    return [n for n, fr in (result.get("filterResults") or {}).items() if '"MATCH_FOUND"' in json.dumps(fr)]


def category_hit(text: str, policy: GroupPolicy) -> str | None:
    for cat, rx in CATEGORIES.items():
        if policy.blocked_categories and cat not in policy.blocked_categories:
            continue
        if rx.search(text):
            return cat
    return None

# --------------------------------------------------------------------------- routing


def classify_tier(model: str) -> str:
    m = model.lower()
    if "lite" in m:
        return "light"
    if re.search(r"pro|argon|ultra|opus|complex", m):
        return "complex"
    return "default"


def route(requested: str, body: dict[str, Any], text: str, policy: GroupPolicy) -> tuple[str, PickerModel, str]:
    """Return (tier, picker model, reason). Only models in the group's authorized allowlist are ever used.

    1. "Auto" (or any request when smart_route is on): complex / light / default by request complexity.
    2. Explicit selection of an authorized model: honoured as-is (same as the console picker).
    3. Anything else (e.g. client built-in names): mapped by name to a tier of the group's policy.
    """
    auto = requested in (AUTO_MODEL, "auto")
    if auto or policy.smart_route:
        tag = "auto" if auto else "smart"
        size = len(json.dumps(body))
        if COMPLEX_HINT.search(text) or size > 200_000:
            return "complex", AUTHORIZED[policy.tiers["complex"]], f"{tag}:complex"
        if size < 8_000 and not body.get("tools"):
            return "light", AUTHORIZED[policy.tiers["light"]], f"{tag}:light"
        if auto:
            return "default", AUTHORIZED[policy.tiers["default"]], "auto:default"
    if requested in policy.allowed:
        return "explicit", AUTHORIZED[requested], "explicit_authorized"
    tier = classify_tier(requested)
    return tier, AUTHORIZED[policy.tiers[tier]], "not_authorized->tier"


def fallback_candidates(pm: "PickerModel", policy: GroupPolicy) -> list["PickerModel"]:
    """Other authorized models of the group (routing tiers first, then the rest of its allowlist), distinct Vertex models."""
    seen, out = {pm.vertex_model}, []
    for pid in [policy.tiers.get(t) for t in ("light", "default", "complex")] + list(policy.allowed):
        m = AUTHORIZED.get(pid or "")
        if m and m.vertex_model not in seen and (not policy.allowed or m.picker_id in policy.allowed):
            out.append(m)
            seen.add(m.vertex_model)
    return out


def retry_delay(attempt: int, retry_after: str | None) -> float:
    """Exponential backoff with jitter; honours a short Retry-After (seconds), capped at 4 s per wait."""
    try:
        ra = float(retry_after) if retry_after else 0.0
    except ValueError:
        ra = 0.0
    return min(4.0, max(ra, 0.5 * (2 ** attempt)) + random.uniform(0, 0.25))


def apply_grounding(body: dict[str, Any]) -> None:
    """Append the corporate grounding instruction to the request's system instruction (client prompt kept intact)."""
    if not GROUNDING_INSTRUCTION:
        return
    si = body.get("systemInstruction") or body.get("system_instruction")
    if not isinstance(si, dict):
        si = {"parts": []}
    parts = si.setdefault("parts", [])
    if not any(GROUNDING_INSTRUCTION in str(p.get("text", "")) for p in parts if isinstance(p, dict)):
        parts.append({"text": "\n\n" + GROUNDING_INSTRUCTION})
    body.pop("system_instruction", None)
    body["systemInstruction"] = si


def apply_thinking(body: dict[str, Any], level: str) -> None:
    """Set thinkingLevel for the routed picker model (the EU models accept low/medium/high;
    gemini-4-argon rejects thinkingBudget)."""
    gc = body.setdefault("generationConfig", {})
    tc = gc.get("thinkingConfig") if isinstance(gc.get("thinkingConfig"), dict) else {}
    tc.pop("thinkingBudget", None)
    tc["thinkingLevel"] = level
    gc["thinkingConfig"] = tc

# --------------------------------------------------------------------------- helpers


async def record_evidence(text: str, reason: str, requested: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """Tier 1 (reversible tokens) and Tier 2 (HSM-encrypted original) for a blocked prompt. Never raises:
    the prompt is blocked regardless; failures are logged as EVIDENCE_FAILED (alerted)."""
    ev = S.evidence
    out: dict[str, Any] = {}
    if PROMPT_LOGGING not in ("deidentified", "evidence") or ev is None or not text:
        return out
    try:
        if ev.tier1:
            out["prompt_deidentified"], out["deid_infotypes"] = await ev.deidentify(text)
        if PROMPT_LOGGING == "evidence" and ev.tier2:
            out["evidence_object"] = await ev.seal(ctx["incident"], {
                "incident": ctx["incident"], "user": ctx.get("user"), "group": ctx.get("group"),
                "device": ctx.get("device"), "category": reason, "requested": requested, "prompt": text})
    except Exception as e:  # noqa: BLE001
        log("EVIDENCE_FAILED", "ERROR", error=type(e).__name__, detail=str(e)[:300], incident=ctx.get("incident"))
        out["evidence_error"] = type(e).__name__
    return out


def error(code: int, status: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"error": {"code": code, "status": status, "message": message}})


def block_text(incident: str, reason: str) -> str:
    return f"Blocked by corporate AI policy ({reason}). Incident {incident}. Contact SecOps."


def blocked(incident: str, reason: str) -> JSONResponse:
    return error(403, "PERMISSION_DENIED", block_text(incident, reason))


def notice_event(incident: str, reason: str) -> bytes:
    """SSE event carrying a policy notice as the final model turn (used to stop a stream)."""
    turn = {"candidates": [{"content": {"role": "model", "parts": [{"text": "\n\n\u26a0\ufe0f " + block_text(incident, reason)}]},
                            "finishReason": "STOP", "index": 0}], "modelVersion": "agy-gateway-policy"}
    return f"data: {json.dumps(turn)}\r\n\r\n".encode()


def blocked_as_reply(incident: str, reason: str, method: str) -> Response:
    """Policy block rendered as a normal, final model turn so every client UI shows the reason + incident."""
    turn = {"candidates": [{"content": {"role": "model", "parts": [{"text": "\u26a0\ufe0f " + block_text(incident, reason)}]},
                            "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": 0, "candidatesTokenCount": 0, "totalTokenCount": 0},
            "modelVersion": "agy-gateway-policy", "responseId": f"policy-{incident}"}
    if method == "streamGenerateContent":
        return Response(content=f"data: {json.dumps(turn)}\r\n\r\n".encode(), status_code=200,
                        media_type="text/event-stream", headers={"x-agy-policy-block": incident})
    return JSONResponse(turn, status_code=200, headers={"x-agy-policy-block": incident})


def label_value(value: Any) -> str:
    """Vertex AI / billing label value: lowercase letters, digits, '_' and '-', at most 63 characters."""
    return LABEL_UNSAFE.sub("_", str(value or "").lower())[:63] or "unknown"


def billing_labels(ctx: dict[str, Any]) -> dict[str, str]:
    """Labels from the authenticated identity: persona (policy group without the agy- prefix) and device."""
    device = ctx.get("device") if isinstance(ctx.get("device"), dict) else {}
    group = str(ctx.get("group") or "")
    return {"agy_persona": label_value(group.removeprefix("agy-")),
            "agy_device": label_value(device.get("device_id") or device.get("instance"))}


def apply_billing_labels(body: dict[str, Any], ctx: dict[str, Any]) -> None:
    if BILLING_LABELS:
        body["labels"] = billing_labels(ctx)


def usage_from(chunk: bytes, usage: dict[str, int]) -> None:
    """Keep the latest token counts seen in a response chunk (unary JSON or SSE stream)."""
    if b"usageMetadata" not in chunk and not usage:
        return
    for m in USAGE_FIELD.finditer(chunk):
        usage[m.group(1).decode()] = int(m.group(2))


def vertex_url(model: str, method: str) -> str:
    host = ("https://aiplatform.googleapis.com" if VERTEX_LOCATION == "global"
            else f"https://aiplatform.{VERTEX_LOCATION}.rep.googleapis.com" if VERTEX_LOCATION in ("eu", "us")
            else f"https://{VERTEX_LOCATION}-aiplatform.googleapis.com")
    return f"{host}/v1/projects/{INFERENCE_PROJECT}/locations/{VERTEX_LOCATION}/publishers/google/models/{model}:{method}"


async def vertex_headers(request: Request) -> dict[str, str]:
    h = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
    h["authorization"] = f"Bearer {await sa_token()}"
    h["x-goog-user-project"] = INFERENCE_PROJECT
    h["accept-encoding"] = "identity"
    return h


async def relay(upstream: httpx.Response, ctx: dict[str, Any], audit: bool, mode: str = "",
                t0: float | None = None) -> AsyncIterator[bytes]:
    collected: list[str] = []
    budget = MA_MAX_CHARS
    t0 = t0 if t0 is not None else time.monotonic()
    first: float | None = None
    chunks = 0
    stats: dict[str, Any] = {}
    usage: dict[str, int] = {}
    source: AsyncIterator[bytes] = upstream.aiter_raw()
    if mode and S.dp is not None and S.dp.enabled:
        def hit(found: list[str]) -> None:
            log("RESPONSE_MASKED" if mode == "mask" else "RESPONSE_BLOCKED", "WARNING", infotypes=found, **ctx)
        def err(e: Exception) -> None:
            log("DATA_PROTECTION_ERROR", "ERROR", error=type(e).__name__, detail=str(e)[:200], **ctx)
        source = S.dp.guard_stream(source, mode, hit, lambda: notice_event(ctx["incident"], "sensitive_data_in_response"),
                                   err, stats)
    try:
        async for chunk in source:
            chunks += 1
            if first is None:
                first = time.monotonic()
            usage_from(chunk, usage)
            if audit and budget > 0:
                for m in TEXT_FIELD.finditer(chunk):
                    try:
                        s = json.loads(b'"' + m.group(1) + b'"')
                    except json.JSONDecodeError:
                        continue
                    collected.append(s)
                    budget -= len(s)
            yield chunk
    finally:
        await upstream.aclose()
        end = time.monotonic()
        log("STREAM_DONE", ttfb_ms=int(((first or end) - t0) * 1000), total_ms=int((end - t0) * 1000), chunks=chunks,
            inspected=bool(stats), **stats, **({"usage": usage} if usage else {}), **ctx)
        if audit and collected:
            asyncio.create_task(audit_response("".join(collected), ctx))


async def audit_response(text: str, ctx: dict[str, Any]) -> None:
    try:
        res = await model_armor("response", text)
    except Exception as e:  # noqa: BLE001 - audit must never raise
        log("RESPONSE_AUDIT_ERROR", "WARNING", error=str(e), **ctx)
        return
    if res.get("filterMatchState") == "MATCH_FOUND":
        log("RESPONSE_FLAGGED", "WARNING", model_armor_filters=matched_filters(res), **ctx)


def cert_sans_if_matches(cert_b64: str, lb_fingerprint: str) -> list[str] | None:
    """URI SANs of the presented certificate, or None if it isn't the one the LB verified in the handshake."""
    try:
        der = base64.b64decode(cert_b64.strip())
        fp = base64.b64encode(hashlib.sha256(der).digest()).decode().rstrip("=")
        if not lb_fingerprint or not hmac.compare_digest(fp, lb_fingerprint.strip().rstrip("=")):
            return None
        cert = x509.load_der_x509_certificate(der)
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [str(u) for u in ext.value.get_values_for_type(x509.UniformResourceIdentifier)]
    except Exception:  # noqa: BLE001 - malformed input = rejection
        return None


def lb_verified_sans(headers: Any) -> tuple[list[str], str | None]:
    """URI SANs of the client certificate the internal LB verified, or a rejection reason."""
    if not LB_HEADER_SECRET or not hmac.compare_digest(headers.get("x-agy-lb-auth", ""), LB_HEADER_SECRET):
        return [], "mtls_not_via_lb"
    if headers.get("x-client-cert-present", "").lower() != "true":
        return [], "mtls_no_client_cert"
    if headers.get("x-client-cert-chain-verified", "").lower() != "true":
        return [], "mtls_chain_not_verified"
    # The regional internal ALB leaves {client_cert_uri_sans}/{client_cert_spiffe_id} empty, but
    # provides the SHA-256 fingerprint of the certificate it verified. The proxy also sends the (public) device
    # certificate; it is trusted only if its fingerprint equals the LB-verified one, then its SAN is used.
    sans = [x.strip() for x in headers.get("x-client-cert-uri-sans", "").split(",") if x.strip()]
    if headers.get("x-client-cert-spiffe-id"):
        sans.append(headers["x-client-cert-spiffe-id"].strip())
    if not sans and headers.get("x-agy-device-cert"):
        got = cert_sans_if_matches(headers["x-agy-device-cert"], headers.get("x-client-cert-hash", ""))
        if got is None:
            return [], "mtls_cert_fingerprint_mismatch"
        sans = got
    return sans, None


def check_mtls(headers: Any, device: dict[str, Any] | None) -> str | None:
    """Return a rejection reason, or None if the LB-verified client certificate is bound to this device."""
    sans, why = lb_verified_sans(headers)
    if why:
        return why
    expected = f"{SPIFFE_PREFIX}{(device or {}).get('instance', '')}"
    if expected not in sans:
        return "mtls_device_mismatch"
    return None


def check_fleet_device(headers: Any) -> tuple[dict[str, Any] | None, str]:
    """Certificate-only device: LB-verified FLEET certificate + registered device. Returns (registry entry, reason)."""
    sans, why = lb_verified_sans(headers)
    if why:
        return None, why
    ids = [s[len(FLEET_SPIFFE_PREFIX):] for s in sans if FLEET_SPIFFE_PREFIX and s.startswith(FLEET_SPIFFE_PREFIX)]
    if len(ids) != 1:
        return None, "fleet_cert_required"
    entry = FLEET_DEVICES.get(ids[0])
    if entry is None:
        return None, "fleet_device_unregistered"
    return {"device_id": ids[0], **entry}, "ok"


async def authenticate(request: Request) -> tuple[dict[str, Any] | None, GroupPolicy | None, JSONResponse | None]:
    """Device proof (Compute Engine token + bound mTLS, or certificate-only fleet device) -> context + policy."""
    incident = uuid.uuid4().hex[:10]
    h = request.headers
    if "cert" in DEVICE_AUTH_MODES and not h.get("x-agy-device-token"):
        fleet, why = check_fleet_device(h)
        if fleet is None:
            log("DEVICE_REJECTED", "WARNING", incident=incident, reason=why, path=request.url.path, mode="cert",
                cert_hash=h.get("x-client-cert-hash"))
            return None, None, error(401, "UNAUTHENTICATED", f"Unmanaged device ({why}). Incident {incident}.")
        device = {"kind": "fleet", "device_id": fleet["device_id"], "cert_hash": h.get("x-client-cert-hash"),
                  "cert_serial": h.get("x-client-cert-serial")}
        ctx = {"incident": incident, "user": fleet["user"], "group": fleet["group"], "device": device,
               "os_user": h.get("x-agy-user")}   # registry identity wins; what the client asserted is kept for audit
        return ctx, POLICIES[fleet["group"]], None
    device: dict[str, Any] | None = {"instance": "unverified"}
    if REQUIRE_DEVICE:
        if "gce" not in DEVICE_AUTH_MODES:
            log("DEVICE_REJECTED", "WARNING", incident=incident, reason="gce_devices_not_allowed", path=request.url.path)
            return None, None, error(401, "UNAUTHENTICATED", f"Unmanaged device (gce_devices_not_allowed). Incident {incident}.")
        device, why = await verify_device(h.get("x-agy-device-token"))
        if device is None:
            log("DEVICE_REJECTED", "WARNING", incident=incident, reason=why, path=request.url.path)
            return None, None, error(401, "UNAUTHENTICATED", f"Unmanaged device ({why}). Incident {incident}.")
    if REQUIRE_MTLS:
        why = check_mtls(h, device)
        if why:
            log("DEVICE_REJECTED", "WARNING", incident=incident, reason=why, path=request.url.path,
                device=device, cert_sans=h.get("x-client-cert-uri-sans"),
                cert_spiffe=h.get("x-client-cert-spiffe-id"),
                cert_hash=h.get("x-client-cert-hash"))
            return None, None, error(401, "UNAUTHENTICATED", f"Device certificate required ({why}). Incident {incident}.")
        device = {**(device or {}), "cert_hash": h.get("x-client-cert-hash"),
                  "cert_serial": h.get("x-client-cert-serial")}
    user, group = h.get("x-agy-user"), h.get("x-agy-group")
    policy = POLICIES.get(group or "")
    ctx = {"incident": incident, "user": user, "group": group, "device": device}
    if not user or policy is None:
        log("GROUP_UNKNOWN", "WARNING", **ctx)
        return None, None, blocked(incident, "unknown_user_or_group")
    return ctx, policy, None

# --------------------------------------------------------------------------- routes


@app.get("/_gw/health")  # Cloud Run reserves /healthz
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1beta/models")
@app.get("/v1/models")
async def list_models(request: Request) -> Response:
    ctx, policy, err = await authenticate(request)
    if err:
        return err
    assert policy is not None
    def entry(mid: str, display: str) -> dict[str, Any]:
        return {"name": f"models/{mid}", "baseModelId": mid, "displayName": display, "version": f"vertex-{VERTEX_LOCATION}",
                "inputTokenLimit": 1_000_000, "outputTokenLimit": 65_536,
                "supportedGenerationMethods": ["generateContent", "streamGenerateContent", "countTokens"]}
    models = [entry(AUTO_MODEL, "Auto (corporate routing)")]   # first entry = client default selection
    models += [entry(m, AUTHORIZED[m].display) for m in policy.allowed]
    log("MODELS_LISTED", models=[m["baseModelId"] for m in models], **(ctx or {}))
    return JSONResponse({"models": models})


@app.api_route("/v1/chat/completions", methods=["POST"])
async def openai_denied(request: Request) -> Response:
    log("WIRE_PROTOCOL_DENIED", "WARNING", path=request.url.path)
    return error(400, "FAILED_PRECONDITION", "This gateway supports gateway.wireProtocol=genai only (the default); the OpenAI protocol is not supported.")


@app.post("/_seat/pubsub")
async def seat_pubsub(request: Request) -> Response:
    """Pub/Sub push target (seat inspector service only). 204 = processed/ignored; 500 = retry later."""
    if not SEAT_INSPECTOR:
        return error(404, "NOT_FOUND", "Unsupported gateway path.")
    try:
        raw = seat.decode_push(await request.json())
        entry = seat.parse_entry(raw)
    except (ValueError, json.JSONDecodeError, TypeError) as e:
        log("SEAT_INSPECTOR_BAD_MESSAGE", "WARNING", error=type(e).__name__)
        return Response(status_code=204)                     # malformed: ack, never retry forever
    if entry is None:
        v = seat.parse_vpcsc_violation(raw)
        if v:                                                # seat API call refused by the perimeter
            incident = uuid.uuid4().hex[:10]
            if v["dry_run"] == "true":                       # dry-run perimeter: would have been refused - never contain
                log("PERIMETER_DRYRUN_VIOLATION", "NOTICE", incident=incident, mode="seat", source="vpc_sc", **v)
                return Response(status_code=204)
            log("STOLEN_TOKEN_SUSPECTED", "WARNING", incident=incident, mode="seat", source="vpc_sc", **v)
            await contain_user(v["user"], f"vpc_sc:{v['reason']}", {"incident": incident, "mode": "seat"})
        return Response(status_code=204)
    group = SEAT_USER_GROUPS.get(entry.user, SEAT_DEFAULT_GROUP)
    policy = POLICIES.get(group) or POLICIES.get(SEAT_DEFAULT_GROUP)
    ctx = {"incident": uuid.uuid4().hex[:10], "user": entry.user, "group": group, "mode": "seat",
           "trajectory_id": entry.labels.get("trajectory_id"), "request_id": entry.labels.get("request_id"),
           "model": entry.labels.get("model"), "client": entry.labels.get("client_name"), "location": entry.location}
    await seat_model_check(entry, group, ctx)
    try:
        findings = await seat_findings(entry, policy)
    except Exception as e:  # noqa: BLE001 - transient engine failure: let Pub/Sub retry (dead letter after N tries)
        log("SEAT_INSPECTOR_ERROR", "ERROR", error=type(e).__name__, detail=str(e)[:200], **ctx)
        return Response(status_code=500)
    if findings:
        sev = seat.severity(findings, bool(policy and policy.pci_scope))
        extra = await record_evidence(entry.text, ",".join(findings), entry.labels.get("model", ""), ctx) \
            if entry.kind == "request" else {}
        log("PROMPT_FLAGGED" if entry.kind == "request" else "RESPONSE_FLAGGED", "WARNING", findings=findings,
            risk=sev, source="seat_inspector", prompt_sha256=hashlib.sha256(entry.text.encode()).hexdigest(),
            prompt_chars=len(entry.text), **ctx, **extra)
        if sev == "high":
            await contain_user(entry.user, ",".join(findings), ctx)
    return Response(status_code=204)


async def seat_model_check(entry: "seat.SeatEntry", group: str, ctx: dict[str, Any]) -> None:
    """Seat model policy: flag a request served by a model/effort outside the group's allowlist (from the server-side
    prompt log, so a modified client can't hide it); request containment after N distinct turns per hour."""
    allowed = SEAT_MODEL_POLICY.get(group) if group in SEAT_MODEL_POLICY else None
    if entry.kind != "request" or not entry.experience or seat.model_allowed(entry.experience, allowed, SEAT_AUX_MODELS):
        return
    n = MODEL_VIOLATIONS.add(entry.user.lower(), time.time(), str(ctx.get("trajectory_id") or ""))
    log("MODEL_OFF_POLICY", "WARNING", experience=entry.experience, allowed=allowed, violations_1h=n,
        threshold=SEAT_MODEL_CONTAIN_AFTER, source="seat_inspector", **ctx)
    if n >= SEAT_MODEL_CONTAIN_AFTER:
        await contain_user(entry.user, f"model_off_policy:{entry.experience}", ctx)


async def contain_user(user: str, reason: str, ctx: dict[str, Any]) -> str:
    """Remove the user's Gemini Enterprise licence (enforce) or record what would happen (dry_run). Never raises."""
    u = user.lower()
    base = {"user": user, "reason": reason[:300], "incident": ctx.get("incident"), "seat_project": SEAT_PROJECT,
            "seat_location": SEAT_LOCATION}
    if SEAT_CONTAINMENT == "off" or not u:
        return "off"
    if u in SEAT_CONTAIN_EXEMPT:
        log("CONTAINMENT_SKIPPED", "WARNING", why="exempt", **base)
        return "exempt"
    now = time.time()
    if CONTAINED.get(u, 0) > now - 3600:
        log("CONTAINMENT_SKIPPED", "NOTICE", why="already_handled_within_1h", **base)
        return "already"
    if SEAT_CONTAINMENT != "enforce":
        log("CONTAINMENT_DRYRUN", "WARNING", action="unassign_license", **base)
        CONTAINED[u] = now
        return "dry_run"
    host = "discoveryengine.googleapis.com" if SEAT_LOCATION == "global" else f"{SEAT_LOCATION}-discoveryengine.googleapis.com"
    url = (f"https://{host}/v1/projects/{SEAT_PROJECT}/locations/{SEAT_LOCATION}"
           "/userStores/default_user_store:batchUpdateUserLicenses")
    try:
        r = await post_with_retry(url, headers={"Authorization": f"Bearer {await sa_token()}",
                                                "X-Goog-User-Project": SEAT_PROJECT}, body=seat.unassign_body(user))
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001 - alert, keep processing
        log("CONTAINMENT_FAILED", "ERROR", error=type(e).__name__, detail=str(e)[:200], **base)
        return "failed"
    CONTAINED[u] = now
    log("CONTAINMENT_APPLIED", "WARNING", action="unassign_license", **base)
    return "applied"


async def seat_findings(entry: "seat.SeatEntry", policy: GroupPolicy | None) -> list[str]:
    """Same engines as the inline gateway, in detect mode."""
    found: list[str] = []
    if entry.kind == "request":
        if policy is not None and (cat := category_hit(entry.text, policy)):
            found.append(f"category:{cat}")
        if MA_ENABLED:
            found += [f"model_armor:{f}" for f in matched_filters(await model_armor("prompt", entry.text))]
        if policy is not None and policy.classifier != "off" and S.clf is not None and S.clf.enabled:
            res = await S.clf.classify(entry.text)
            if S.clf.blocks(res):
                found.append(f"classifier:{res.get('category')}")
    else:
        if MA_ENABLED:
            found += [f"model_armor:{f}" for f in matched_filters(await model_armor("response", entry.text))]
        if S.dp is not None and S.dp.enabled:
            _, infotypes = await S.dp.mask_values([entry.text])
            if infotypes:
                found.append("sensitive_data:" + ",".join(infotypes))
    return sorted(set(found))


@app.api_route("/{full_path:path}", methods=["GET", "POST"])
async def model_call(full_path: str, request: Request) -> Response:
    t0 = time.monotonic()
    ctx, policy, err = await authenticate(request)
    if err:
        return err
    assert ctx is not None and policy is not None
    if request.method == "POST" and TELEMETRY_CALL.match("/" + full_path):
        size = len(await request.body())
        log("TELEMETRY", path="/" + full_path, bytes=size, **ctx)   # metadata only, content never logged
        return JSONResponse({}, status_code=200)
    m = MODEL_CALL.match("/" + full_path)
    if not m or m.group("method") not in GENERATE_METHODS | PASS_METHODS:
        log("PATH_DENIED", "WARNING", path="/" + full_path[:200], **ctx)
        return error(404, "NOT_FOUND", "Unsupported gateway path.")
    requested, method = m.group("model"), m.group("method")
    content = await request.body()
    try:
        body = json.loads(content or b"{}")
    except json.JSONDecodeError:
        return error(400, "INVALID_ARGUMENT", "invalid JSON")
    ctx = {**ctx, "method": method}

    if method in PASS_METHODS:
        pm = AUTHORIZED.get(requested) if requested in policy.allowed else AUTHORIZED[policy.tiers["default"]]
        tier, why = "passthrough", "passthrough"
    else:
        # ---- Req 4: inspection
        text = extract_inspectable_text(body)
        audit: dict[str, Any] = {} if PROMPT_LOGGING == "none" else {
            "prompt_sha256": hashlib.sha256(text.encode()).hexdigest(), "prompt_chars": len(text)}
        reason = category_hit(text, policy) if text else None
        source = "category_rule" if reason else None
        sdp_only = False
        if text and not reason and MA_ENABLED:
            try:
                res = await model_armor("prompt", text)
                if res.get("filterMatchState") == "MATCH_FOUND":
                    hits = matched_filters(res) or ["match"]
                    if hits == ["sdp"] and S.dp is not None and S.dp.enabled and not policy.pci_scope:
                        sdp_only = True   # sensitive data only: mask it instead of blocking (non-PCI groups)
                    elif hits == ["sdp"] and policy.pci_scope:
                        reason, source = "sensitive_data:pci_scope", "model_armor"
                    else:
                        reason, source = "model_armor:" + ",".join(hits), "model_armor"
            except Exception as e:  # noqa: BLE001
                log("MODEL_ARMOR_ERROR", "ERROR", error=str(e), **ctx)
                if MA_FAIL_CLOSED:
                    reason, source = "inspection_unavailable", "fail_closed"
        if reason:
            audit.update(await record_evidence(text, reason, requested, ctx))
            log("PROMPT_BLOCKED", "WARNING", category=reason, source=source, requested=requested,
                block_mode=BLOCK_RESPONSE_MODE, **ctx, **audit)
            if BLOCK_RESPONSE_MODE == "message":
                return blocked_as_reply(ctx["incident"], reason, method)
            return blocked(ctx["incident"], reason)
        if not reason:
            creason = await classify_intent(body, policy, ctx)
            if creason:
                reason, source = creason, "classifier"
                audit.update(await record_evidence(text, reason, requested, ctx))
                log("PROMPT_BLOCKED", "WARNING", category=reason, source=source, requested=requested,
                    block_mode=BLOCK_RESPONSE_MODE, **ctx, **audit)
                if BLOCK_RESPONSE_MODE == "message":
                    return blocked_as_reply(ctx["incident"], reason, method)
                return blocked(ctx["incident"], reason)
        if sdp_only:
            try:
                masked = await S.dp.mask_request(body)
                log("REQUEST_MASKED", "NOTICE", infotypes=masked, requested=requested, **ctx)
            except Exception as e:  # noqa: BLE001 - cannot mask -> do not forward sensitive data
                log("DATA_PROTECTION_ERROR", "ERROR", error=type(e).__name__, detail=str(e)[:200], **ctx)
                return blocked(ctx["incident"], "sensitive_data:masking_unavailable") if BLOCK_RESPONSE_MODE != "message" \
                    else blocked_as_reply(ctx["incident"], "sensitive_data:masking_unavailable", method)
        # ---- Req 5: routing
        tier, pm, why = route(requested, body, text, policy)
        apply_thinking(body, pm.level)
        apply_grounding(body)
        apply_billing_labels(body, ctx)
        content = json.dumps(body).encode()
        log("ROUTED", requested=requested, tier=tier, routed=pm.picker_id, vertex_model=pm.vertex_model,
            thinking_level=pm.level, reason=why,
            user_agent=request.headers.get("user-agent"), request_bytes=len(content), **ctx)

    routed = pm.picker_id
    can_fallback = UPSTREAM_FALLBACK and method in GENERATE_METHODS and isinstance(body, dict) and policy is not None
    chain = [pm] + (fallback_candidates(pm, policy) if can_fallback else [])
    upstream = None
    for idx, cand in enumerate(chain):
        if idx:   # fallback: same request, next authorized model of the group (thinking level of that model)
            apply_thinking(body, cand.level)
            content = json.dumps(body).encode()
            log("ROUTED_FALLBACK", "WARNING", from_model=routed, to_model=cand.picker_id, vertex_model=cand.vertex_model,
                status=upstream.status_code if upstream is not None else None, **ctx)
            routed = cand.picker_id
        for attempt in range(UPSTREAM_RETRIES + 1):
            req = S.http.build_request("POST", vertex_url(cand.vertex_model, method), params=dict(request.query_params),
                                       headers=await vertex_headers(request), content=content)
            upstream = await S.http.send(req, stream=True)
            if upstream.status_code not in CAPACITY_STATUSES:
                break
            ra = upstream.headers.get("retry-after")
            if attempt < UPSTREAM_RETRIES:
                await upstream.aread()
                await upstream.aclose()
                log("UPSTREAM_RETRY", "NOTICE", status=upstream.status_code, routed=routed, attempt=attempt + 1, **ctx)
                await asyncio.sleep(retry_delay(attempt, ra))
        if upstream.status_code not in CAPACITY_STATUSES or idx == len(chain) - 1:
            break
        await upstream.aread()
        await upstream.aclose()
    assert upstream is not None
    if upstream.status_code != 200:
        data = await upstream.aread()
        await upstream.aclose()
        try:
            msg = json.loads(data).get("error", {}).get("message", "")[:300]
        except (json.JSONDecodeError, AttributeError):
            msg = data[:300].decode(errors="replace")
        log("UPSTREAM_ERROR", "WARNING", status=upstream.status_code, routed=routed, upstream_message=msg,
            generation_config=json.dumps(body.get("generationConfig", {}))[:400], **ctx)
        return Response(content=data, status_code=upstream.status_code,
                        media_type=upstream.headers.get("content-type", "application/json"))
    out_headers = {k: v for k, v in upstream.headers.items()
                   if k.lower() not in ("content-length", "transfer-encoding", "connection", "content-encoding")}
    mode = ("block" if policy.pci_scope else "mask") if (S.dp is not None and S.dp.enabled and method in GENERATE_METHODS) else ""
    if mode and method == "generateContent":   # unary: inspect the whole answer
        data = await upstream.aread()
        await upstream.aclose()
        try:
            payload = json.loads(data)
            new, found = await S.dp.mask_unary(payload, mode)
        except Exception as e:  # noqa: BLE001
            log("DATA_PROTECTION_ERROR", "ERROR", error=type(e).__name__, detail=str(e)[:200], **ctx)
            return blocked_as_reply(ctx["incident"], "sensitive_data:inspection_unavailable", method)
        if found:
            log("RESPONSE_MASKED" if new is not None else "RESPONSE_BLOCKED", "WARNING", infotypes=found, **ctx)
        if new is None:
            return blocked_as_reply(ctx["incident"], "sensitive_data_in_response", method)
        return JSONResponse(new, status_code=200)
    return StreamingResponse(relay(upstream, ctx, AUDIT_RESPONSES and method in GENERATE_METHODS and upstream.status_code == 200, mode, t0),
                             status_code=upstream.status_code, headers=out_headers,
                             media_type=upstream.headers.get("content-type"))
