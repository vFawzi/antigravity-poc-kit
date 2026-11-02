#!/usr/bin/env bash
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

# Break-glass restore of a blocked prompt (prompt_logging = deidentified | evidence).
#   scripts/investigate.sh <incident-id> [days-back]
# Requires an ACTIVE Privileged Access Manager grant on the entitlement "<prefix>-prompt-investigator":
#   gcloud pam grants create --entitlement=agy-prompt-investigator --location=global \
#     --project=<project> --requested-duration=3600s --justification="<case id / reason>"
# Output goes to this terminal only (never to disk). Every restore is visible in Cloud Audit Logs
# (PAM grant, Secret Manager access, Cloud KMS decrypt, SDP reidentify) and logged as EVIDENCE_ACCESSED.
source "$(dirname "$0")/lib.sh"
INCIDENT="${1:?usage: $0 <incident-id> [days-back]}"; DAYS="${2:-400}"
[[ "$INCIDENT" =~ ^[a-f0-9]{6,32}$ ]] || die "incident id looks invalid"
EV="$(tfo evidence)"; [[ -n "$EV" && "$EV" != "null" ]] || die "prompt evidence is not enabled (prompt_logging none/hash)"
read -r -p "Justification / case reference (logged): " WHY; [[ -n "$WHY" ]] || die "justification required"

log "looking up incident ${INCIDENT} (last ${DAYS} days)"
ENTRY="$(gcloud logging read "jsonPayload.event=\"PROMPT_BLOCKED\" AND jsonPayload.incident=\"${INCIDENT}\"" \
  --freshness="${DAYS}d" --limit=1 --format=json)"
[[ "$ENTRY" != "[]" && -n "$ENTRY" ]] || die "incident not found"

gcloud logging write agy-evidence-access "$(python3 -c 'import json,sys; print(json.dumps({"event":"EVIDENCE_ACCESSED","component":"agy-investigate","incident":sys.argv[1],"justification":sys.argv[2]}))' "$INCIDENT" "$WHY")" \
  --payload-type=json --severity=NOTICE >/dev/null

TOKEN="$(gcloud auth print-access-token)"
SECRET="$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["wrapped_secret"])' "$EV")"
WRAPPED="$(gcloud secrets versions access latest --secret "$SECRET" --out-file=/dev/stdout 2>/dev/null | base64 | tr -d '\n')" \
  || die "cannot read the wrapped token key - is your PAM grant active?"

ENTRY="$ENTRY" EV="$EV" TOKEN="$TOKEN" WRAPPED="$WRAPPED" PROJECT_ID="$PROJECT_ID" REGION="$REGION" python3 - <<'PY'
import base64, json, os, subprocess, sys, urllib.request, urllib.error

e = json.loads(os.environ["ENTRY"])[0]["jsonPayload"]
ev = json.loads(os.environ["EV"])
H = {"Authorization": "Bearer " + os.environ["TOKEN"], "Content-Type": "application/json", "X-Goog-User-Project": os.environ["PROJECT_ID"]}

def post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=H, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as err:
        sys.exit(f"ERROR {err.code} from {url.split('/v')[0]}: {err.read()[:300]!r} - is your PAM grant active?")

print(f"\n== incident {e['incident']}  user={e.get('user')} group={e.get('group')} category={e.get('category')} "
      f"time={e.get('timestamp', '')}\n")
crypto = {"cryptoKey": {"kmsWrapped": {"wrappedKey": os.environ["WRAPPED"], "cryptoKeyName": ev["tokenization_key"]}},
          "surrogateInfoType": {"name": "AGY_TOKEN"}}
if e.get("prompt_deidentified"):
    r = post(f"https://dlp.googleapis.com/v2/projects/{os.environ['PROJECT_ID']}/locations/{os.environ['REGION']}/content:reidentify", {
        "reidentifyConfig": {"infoTypeTransformations": {"transformations": [
            {"infoTypes": [{"name": "AGY_TOKEN"}], "primitiveTransformation": {"cryptoDeterministicConfig": crypto}}]}},
        "inspectConfig": {"customInfoTypes": [{"infoType": {"name": "AGY_TOKEN"}, "surrogateType": {}}]},
        "item": {"value": e["prompt_deidentified"]}})
    print("-- Tier 1 (re-identified audit copy) --")
    print(r.get("item", {}).get("value", ""))
obj = e.get("evidence_object")
if obj:
    doc = json.loads(subprocess.run(["gcloud", "storage", "cat", obj], check=True, capture_output=True).stdout)
    raw = b""
    for c in doc["chunks"]:
        r = post(f"https://cloudkms.googleapis.com/v1/{doc['key']}:decrypt", {
            "ciphertext": c["ciphertext"], "additionalAuthenticatedData": base64.b64encode(c["aad"].encode()).decode()})
        raw += base64.b64decode(r["plaintext"])
    rec = json.loads(raw)
    assert rec.get("incident") == e["incident"], "evidence/incident mismatch"
    print("\n-- Tier 2 (exact original, from the evidence store) --")
    print(rec["prompt"])
PY
log "restore complete for incident ${INCIDENT} (audited)"
