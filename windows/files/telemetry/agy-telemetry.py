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

"""AGY telemetry shipper (Windows, SYSTEM, every 5 minutes; Python standard library only).

Reads AGY events (hook decisions, policy / drift, launches) and optional OS security channels from the Windows Event
Log since the last run, and writes them to Cloud Logging with a write-only federated identity:
  device certificate (customer PKI) --mTLS--> Google STS (Workload Identity Federation, X.509) --> 1 h access token
  --> logging.googleapis.com entries.write (roles/logging.logWriter only)
Entries mimic the Ops Agent Windows event format (log agy_winevt, resource generic_node), so the SIEM views treat a
laptop like a reference VM. Offline: a bounded local spool; a daily cap bounds cost; a heartbeat shows the shipper
is alive (SIEM detection: device silent for 24 h).

Usage: python agy-telemetry.py --config C:\\ProgramData\\AntigravityTelemetry\\config.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import http.client
import json
import os
import ssl
# subprocess: fixed binary (wevtutil), list arguments, no shell; XML: parses wevtutil output, not untrusted input
import subprocess  # nosec B404
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path
from typing import Any

VERSION = "2.0.0"
STS_HOST = "sts.mtls.googleapis.com"
LOGGING_HOST = "logging.googleapis.com"
EVT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
LEVELS = {"1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFO", "0": "INFO", "5": "DEBUG"}
AGY_PROVIDERS = ("agy-hook", "agy-mdm", "agy-launch", "agy-shim")
OS_CHANNELS = {"applocker": "Microsoft-Windows-AppLocker/EXE and DLL", "wdac": "Microsoft-Windows-CodeIntegrity/Operational",
               "firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", "defender":
               "Microsoft-Windows-Windows Defender/Operational", "signin": "Security"}
MAX_BATCH = 500


# ---------------------------------------------------------------------------------------------- local state
class State:
    def __init__(self, d: Path) -> None:
        self.dir = d
        self.file = d / "state.json"
        self.data: dict[str, Any] = {}
        try:
            self.data = json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}

    def save(self) -> None:
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
        os.replace(tmp, self.file)


def log(state_dir: Path, msg: str) -> None:
    f = state_dir / "shipper.log"
    try:
        if f.exists() and f.stat().st_size > 1_000_000:
            os.replace(f, state_dir / "shipper.log.1")
        with f.open("a", encoding="utf-8") as fh:
            fh.write(f"{dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} {msg}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------- event collection
def _wevtutil(channel: str, xpath: str, count: int, newest_first: bool = False) -> str:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wevtutil.exe")
    args = [exe, "qe", channel, f"/q:{xpath}", "/f:RenderedXml", f"/c:{count}"] + (["/rd:true"] if newest_first else [])
    r = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",  # nosec B603
                       timeout=120, check=False)
    return r.stdout if r.returncode == 0 else ""


def parse_events(xml_text: str, channel: str, host: str) -> list[dict[str, Any]]:
    """wevtutil RenderedXml (several <Event> roots) -> Ops-Agent-like payloads with record id and time."""
    out: list[dict[str, Any]] = []
    if not xml_text.strip():
        return out
    root = ET.fromstring(f"<Events>{xml_text}</Events>")  # nosec B314
    for ev in root.findall("e:Event", EVT_NS):
        sysn = ev.find("e:System", EVT_NS)
        if sysn is None:
            continue
        prov = sysn.find("e:Provider", EVT_NS)
        rid = int((sysn.findtext("e:EventRecordID", "0", EVT_NS) or "0"))
        tc = sysn.find("e:TimeCreated", EVT_NS)
        msg = ev.findtext("e:RenderingInfo/e:Message", "", EVT_NS) or ""
        if not msg:
            msg = " ".join((d.text or "") for d in ev.findall("e:EventData/e:Data", EVT_NS)).strip()
        out.append({"record": rid, "time": (tc.get("SystemTime") if tc is not None else None),
                    "severity": LEVELS.get(sysn.findtext("e:Level", "4", EVT_NS) or "4", "INFO"),
                    "payload": {"SourceName": prov.get("Name") if prov is not None else "", "ProviderName":
                                prov.get("Name") if prov is not None else "", "EventID": int(sysn.findtext("e:EventID", "0", EVT_NS) or 0),
                                "Channel": channel, "Computer": host, "RecordNumber": rid, "Message": msg[:16000]}})
    return out


def _xpath(pred: str, after: int | None) -> str:
    parts = [x for x in (pred, f"(EventRecordID>{after})" if after is not None else "") if x]
    return f"*[System[{' and '.join(parts)}]]" if parts else "*"


def sources(cfg: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(channel, bookmark key, System predicate) for the configured event sets."""
    out: list[tuple[str, str, str]] = []
    if "agy" in cfg["events"]:
        out.append(("Application", "agy", "Provider[" + " or ".join(f"@Name='{p}'" for p in AGY_PROVIDERS) + "]"))
    for ch in cfg.get("os_channels", []):
        if ch in OS_CHANNELS:
            out.append((OS_CHANNELS[ch], ch, "(EventID=4624 or EventID=4625)" if ch == "signin" else ""))
    return out


def collect(cfg: dict[str, Any], st: State) -> list[dict[str, Any]]:
    host = os.environ.get("COMPUTERNAME", "")
    marks: dict[str, int] = st.data.setdefault("bookmarks", {})
    events: list[dict[str, Any]] = []
    for channel, key, pred in sources(cfg):
        if key not in marks:   # first run: start at the newest record, don't replay the device's history
            newest = parse_events(_wevtutil(channel, _xpath(pred, None), 1, newest_first=True), channel, host)
            marks[key] = newest[0]["record"] if newest else 0
            continue
        evs = parse_events(_wevtutil(channel, _xpath(pred, int(marks[key])), MAX_BATCH), channel, host)
        evs.sort(key=lambda e: e["record"])
        if evs:
            marks[key] = evs[-1]["record"]
        events += evs
    return events


# ---------------------------------------------------------------------------------------------- identity + API
def _ctx(cfg: dict[str, Any]) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg["cert_file"], cfg["key_file"])
    return ctx


def _pem_certs(path: str) -> list[str]:
    text = Path(path).read_text(encoding="ascii")
    blocks, cur = [], []
    for line in text.splitlines():
        if "BEGIN CERTIFICATE" in line:
            cur = [line]
        elif "END CERTIFICATE" in line:
            cur.append(line)
            blocks.append("\n".join(cur) + "\n")
            cur = []
        elif cur:
            cur.append(line)
    return blocks


def subject_token(cfg: dict[str, Any]) -> str:
    """JSON list of base64 DER certificates, leaf first (RFC 7515 x5c), as Google STS expects for X.509 federation."""
    leaf = _pem_certs(cfg["cert_file"])
    chain = leaf[1:] + (_pem_certs(cfg["chain_file"]) if cfg.get("chain_file") and Path(cfg["chain_file"]).exists() else [])
    ders = [base64.b64encode(ssl.PEM_cert_to_DER_cert(p)).decode() for p in leaf[:1] + chain]
    return json.dumps(list(dict.fromkeys(ders)))


def _post(host: str, path: str, body: bytes, headers: dict[str, str], ctx: ssl.SSLContext | None = None) -> tuple[int, bytes]:
    conn = http.client.HTTPSConnection(host, 443, timeout=60, context=ctx or ssl.create_default_context())
    try:
        conn.request("POST", path, body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def access_token(cfg: dict[str, Any], st: State) -> str:
    tok = st.data.get("token") or {}
    if tok.get("value") and tok.get("expires", 0) - time.time() > 300:
        return str(tok["value"])
    body = urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": cfg["audience"],
        "scope": "https://www.googleapis.com/auth/logging.write",
        "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "subject_token_type": "urn:ietf:params:oauth:token-type:mtls", "subject_token": subject_token(cfg)}).encode()
    status, data = _post(STS_HOST, "/v1/token", body, {"Content-Type": "application/x-www-form-urlencoded"}, _ctx(cfg))
    if status != 200:
        raise RuntimeError(f"STS {status}: {data[:300].decode(errors='replace')}")
    j = json.loads(data)
    st.data["token"] = {"value": j["access_token"], "expires": time.time() + int(j.get("expires_in", 3600))}
    return str(j["access_token"])


def write_entries(cfg: dict[str, Any], token: str, entries: list[dict[str, Any]]) -> None:
    body = json.dumps({"logName": f"projects/{cfg['project']}/logs/{cfg['log_id']}", "partialSuccess": True,
                       "resource": {"type": "generic_node", "labels": {"project_id": cfg["project"], "location": cfg["location"],
                                                                       "namespace": "agy-devices", "node_id": cfg["device_id"]}},
                       "labels": {"agy_device": cfg["device_id"], "agy_shipper": VERSION},
                       "entries": entries}).encode()
    status, data = _post(LOGGING_HOST, "/v2/entries:write", body,
                         {"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    if status != 200:
        raise RuntimeError(f"Logging {status}: {data[:300].decode(errors='replace')}")


# ---------------------------------------------------------------------------------------------- spool + cap
def to_entry(e: dict[str, Any]) -> dict[str, Any]:
    ent: dict[str, Any] = {"severity": e["severity"], "jsonPayload": e["payload"]}
    if e.get("time"):
        ent["timestamp"] = e["time"]
    return ent


def spool_append(d: Path, entries: list[dict[str, Any]], max_mb: int) -> None:
    f = d / "spool.jsonl"
    with f.open("a", encoding="utf-8") as fh:
        for ent in entries:
            fh.write(json.dumps(ent) + "\n")
    if f.stat().st_size > max_mb * 1_000_000:   # keep the newest half, mark the gap
        lines = f.read_text(encoding="utf-8").splitlines()
        keep = lines[len(lines) // 2:]
        gap = {"severity": "WARNING", "jsonPayload": {"SourceName": "agy-mdm", "EventID": 0, "Channel": "AGY",
                                                    "Message": f"TELEMETRY_SPOOL_TRUNCATED dropped={len(lines) - len(keep)}"}}
        f.write_text("\n".join([json.dumps(gap)] + keep) + "\n", encoding="utf-8")


def spool_take(d: Path) -> list[dict[str, Any]]:
    f = d / "spool.jsonl"
    if not f.exists():
        return []
    out = [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]
    f.unlink()
    return out


def heartbeat(cfg: dict[str, Any], st: State) -> dict[str, Any]:
    d = st.dir
    spool = (d / "spool.jsonl").stat().st_size if (d / "spool.jsonl").exists() else 0
    not_after = str(cfg.get("cert_not_after", ""))
    msg = (f"TELEMETRY_HEARTBEAT device={cfg['device_id']} version={VERSION} spool_bytes={spool} "
           f"last_send={st.data.get('last_success', '')} cert_not_after={not_after}")
    return {"severity": "INFO", "jsonPayload": {"SourceName": "agy-mdm", "ProviderName": "agy-mdm", "EventID": 1020,
                                                "Channel": "AGY", "Computer": os.environ.get("COMPUTERNAME", ""), "Message": msg}}


def run(cfg: dict[str, Any]) -> int:
    d = Path(cfg["state_dir"])
    d.mkdir(parents=True, exist_ok=True)
    st = State(d)
    today = dt.date.today().isoformat()
    if st.data.get("day") != today:
        st.data.update({"day": today, "bytes_today": 0, "cap_noted": False})
    entries = [to_entry(e) for e in collect(cfg, st)]
    hb_every = int(cfg.get("heartbeat_min", 15)) * 60
    if time.time() - float(st.data.get("last_heartbeat", 0)) >= hb_every:
        entries.append(heartbeat(cfg, st))
        st.data["last_heartbeat"] = time.time()
    cap = int(cfg.get("daily_cap_mb", 5)) * 1_000_000
    size = sum(len(json.dumps(x)) for x in entries)
    if st.data["bytes_today"] + size > cap:
        entries = [x for x in entries if "TELEMETRY_HEARTBEAT" in json.dumps(x)]
        if not st.data.get("cap_noted"):
            entries.append({"severity": "WARNING", "jsonPayload": {"SourceName": "agy-mdm", "EventID": 1021, "Channel": "AGY",
                                                                 "Message": f"TELEMETRY_CAP_REACHED cap_mb={cap // 1_000_000}"}})
            st.data["cap_noted"] = True
    pending = spool_take(d) + entries
    sent = 0
    try:
        if pending:
            tok = access_token(cfg, st)
            for i in range(0, len(pending), MAX_BATCH):
                write_entries(cfg, tok, pending[i:i + MAX_BATCH])
                sent = i + len(pending[i:i + MAX_BATCH])
            st.data["last_success"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            st.data["bytes_today"] = int(st.data["bytes_today"]) + size
            st.data.pop("last_error", None)
        log(d, f"sent {sent} entries ({len(entries)} new)")
        rc = 0
    except Exception as ex:  # noqa: BLE001 - network / STS / API: keep the data, retry next run
        spool_append(d, pending[sent:], int(cfg.get("spool_mb", 50)))
        st.data["last_error"] = str(ex)[:300]
        log(d, f"send failed, {len(pending) - sent} entries spooled: {ex}")
        rc = 1
    st.data["last_run"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    st.save()
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="AGY telemetry shipper")
    ap.add_argument("--config", required=True)
    cfg = json.loads(Path(ap.parse_args().config).read_text(encoding="utf-8"))
    for k in ("project", "audience", "log_id", "location", "device_id", "cert_file", "key_file", "state_dir", "events"):
        if not cfg.get(k):
            print(f"config: {k} missing", file=sys.stderr)
            return 2
    return run(cfg)


if __name__ == "__main__":
    sys.exit(main())
