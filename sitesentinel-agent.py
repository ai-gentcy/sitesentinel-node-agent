#!/usr/bin/env python3
"""Site Sentinel node agent — Raspberry Pi probe telemetry.

Single-file, stdlib-only. Runs as a systemd service (sitesentinel-agent.service).

Onboarding (RIPE-Atlas style): on first boot the agent GENERATES its own
node_key, persists it to /etc/sitesentinel/credentials.json (0600), and logs
its registration hash (sha256 of the key):

    Registration hash: <64 hex chars>

An operator adds that hash in the backoffice (Nodes → Add node); until then
POST /register answers 404 and the agent keeps polling. Once matched the
server returns node_id and heartbeats start:

  POST /heartbeat
    X-Sentinel-Node:      node_id
    X-Sentinel-Timestamp: unix seconds (server-offset corrected)
    X-Sentinel-Signature: hex hmac_sha256(node_key, "<ts>." + body)

Telemetry: local IP, CPU temperature, uptime, and modem signal/carrier via
ModemManager (mmcli). A missing modem or mmcli yields modem=null, never a crash.
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

AGENT_VERSION = "0.1.0"

SENTINEL_URL = os.environ.get("SENTINEL_URL", "https://nodes.sitesentinel.io").rstrip("/")
CRED_PATH = Path(os.environ.get("SENTINEL_CRED_PATH", "/etc/sitesentinel/credentials.json"))

DEFAULT_INTERVAL_S = 60
MAX_BACKOFF_S = 900
REVOKED_POLL_S = 3600
HTTP_TIMEOUT_S = 30


def log(msg: str) -> None:
    print(msg, flush=True)  # journald adds timestamps


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested in test_agent.py)
# ---------------------------------------------------------------------------

def sign(node_key: str, ts: int, body: str) -> str:
    return hmac.new(node_key.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()


def fingerprint(node_key: str) -> str:
    """The public registration hash an operator adds in the backoffice."""
    return hashlib.sha256(node_key.encode()).hexdigest()


def _num(v):
    """mmcli -J reports numbers as strings, absent values as '--'."""
    if v is None or v == "--":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_modem_list(raw: str):
    """First modem DBus path from `mmcli -L -J`, or None."""
    try:
        modems = json.loads(raw).get("modem-list", [])
        return modems[0] if modems else None
    except (json.JSONDecodeError, AttributeError):
        return None


def parse_modem(raw: str) -> dict:
    """Carrier fields from `mmcli -m <path> -J`."""
    out = {"operator_name": None, "mcc": None, "mnc": None, "access_tech": None}
    try:
        modem = json.loads(raw).get("modem", {})
    except json.JSONDecodeError:
        return out
    g3 = modem.get("3gpp", {}) or {}
    name = g3.get("operator-name")
    out["operator_name"] = name if name and name != "--" else None
    code = g3.get("operator-code")
    if code and code != "--" and len(code) >= 5:
        out["mcc"], out["mnc"] = code[:3], code[3:]
    techs = (modem.get("generic", {}) or {}).get("access-technologies") or []
    out["access_tech"] = techs[0] if techs else None
    return out


def parse_signal(raw: str) -> dict:
    """Signal metrics from `mmcli -m <path> --signal-get -J`.

    Prefers the 5g section when it carries values, else lte. rssi/rsrp are
    rounded to int dBm; rsrq/snr stay fractional.
    """
    out = {"rssi_dbm": None, "rsrp_dbm": None, "rsrq_db": None, "sinr_db": None}
    try:
        signal = json.loads(raw).get("modem", {}).get("signal", {})
    except (json.JSONDecodeError, AttributeError):
        return out
    for section in ("5g", "lte"):
        s = signal.get(section) or {}
        vals = {
            "rssi_dbm": _num(s.get("rssi")),
            "rsrp_dbm": _num(s.get("rsrp")),
            "rsrq_db": _num(s.get("rsrq")),
            "sinr_db": _num(s.get("snr")),
        }
        if any(v is not None for v in vals.values()):
            for k in ("rssi_dbm", "rsrp_dbm"):
                if vals[k] is not None:
                    vals[k] = round(vals[k])
            return vals
    return out


# ---------------------------------------------------------------------------
# Collectors (best-effort; every failure degrades to None)
# ---------------------------------------------------------------------------

def _run(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return r.stdout if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def read_cpu_temp():
    try:
        raw = Path("/sys/class/thermal/thermal_zone0/temp").read_text().strip()
        return round(int(raw) / 1000, 1)
    except (OSError, ValueError):
        pass
    out = _run(["vcgencmd", "measure_temp"])  # "temp=52.6'C"
    if out and "=" in out:
        try:
            return float(out.split("=")[1].split("'")[0])
        except (ValueError, IndexError):
            pass
    return None


def read_uptime_s():
    try:
        return int(float(Path("/proc/uptime").read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def read_hardware():
    try:
        return Path("/proc/device-tree/model").read_text().rstrip("\x00").strip() or None
    except OSError:
        return None


def read_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # no packets sent; just picks the route
            return s.getsockname()[0]
    except OSError:
        return None


_signal_setup_done = False


def read_modem():
    """Carrier + signal via ModemManager. None when no modem/mmcli."""
    global _signal_setup_done
    listing = _run(["mmcli", "-L", "-J"])
    if listing is None:
        return None
    # Rediscover the path every cycle — modem resets renumber the index.
    path = parse_modem_list(listing)
    if path is None:
        return None
    if not _signal_setup_done:
        _run(["mmcli", "-m", path, "--signal-setup=10"])
        _signal_setup_done = True
    modem = {}
    info = _run(["mmcli", "-m", path, "-J"])
    if info:
        modem.update(parse_modem(info))
    sig = _run(["mmcli", "-m", path, "--signal-get", "-J"])
    if sig:
        modem.update(parse_signal(sig))
    return modem or None


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def post(path: str, body: str, headers: dict):
    req = urllib.request.Request(
        SENTINEL_URL + path,
        data=body.encode(),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as res:
            return res.status, json.loads(res.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except json.JSONDecodeError:
            return e.code, {}
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        log(f"request failed: {e}")
        return None, {}


# ---------------------------------------------------------------------------
# Enrollment + heartbeat loop
# ---------------------------------------------------------------------------

def load_credentials() -> dict:
    """{node_key, node_id?} — the key is generated HERE on first run (never by
    the server), so the machine's identity exists before any network contact."""
    try:
        creds = json.loads(CRED_PATH.read_text())
        if creds.get("node_key"):
            return creds
    except (OSError, json.JSONDecodeError):
        pass
    creds = {"node_key": secrets.token_hex(32)}
    save_credentials(creds)
    log("generated new node key")
    return creds


def save_credentials(creds: dict) -> None:
    CRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    CRED_PATH.write_text(json.dumps(creds))
    os.chmod(CRED_PATH, 0o600)


def register(creds: dict):
    """Poll /register until an operator has added our hash in the backoffice."""
    fp = fingerprint(creds["node_key"])
    log(f"Registration hash: {fp}")
    log("add this hash in the backoffice (Nodes -> Add node) to activate this node")
    backoff = DEFAULT_INTERVAL_S
    while True:
        status, res = post(
            "/register",
            json.dumps(
                {
                    "node_key": creds["node_key"],
                    "hostname": socket.gethostname(),
                    "hardware": read_hardware(),
                    "agent_version": AGENT_VERSION,
                    "local_ip": read_local_ip(),
                }
            ),
            {},
        )
        if status == 200 and res.get("node_id"):
            creds["node_id"] = res["node_id"]
            save_credentials(creds)
            log(f"registered as {creds['node_id']}")
            return creds, int(res.get("heartbeat_interval_s", DEFAULT_INTERVAL_S))
        if status == 404:
            # Hash not added (yet) — normal while the operator hasn't pasted it.
            log(f"not registered yet (hash {fp[:16]}…) — retrying in {DEFAULT_INTERVAL_S}s")
            time.sleep(DEFAULT_INTERVAL_S)
            continue
        if status == 403:
            log("node revoked/disabled — slow-polling")
            time.sleep(REVOKED_POLL_S)
            continue
        log(f"register failed (status={status}), retrying in {backoff}s")
        time.sleep(backoff)
        backoff = min(backoff * 2, MAX_BACKOFF_S)


def build_heartbeat(ts: int) -> str:
    return json.dumps(
        {
            "ts": ts,
            "local_ip": read_local_ip(),
            "cpu_temp_c": read_cpu_temp(),
            "uptime_s": read_uptime_s(),
            "agent_version": AGENT_VERSION,
            "modem": read_modem(),
        }
    )


def main() -> None:
    creds = load_credentials()
    interval = DEFAULT_INTERVAL_S
    if not creds.get("node_id"):
        creds, interval = register(creds)

    clock_offset = 0  # server_ts - local, learned from 401 skew responses
    backoff = interval
    while True:
        ts = int(time.time()) + clock_offset
        body = build_heartbeat(ts)
        headers = {
            "X-Sentinel-Node": creds["node_id"],
            "X-Sentinel-Timestamp": str(ts),
            "X-Sentinel-Signature": sign(creds["node_key"], ts, body),
        }
        status, res = post("/heartbeat", body, headers)

        if status == 200:
            interval = int(res.get("interval_s", interval))
            backoff = interval
            time.sleep(interval)
        elif status == 401 and res.get("error") == "skew" and "server_ts" in res:
            clock_offset = int(res["server_ts"]) - int(time.time())
            log(f"clock skew corrected (offset {clock_offset}s), retrying")
        elif status == 401:
            # Our node_id is no longer accepted (e.g. the node was deleted and
            # re-added with the same hash) — fall back to registration.
            log("heartbeat unauthorized — re-registering")
            creds.pop("node_id", None)
            creds, interval = register(creds)
            backoff = interval
        elif status == 403:
            log(f"node revoked/disabled — slow-polling every {REVOKED_POLL_S}s")
            time.sleep(REVOKED_POLL_S)
        else:
            log(f"heartbeat failed (status={status}), retrying in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, MAX_BACKOFF_S)


if __name__ == "__main__":
    main()
