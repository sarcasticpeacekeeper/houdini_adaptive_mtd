"""Adaptive MTD Dashboard — FastAPI app.

Served on port 43123 on the sensor. Reads state.json (written by the
controller) and renders a live view + an A/B comparison table + the
list of attackers currently being redirected to the honeypot. The
`mtd_enabled` toggle POSTs back to config.json, which the controller
re-reads on its next tick.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


CONFIG_PATH = Path(os.environ.get("MTD_CONFIG_PATH", "/etc/mtd/config.json"))
STATE_PATH = Path(os.environ.get("MTD_STATE_PATH", "/var/log/mtd/state.json"))
ROTATION_LOG = Path(os.environ.get("MTD_ROTATION_LOG", "/var/log/mtd/rotations.json"))

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Adaptive MTD Dashboard")


def _read_json(path: Path, default=None):
    if default is None:
        default = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _read_rotation_log_tail(n: int = 50):
    if not ROTATION_LOG.exists():
        return []
    lines = ROTATION_LOG.read_text(encoding="utf-8").splitlines()
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    state = _read_json(STATE_PATH, default={})
    config = _read_json(CONFIG_PATH, default={})
    rotations = _read_rotation_log_tail(50)
    attackers = state.get("attackers", {})
    # read recent Suricata alerts from eve.json
    alerts = []
    try:
        with open("/var/log/suricata/eve.json", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or '"event_type":"alert"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                a = obj.get("alert", {})
                sev = a.get("severity", 3)
                severity_str = "high" if sev == 1 else ("medium" if sev == 2 else "low")
                alerts.append({
                    "timestamp": obj.get("timestamp", ""),
                    "src_ip": obj.get("src_ip", ""),
                    "dest_ip": obj.get("dest_ip", ""),
                    "dest_port": obj.get("dest_port", ""),
                    "signature": a.get("signature", ""),
                    "signature_id": a.get("signature_id", 0),
                    "severity": severity_str,
                    "severity_num": sev,
                })
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return templates.TemplateResponse(request, "index.html", {
        "state": state,
        "config": config,
        "rotations": rotations,
        "attackers": attackers,
        "alerts": alerts[-20:],
    })


@app.get("/api/surface")
async def api_surface():
    """Compact endpoint the client loop polls to follow the surface."""
    state = _read_json(STATE_PATH, default={})
    return JSONResponse({
        "current_vip": state.get("current_vip", ""),
        "current_ssh_port": state.get("current_ssh_port", 0),
        "current_https_port": state.get("current_https_port", 0),
        "threat_level": state.get("threat_level", 0),
        "t_eff": state.get("t_eff", 60),
        "mtd_enabled": state.get("mtd_enabled", False),
        "rotation_count": state.get("rotation_count", 0),
    })


@app.get("/api/state")
async def api_state():
    return JSONResponse(_read_json(STATE_PATH, default={}))


@app.get("/api/rotations")
async def api_rotations():
    return JSONResponse(_read_rotation_log_tail(100))


@app.get("/api/attackers")
async def api_attackers():
    """List of source IPs currently being redirected to the honeypot's
    dummy website. Each entry: src_ip, flagged_at, trigger_sid, message."""
    state = _read_json(STATE_PATH, default={})
    return JSONResponse(state.get("attackers", {}))


@app.get("/api/alerts")
async def api_alerts():
    """Recent Suricata alerts from eve.json — shows the signature,
    severity, source IP, and timestamp for each alert. This makes it clear which
    rule fired (scan = severity 2, brute force = severity 1)."""
    alerts = []
    try:
        with open("/var/log/suricata/eve.json", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or '"event_type":"alert"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                a = obj.get("alert", {})
                sev = a.get("severity", 3)
                severity_str = "high" if sev == 1 else ("medium" if sev == 2 else "low")
                alerts.append({
                    "timestamp": obj.get("timestamp", ""),
                    "src_ip": obj.get("src_ip", ""),
                    "dest_ip": obj.get("dest_ip", ""),
                    "dest_port": obj.get("dest_port", ""),
                    "signature": a.get("signature", ""),
                    "signature_id": a.get("signature_id", 0),
                    "severity": severity_str,
                    "severity_num": sev,
                })
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return JSONResponse(alerts[-20:])


@app.post("/api/toggle")
async def api_toggle(enabled: bool = Form(...)):
    """Flip the mtd_enabled toggle. Persists to config.json; the controller
    re-reads it on its next tick (every tick_seconds)."""
    config = _read_json(CONFIG_PATH, default={})
    config["mtd_enabled"] = bool(enabled)
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    return RedirectResponse(url="/", status_code=303)


@app.post("/api/enable")
async def api_enable():
    return await api_toggle(enabled=True)


@app.post("/api/disable")
async def api_disable():
    return await api_toggle(enabled=False)


@app.post("/api/reset")
async def api_reset():
    """Reset all MTD state: clear per-source redirects, reset threat level,
    truncate logs, flush conntrack. Does NOT restart Suricata."""
    import subprocess
    subprocess.run(["bash", "/opt/mtd-client/reset.sh"], capture_output=True)
    return {"status": "reset complete"}
