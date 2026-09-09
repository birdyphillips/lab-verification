#!/usr/bin/env python3
"""
FastAPI wrapper for Lab_verification_and_trouble_shooting.py

Endpoints:
  POST /connect          — open jump + store session
  POST /disconnect       — close jump session
  GET  /ping             — Stage 1: ping all (or ?device=alias)
  GET  /ssh              — Stage 2: SSH test
  GET  /verify           — Stage 3: full checks
  GET  /configs          — Stage 3b: pull & save running configs
  GET  /web-services     — web service reachability
  GET  /critical-links   — critical link summary
  GET  /run-all          — stages 1-3 + web + links in one call
  GET  /devices          — list known devices/aliases
  GET  /logs             — list log files
  GET  /logs/{filename}  — download a log file

Auth: every request that touches devices requires X-Jump-Password + X-Device-Password
headers (or pass them in /connect and reuse the session token).
"""

import io
import os
import time
import traceback
import uuid
from contextlib import redirect_stdout
from typing import Optional

import paramiko
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── import everything from the original script ──────────────────────────────
import sys
sys.path.insert(0, os.path.dirname(__file__))

from Lab_verification_and_trouble_shooting import (
    ALIASES, DEVICES, LOG_DIR, USERNAME, JUMP_HOST, JUMP_PORT,
    DISABLED_ALGORITHMS, KEY_PATH, CONFIG_DIR,
    load_key, stage_ping, stage_ssh, stage_verify, stage_configs,
    check_web_services, evaluate_critical_links,
    log,
)

# ── session store (in-memory; one session per token) ────────────────────────
_sessions: dict[str, dict] = {}   # token -> {"jump": SSHClient, "password": str}

app = FastAPI(title="Lab Verifier API", version="1.0")

_STATIC = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=_STATIC), name="static")

@app.get("/", include_in_schema=False)
def root():
    return FileResponse(os.path.join(_STATIC, "index.html"))


# ── helpers ──────────────────────────────────────────────────────────────────

def _resolve_targets(device: Optional[str]) -> dict:
    if not device:
        return DEVICES
    resolved = ALIASES.get(device, device)
    if resolved not in DEVICES:
        raise HTTPException(400, f"Unknown device '{device}'. Aliases: {', '.join(ALIASES)}")
    return {resolved: DEVICES[resolved]}


def _get_session(token: str) -> dict:
    s = _sessions.get(token)
    if not s:
        raise HTTPException(401, "Invalid or expired session token. POST /connect first.")
    if not s["jump"].get_transport() or not s["jump"].get_transport().is_active():
        _sessions.pop(token, None)
        raise HTTPException(401, "Jump session expired. POST /connect again.")
    return s


def _open_jump(jump_password: str) -> paramiko.SSHClient:
    key  = load_key(KEY_PATH)
    jump = paramiko.SSHClient()
    jump.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if key:
        try:
            jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                         pkey=key, timeout=20, banner_timeout=20,
                         disabled_algorithms=DISABLED_ALGORITHMS)
            return jump
        except Exception:
            pass
    jump.connect(JUMP_HOST, port=JUMP_PORT, username=USERNAME,
                 password=jump_password, timeout=20, banner_timeout=20,
                 disabled_algorithms=DISABLED_ALGORITHMS)
    return jump


def _capture(fn, *args, **kwargs) -> str:
    """Run fn(*args, **kwargs) and capture log output to a string."""
    buf = io.StringIO()
    handler = log.handlers[0].__class__(buf)
    handler.setFormatter(log.handlers[0].formatter)
    log.addHandler(handler)
    try:
        result = fn(*args, **kwargs)
    finally:
        log.removeHandler(handler)
    return result, buf.getvalue()


# ── models ───────────────────────────────────────────────────────────────────

class ConnectRequest(BaseModel):
    jump_password: str
    device_password: str


# ── endpoints ────────────────────────────────────────────────────────────────

@app.post("/connect", summary="Open jump server session")
def connect(body: ConnectRequest):
    try:
        jump = _open_jump(body.jump_password)
    except Exception as exc:
        raise HTTPException(502, f"Jump connection failed: {exc}")
    token = str(uuid.uuid4())
    _sessions[token] = {"jump": jump, "password": body.device_password}
    return {"token": token, "jump_host": JUMP_HOST, "username": USERNAME}


@app.post("/disconnect", summary="Close jump server session")
def disconnect(x_session_token: str = Header(...)):
    s = _sessions.pop(x_session_token, None)
    if s:
        try:
            s["jump"].close()
        except Exception:
            pass
    return {"disconnected": True}


@app.get("/devices", summary="List known devices and aliases")
def list_devices():
    return {
        "aliases": ALIASES,
        "devices": {h: d["label"] for h, d in DEVICES.items()},
    }


@app.get("/ping", summary="Stage 1 — ping reachability via jump")
def ping(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None, description="Alias or hostname"),
):
    s       = _get_session(x_session_token)
    targets = _resolve_targets(device)
    results = stage_ping(s["jump"], targets)
    return {"stage": "ping", "results": results}


@app.get("/ssh", summary="Stage 2 — SSH connectivity test")
def ssh_test(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None),
):
    s            = _get_session(x_session_token)
    targets      = _resolve_targets(device)
    ping_results = stage_ping(s["jump"], targets)
    ssh_results  = stage_ssh(s["jump"], targets, ping_results, USERNAME, s["password"])
    return {"stage": "ssh", "ping": ping_results, "ssh": ssh_results}


@app.get("/verify", summary="Stage 3 — full device checks")
def verify(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None),
):
    s            = _get_session(x_session_token)
    targets      = _resolve_targets(device)
    ping_results = stage_ping(s["jump"], targets)
    ssh_results  = stage_ssh(s["jump"], targets, ping_results, USERNAME, s["password"])
    all_results  = stage_verify(s["jump"], targets, ssh_results, USERNAME, s["password"])
    return {"stage": "verify", "results": all_results}


@app.get("/configs", summary="Stage 3b — pull and save running configs")
def pull_configs(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None),
):
    s            = _get_session(x_session_token)
    targets      = _resolve_targets(device)
    ping_results = stage_ping(s["jump"], targets)
    ssh_results  = stage_ssh(s["jump"], targets, ping_results, USERNAME, s["password"])
    stage_configs(s["jump"], targets, ssh_results, USERNAME, s["password"])
    saved = sorted(os.listdir(CONFIG_DIR)) if os.path.isdir(CONFIG_DIR) else []
    return {"stage": "configs", "saved_files": saved}


@app.get("/web-services", summary="Web service reachability check")
def web_services(x_session_token: str = Header(...)):
    s = _get_session(x_session_token)
    check_web_services(s["jump"])
    return {"stage": "web-services", "status": "completed — see server logs"}


@app.get("/critical-links", summary="Critical link summary")
def critical_links(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None),
):
    s            = _get_session(x_session_token)
    targets      = _resolve_targets(device)
    ping_results = stage_ping(s["jump"], targets)
    ssh_results  = stage_ssh(s["jump"], targets, ping_results, USERNAME, s["password"])
    all_results  = stage_verify(s["jump"], targets, ssh_results, USERNAME, s["password"])
    evaluate_critical_links(all_results)
    return {"stage": "critical-links", "status": "completed — see server logs"}


@app.get("/run-all", summary="Run all stages (1-3 + web + critical links)")
def run_all(
    x_session_token: str = Header(...),
    device: Optional[str] = Query(None),
):
    s            = _get_session(x_session_token)
    targets      = _resolve_targets(device)
    ping_results = stage_ping(s["jump"], targets)
    ssh_results  = stage_ssh(s["jump"], targets, ping_results, USERNAME, s["password"])
    all_results  = stage_verify(s["jump"], targets, ssh_results, USERNAME, s["password"])
    stage_configs(s["jump"], targets, ssh_results, USERNAME, s["password"])
    if not device:
        check_web_services(s["jump"])
        evaluate_critical_links(all_results)
    return {
        "stage":   "run-all",
        "ping":    ping_results,
        "ssh":     ssh_results,
        "verify":  all_results,
    }


@app.get("/logs", summary="List log files")
def list_logs():
    if not os.path.isdir(LOG_DIR):
        return {"logs": []}
    return {"logs": sorted(os.listdir(LOG_DIR))}


@app.get("/logs/{filename}", summary="Download a log file")
def get_log(filename: str):
    path = os.path.join(LOG_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(404, "Log file not found")
    return FileResponse(path, media_type="text/plain", filename=filename)
