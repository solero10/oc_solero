#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path

def run(cmd):
    return subprocess.check_output(cmd, text=True).strip()

def maybe_int(value):
    try:
        return int(value)
    except Exception:
        return None

def human_age(ms):
    if ms is None:
        return "unknown"
    seconds = max(0, int(ms // 1000))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"

def get_systemd_start():
    try:
        start_text = run(["systemctl", "--user", "show", "openclaw-gateway", "-p", "ActiveEnterTimestamp", "--value"])
        pid = run(["systemctl", "--user", "show", "openclaw-gateway", "-p", "MainPID", "--value"])
        if not start_text:
            return None
        start_epoch = maybe_int(run(["date", "-d", start_text, "+%s"]))
        return {
            "start_epoch": start_epoch,
            "start_text": start_text,
            "pid": maybe_int(pid) if pid else None,
            "source": "systemd"
        }
    except Exception:
        return None

def get_proc_start():
    try:
        status = json.loads(run(["openclaw", "gateway", "status", "--json"]))
        pid = status.get("service", {}).get("runtime", {}).get("pid")
        if not pid:
            return None
        start_text = run(["ps", "-p", str(pid), "-o", "lstart="])
        if not start_text:
            return None
        start_epoch = maybe_int(run(["date", "-d", start_text, "+%s"]))
        return {
            "start_epoch": start_epoch,
            "start_text": start_text,
            "pid": pid,
            "source": "ps"
        }
    except Exception:
        return None

def get_last_session():
    try:
        status = json.loads(run(["openclaw", "status", "--json"]))
        recent = status.get("sessions", {}).get("recent") or []
        if not recent:
            return None
        top = recent[0]
        return {
            "key": top.get("key"),
            "agentId": top.get("agentId"),
            "kind": top.get("kind"),
            "updatedAt": top.get("updatedAt"),
            "age": top.get("age")
        }
    except Exception:
        return None

def send_telegram(message):
    try:
        subprocess.check_output([
            "openclaw", "message", "send",
            "--channel", "telegram",
            "--target", "7729039890",
            "--message", message
        ], text=True)
        return True
    except Exception:
        return False

STATE_PATH = Path("/home/kernk/.openclaw/workspace/automation/state/gateway-restart.json")
STATE_PATH.parent.mkdir(parents=True, exist_ok=True)

state = {}
if STATE_PATH.exists():
    try:
        state = json.loads(STATE_PATH.read_text())
    except Exception:
        state = {}

current = get_systemd_start() or get_proc_start()
last_session = get_last_session()

if current and current.get("start_epoch"):
    prev_epoch = state.get("start_epoch")
    if prev_epoch and current["start_epoch"] != prev_epoch:
        prev_session = state.get("last_session") or {}
        prev_key = prev_session.get("key") or "unknown"
        prev_age = human_age(prev_session.get("age"))
        prev_agent = prev_session.get("agentId") or "unknown"
        prev_kind = prev_session.get("kind") or "unknown"
        msg = (
            "🔄 OpenClaw Gateway restarted.\n"
            f"Start time: {current.get('start_text','unknown')} ({current.get('source','unknown')}).\n"
            f"Where I was before: {prev_key} (agent {prev_agent}, {prev_kind}, last active {prev_age} ago)."
        )
        send_telegram(msg)
    # Update state after check
    state["start_epoch"] = current.get("start_epoch")
    state["start_text"] = current.get("start_text")
    state["pid"] = current.get("pid")
    state["source"] = current.get("source")

if last_session:
    state["last_session"] = last_session

state["checked_at"] = int(time.time())
STATE_PATH.write_text(json.dumps(state, indent=2) + "\n")
