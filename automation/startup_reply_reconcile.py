#!/usr/bin/env python3
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

SESSIONS_DIR = Path('/home/kernk/.openclaw/agents/main/sessions')
STATE_FILE = Path('/home/kernk/.openclaw/workspace/memory/startup-reconcile-state.json')
MAX_SCAN_LINES = 1200
MIN_STALE_SECONDS = 45


def parse_ts(v: str):
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def load_state():
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding='utf-8'))
    except Exception:
        pass
    return {"reported": {}}


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n", encoding='utf-8')


def tail_lines(path: Path, max_lines: int):
    # Simple safe tail implementation for moderate file sizes
    try:
        lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
        return lines[-max_lines:]
    except Exception:
        return []


def find_latest_session_file():
    files = [p for p in SESSIONS_DIR.glob('*.jsonl') if p.is_file()]
    if not files:
        return None
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0]


def summarize_text(content):
    if not isinstance(content, list):
        return ""
    out = []
    for part in content:
        if isinstance(part, dict) and part.get('type') == 'text' and isinstance(part.get('text'), str):
            out.append(part['text'])
    txt = " ".join(out).strip().replace('\n', ' ')
    return txt[:220]


def main():
    now = datetime.now(timezone.utc)
    result = {
        "ok": True,
        "unresolved": False,
        "reason": "none",
    }

    sf = find_latest_session_file()
    if not sf:
        result.update({"reason": "no_session_files"})
        print(json.dumps(result))
        return

    lines = tail_lines(sf, MAX_SCAN_LINES)
    last_user = None
    last_assistant = None

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get('type') != 'message':
            continue
        msg = obj.get('message') if isinstance(obj.get('message'), dict) else {}
        role = msg.get('role')
        ts = parse_ts(obj.get('timestamp'))
        if ts is None:
            ts = parse_ts(msg.get('timestamp'))
        if ts is None:
            continue

        if role == 'user':
            last_user = {
                'id': obj.get('id'),
                'ts': ts,
                'text': summarize_text(msg.get('content')),
            }
        elif role == 'assistant':
            # gateway-injected status messages are assistant role too but still count as reply
            last_assistant = {
                'id': obj.get('id'),
                'ts': ts,
            }

    if not last_user:
        result.update({"reason": "no_user_messages"})
        print(json.dumps(result))
        return

    unresolved = False
    reason = ""
    if last_assistant is None:
        unresolved = True
        reason = "no_assistant_reply"
    elif last_user['ts'] > last_assistant['ts']:
        unresolved = True
        reason = "last_user_after_last_assistant"

    age_ok = (now - last_user['ts']) >= timedelta(seconds=MIN_STALE_SECONDS)

    state = load_state()
    reported = state.setdefault('reported', {})
    key = f"{sf.name}:{last_user.get('id') or last_user['ts'].isoformat()}"

    if unresolved and age_ok and not reported.get(key):
        reported[key] = now.isoformat()
        save_state(state)
        result.update({
            "unresolved": True,
            "reason": reason,
            "session_file": str(sf),
            "last_user_id": last_user.get('id'),
            "last_user_ts": last_user['ts'].isoformat(),
            "last_user_excerpt": last_user['text'],
        })
    else:
        result.update({
            "unresolved": False,
            "reason": reason if unresolved else "up_to_date",
            "session_file": str(sf),
            "last_user_id": last_user.get('id'),
            "last_user_ts": last_user['ts'].isoformat(),
        })

    print(json.dumps(result))


if __name__ == '__main__':
    main()
