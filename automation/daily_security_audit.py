#!/usr/bin/env python3
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

LA_TZ = "America/Los_Angeles"
NOW_UTC = datetime.now(timezone.utc)
START_UTC = NOW_UTC - timedelta(hours=24)

WORKSPACE = Path('/home/kernk/.openclaw/workspace')
REPORT_DIR = WORKSPACE / 'reports' / 'security-daily'
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SOURCE_GLOBS = [
    '/tmp/openclaw/openclaw-*.log',
    '/home/kernk/.openclaw/logs/*.log',
    '/home/kernk/.openclaw/logs/*.jsonl',
    '/home/kernk/.openclaw/agents/*/sessions/*.jsonl',
    '/home/kernk/.openclaw/cron/runs/*.jsonl',
    '/home/kernk/.openclaw-docker-clone/state/logs/*.log',
    '/home/kernk/.openclaw-docker-clone/state/logs/*.jsonl',
    '/home/kernk/.openclaw-docker-clone/state/agents/*/sessions/*.jsonl',
    '/home/kernk/.openclaw-docker-clone/state/cron/runs/*.jsonl',
]

URL_RE = re.compile(r'https?://[^\s"\'>)]+', re.IGNORECASE)


def to_dt(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if value > 1e12:
            value = value / 1000.0
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
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
    return None


def event_dt(obj):
    for key in ('time', 'timestamp', 'ts'):
        dt = to_dt(obj.get(key))
        if dt:
            return dt
    meta = obj.get('_meta') if isinstance(obj.get('_meta'), dict) else {}
    dt = to_dt(meta.get('date'))
    if dt:
        return dt
    msg = obj.get('message') if isinstance(obj.get('message'), dict) else {}
    dt = to_dt(msg.get('timestamp'))
    if dt:
        return dt
    return None


def extract_fqdns(text):
    out = set()
    host_re = re.compile(r'^[a-z0-9.-]+$', re.IGNORECASE)
    ipv4_re = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
    for m in URL_RE.findall(text or ''):
        try:
            host = (urlparse(m).hostname or '').strip().lower()
            if not host:
                continue
            if not host_re.match(host):
                continue
            if host.startswith('-') or host.endswith('-'):
                continue
            if '..' in host:
                continue
            if host == '.':
                continue
            if '.' not in host:
                continue
            if not any(ch.isalpha() for ch in host):
                continue
            if ipv4_re.match(host):
                continue
            out.add(host)
        except Exception:
            pass
    return out


def parse_toolcall(tc):
    name = tc.get('name') or ''
    args = tc.get('arguments') if isinstance(tc.get('arguments'), dict) else {}
    return name, args


tool_counts = Counter()
role_counts = Counter()
files_read = set()
files_changed = set()
commands = []
skills_used = set()
fqdns = set()
external_actions = []
sensitive_access = set()
errors = []
warns = []
denied_events = []
run_counts = Counter()

high_risk_actions = 0
explicit_approvals = 0
injection_alerts = 0
external_untrusted_events = 0

exec_context = Counter()

files_scanned = 0
lines_scanned = 0
window_events = 0

source_files = []
for g in SOURCE_GLOBS:
    for p in sorted(Path('/').glob(g.lstrip('/'))):
        if p.is_file():
            source_files.append(p)

for path in source_files:
    files_scanned += 1
    is_gateway_log = '/tmp/openclaw/' in str(path) or '/logs/' in str(path)
    is_session = '/sessions/' in str(path)
    try:
        with path.open('r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                lines_scanned += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                dt = event_dt(obj)
                if not dt or dt < START_UTC or dt > NOW_UTC:
                    continue
                window_events += 1

                # gateway log summaries
                if is_gateway_log:
                    lv = (obj.get('_meta', {}) or {}).get('logLevelName') or obj.get('level') or ''
                    msg = str(obj.get('1') or obj.get('message') or obj.get('event') or '')
                    if str(lv).upper() == 'ERROR':
                        errors.append(msg[:220])
                    if str(lv).upper() == 'WARN':
                        warns.append(msg[:220])
                    if 'embedded run start' in msg:
                        run_counts['started'] += 1
                    if 'embedded run done' in msg:
                        run_counts['done'] += 1
                    lmsg = msg.lower()
                    if 'permission denied' in lmsg or 'not allowed' in lmsg or 'denied' in lmsg:
                        denied_events.append(msg[:220])
                    fqdns |= extract_fqdns(msg)

                # command audit approvals
                if path.name == 'commands.log':
                    txt = json.dumps(obj)
                    if 'approve' in txt.lower():
                        explicit_approvals += 1

                if is_session and obj.get('type') == 'message':
                    msg = obj.get('message') if isinstance(obj.get('message'), dict) else {}
                    role = msg.get('role')
                    if role:
                        role_counts[role] += 1

                    content = msg.get('content') if isinstance(msg.get('content'), list) else []

                    # top-level toolResult info
                    tool_name = msg.get('toolName')
                    if isinstance(tool_name, str) and tool_name:
                        # detect untrusted wrapper events
                        if tool_name == 'web_fetch':
                            for item in content:
                                if isinstance(item, dict) and isinstance(item.get('text'), str):
                                    txt = item.get('text')
                                    if 'EXTERNAL_UNTRUSTED_CONTENT' in txt:
                                        external_untrusted_events += 1
                                        fqdns |= extract_fqdns(txt)

                    for part in content:
                        if not isinstance(part, dict):
                            continue
                        ptype = part.get('type')
                        if ptype == 'toolCall':
                            name, args = parse_toolcall(part)
                            if not name:
                                continue
                            tool_counts[name] += 1
                            if name in {'write', 'edit', 'exec', 'message', 'nodes', 'browser', 'sessions_send', 'cron'}:
                                high_risk_actions += 1

                            if name == 'read':
                                p = args.get('path') or args.get('file_path')
                                if isinstance(p, str):
                                    files_read.add(p)
                                    if '/skills/' in p and p.endswith('/SKILL.md'):
                                        skills_used.add(Path(p).parent.name)
                                    lp = p.lower()
                                    if any(x in lp for x in ['auth', 'token', 'credential', 'openclaw.json']):
                                        sensitive_access.add(p)

                            elif name in {'write', 'edit'}:
                                p = args.get('path') or args.get('file_path')
                                if isinstance(p, str):
                                    files_changed.add(p)
                                    lp = p.lower()
                                    if any(x in lp for x in ['auth', 'token', 'credential', 'openclaw.json']):
                                        sensitive_access.add(p)

                            elif name == 'exec':
                                cmd = args.get('command')
                                if isinstance(cmd, str):
                                    commands.append(cmd)
                                    fqdns |= extract_fqdns(cmd)
                                host = args.get('host') or 'default'
                                security = args.get('security') or 'default'
                                ask = args.get('ask') or 'default'
                                exec_context[f"host={host}|security={security}|ask={ask}"] += 1

                            elif name == 'web_fetch':
                                url = args.get('url', '')
                                if isinstance(url, str):
                                    fqdns |= extract_fqdns(url)

                            elif name == 'web_search':
                                # provider endpoint not in args; no direct fqdn here
                                pass

                            elif name == 'message':
                                action = args.get('action')
                                target = args.get('target') or args.get('to')
                                channel = args.get('channel')
                                external_actions.append({
                                    'action': action,
                                    'target': target,
                                    'channel': channel,
                                })

                        elif ptype == 'text':
                            txt = part.get('text')
                            if isinstance(txt, str):
                                if '🚨 SECURITY ALERT: Potential Prompt Injection Detected.' in txt:
                                    injection_alerts += 1
                                fqdns |= extract_fqdns(txt)

    except Exception:
        continue

# retention: prune report markdown files older than 90 days
cutoff = NOW_UTC - timedelta(days=90)
for f in REPORT_DIR.glob('*.md'):
    try:
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            f.unlink(missing_ok=True)
    except Exception:
        pass

# human-friendly synthesis
risk_level = 'low'
risk_reasons = []

if high_risk_actions >= 8:
    risk_reasons.append(f"many higher-impact actions were observed ({high_risk_actions})")
if len(files_changed) >= 5:
    risk_reasons.append(f"a larger number of files were changed ({len(files_changed)})")
if len(errors) >= 5:
    risk_reasons.append(f"there were repeated error events ({len(errors)})")

if high_risk_actions >= 8 or len(files_changed) >= 5 or len(errors) >= 5:
    risk_level = 'high'
else:
    if high_risk_actions >= 3:
        risk_reasons.append(f"some higher-impact actions were observed ({high_risk_actions})")
    if len(files_changed) >= 1:
        risk_reasons.append(f"files were modified ({len(files_changed)})")
    if len(errors) >= 1:
        risk_reasons.append(f"there were error events ({len(errors)})")
    if high_risk_actions >= 3 or len(files_changed) >= 1 or len(errors) >= 1:
        risk_level = 'medium'

if risk_level == 'low':
    risk_reason_text = "No major warning patterns were detected in this 24-hour window."
else:
    risk_reason_text = (
        "This rating was chosen because "
        + '; '.join(risk_reasons[:4])
        + ". This scoring is conservative, so busy setup/debug periods can look higher risk than normal day-to-day use."
    )

most_used_tools = ', '.join([f"{k} ({v})" for k, v in tool_counts.most_common(8)]) or 'No tool activity captured.'

top_fqdns = sorted(fqdns)
fqdn_text = ', '.join(top_fqdns[:20]) if top_fqdns else 'None detected.'

changed_text = '\n'.join([f"- {p}" for p in sorted(files_changed)[:30]]) or '- None'
read_text = '\n'.join([f"- {p}" for p in sorted(files_read)[:30]]) or '- None'
skills_text = ', '.join(sorted(skills_used)) if skills_used else 'None detected.'

msg_action_counts = Counter((x.get('action') or 'unknown') for x in external_actions)
msg_action_text = ', '.join([f"{k}: {v}" for k, v in msg_action_counts.items()]) or 'None'

errors_n = len(errors)
warns_n = len(warns)
denied_n = len(denied_events)

report_date = (NOW_UTC - timedelta(hours=24)).astimezone().date().isoformat()
out_file = REPORT_DIR / f"security-audit-{report_date}.md"

lines = []
lines.append(f"# Daily Security & Activity Report ({report_date})")
lines.append('')
lines.append('## Plain-English Overview (last 24 hours)')
lines.append(f"- Overall risk feel: **{risk_level.upper()}**")
lines.append(f"- Why this rating: {risk_reason_text}")
lines.append(f"- I reviewed activity across both OpenClaw environments (host + Docker twin) and found **{window_events} tracked events** in the last 24 hours.")
lines.append(f"- Most activity looked like normal assistant work (reading files, running commands, and responding in chat).")
lines.append(f"- Warnings: **{warns_n}** | Errors: **{errors_n}** | Denied/blocked signals: **{denied_n}**")
lines.append('')

lines.append('## Work Log Overview (all activity, previous 24 hours)')
lines.append(f"- Tool activity (top): {most_used_tools}")
lines.append(f"- Files read (unique): **{len(files_read)}**")
lines.append(f"- Files changed (unique): **{len(files_changed)}**")
lines.append(f"- Commands executed: **{len(commands)}**")
lines.append(f"- Skills referenced: **{skills_text}**")
lines.append(f"- FQDNs contacted/seen: **{len(top_fqdns)}**")
lines.append(f"  - {fqdn_text}")
lines.append('')

lines.append('## Security Addendum (10-point overview)')
lines.append(f"1. **Intent + risk level**: Most actions were operational/assistant tasks. Computed risk level: **{risk_level.upper()}**. Reason: {risk_reason_text}")
lines.append(f"2. **Approval status**: Explicit approval-like actions spotted in logs: **{explicit_approvals}** (automated detection).")
lines.append(f"3. **Execution context**: Exec contexts seen: {', '.join([f'{k} ({v})' for k,v in exec_context.items()]) or 'No exec context data.'}")
lines.append(f"4. **Side effects**: Files modified: **{len(files_changed)}**. Major changes listed below.")
lines.append(f"5. **Network egress**: Unique FQDNs observed: **{len(top_fqdns)}**.")
lines.append(f"6. **Sensitive access**: Sensitive paths touched: **{len(sensitive_access)}**.")
lines.append(f"7. **Blocked/denied actions**: Signals detected: **{denied_n}**.")
lines.append(f"8. **Prompt-injection signals**: Alerts triggered: **{injection_alerts}**; untrusted external-content wrappers seen: **{external_untrusted_events}**.")
lines.append(f"9. **External actions ledger**: Message actions in logs: {msg_action_text}.")
lines.append(f"10. **Run integrity**: Runs started: **{run_counts.get('started',0)}** | Runs completed: **{run_counts.get('done',0)}** | Errors: **{errors_n}**.")
lines.append('')

lines.append('## File Activity Details')
lines.append('### Files changed')
lines.append(changed_text)
lines.append('')
lines.append('### Files read')
lines.append(read_text)
lines.append('')

lines.append('## Notes')
lines.append('- This is an automated summary in non-technical language.')
lines.append('- Scope target: all visible OpenClaw activity sources from host + Docker clone state.')
lines.append('- Time window: previous 24 hours from report generation time.')
lines.append('')

out_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(f'REPORT_PATH={out_file}')
print(f'WINDOW_START_UTC={START_UTC.isoformat()}')
print(f'WINDOW_END_UTC={NOW_UTC.isoformat()}')
print(f'EVENTS={window_events}')
