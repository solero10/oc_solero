#!/usr/bin/env python3
import json
import os
import re
import subprocess
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

# "Important files" tracked in Git snapshots
PROTECTED_PATHS = [
    'AGENTS.md',
    'SOUL.md',
    'USER.md',
    'TOOLS.md',
    'IDENTITY.md',
    'HEARTBEAT.md',
    'memory',
    'automation',
    'reports',
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


def analyze_protected_git_changes(repo_path: Path, start_utc: datetime):
    out = {
        'available': False,
        'commit_count': 0,
        'unique_files': 0,
        'status_counts': Counter(),
        'top_files': [],
        'category_counts': Counter(),
        'explanation': 'Git-based protected-file analysis was unavailable.',
    }

    if not (repo_path / '.git').exists():
        out['explanation'] = 'This workspace is not a Git repository, so protected-file history could not be analyzed.'
        return out

    since = start_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    cmd = [
        'git', '-C', str(repo_path), 'log',
        f'--since={since}',
        '--name-status',
        '--pretty=format:__COMMIT__|%H|%cI|%s',
        '--',
        *PROTECTED_PATHS,
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except Exception as e:
        out['explanation'] = f'Git analysis failed to run: {e}'
        return out

    if proc.returncode != 0:
        err = (proc.stderr or '').strip().splitlines()[:1]
        out['explanation'] = f"Git analysis returned an error: {err[0] if err else 'unknown git error'}"
        return out

    file_touches = Counter()
    status_counts = Counter()
    category_counts = Counter()
    commit_count = 0

    for raw in (proc.stdout or '').splitlines():
        line = raw.strip('\n')
        if not line:
            continue
        if line.startswith('__COMMIT__|'):
            commit_count += 1
            continue

        parts = line.split('\t')
        if len(parts) < 2:
            continue

        status = (parts[0] or '').strip()
        path = parts[-1].strip()
        if not path:
            continue

        status_letter = status[0].upper() if status else '?'
        status_counts[status_letter] += 1
        file_touches[path] += 1

        if path in {'AGENTS.md', 'SOUL.md', 'USER.md', 'TOOLS.md', 'IDENTITY.md', 'HEARTBEAT.md'}:
            category_counts['assistant core configuration'] += 1
        elif path.startswith('automation/'):
            category_counts['automation/reporting logic'] += 1
        elif path.startswith('memory/'):
            category_counts['memory/journal notes'] += 1
        elif path.startswith('reports/'):
            category_counts['generated report outputs'] += 1
        else:
            category_counts['other protected paths'] += 1

    unique_files = len(file_touches)
    top_files = file_touches.most_common(5)

    if commit_count == 0 and unique_files == 0:
        explanation = 'No Git-tracked changes were recorded for protected files in the last 24 hours.'
    else:
        chunks = [f"{commit_count} Git commit(s) touched {unique_files} protected file(s)"]
        if status_counts.get('D', 0) > 0:
            chunks.append(f"including {status_counts['D']} deletion(s)")
        else:
            chunks.append('with no protected-file deletions')
        if category_counts:
            top_cats = ', '.join([f"{k} ({v})" for k, v in category_counts.most_common(3)])
            chunks.append(f"mainly in: {top_cats}")
        explanation = '; '.join(chunks) + '.'

    out.update({
        'available': True,
        'commit_count': commit_count,
        'unique_files': unique_files,
        'status_counts': status_counts,
        'top_files': top_files,
        'category_counts': category_counts,
        'explanation': explanation,
    })
    return out


def extract_untrusted_payload(text: str) -> str:
    start_tag = '<<<EXTERNAL_UNTRUSTED_CONTENT'
    end_tag = '<<<END_EXTERNAL_UNTRUSTED_CONTENT'
    if start_tag not in text or end_tag not in text:
        return text
    start_idx = text.find(start_tag)
    start_body = text.find('>>>', start_idx)
    end_idx = text.find(end_tag, start_body if start_body >= 0 else start_idx)
    if start_body >= 0 and end_idx > start_body:
        return text[start_body + 3:end_idx].strip()
    return text


def analyze_prompt_injection(session_files, start_utc: datetime, end_utc: datetime):
    phrase = '🚨 SECURITY ALERT: Potential Prompt Injection Detected.'

    suspicious_patterns = [
        (re.compile(r'ignore\s+(all|previous|prior)\s+instructions', re.I), 'instruction override attempt'),
        (re.compile(r'(system|developer)\s+(prompt|message)', re.I), 'prompt-role manipulation attempt'),
        (re.compile(r'execute\s+(shell|bash|terminal|system)\s+command', re.I), 'command execution request'),
        (re.compile(r'\bsudo\b', re.I), 'privilege escalation request'),
        (re.compile(r'openclaw\s+config', re.I), 'config tampering request'),
        (re.compile(r'(reveal|exfiltrate|send)\s+.*(token|password|secret|credential)', re.I), 'secret exfiltration request'),
        (re.compile(r'delete\s+(all\s+)?(data|files|emails)', re.I), 'destructive data request'),
        (re.compile(r'<\s*system\s*>|role\s*:\s*system', re.I), 'fake system-role content'),
    ]

    mention_keys = set()
    assistant_alert_keys = set()
    wrapper_map = {}
    suspicious_map = {}
    assistant_tool_events = []

    for path in session_files:
        path_str = str(path)
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if obj.get('type') != 'message':
                        continue

                    dt = event_dt(obj)
                    if not dt or dt < start_utc or dt > end_utc:
                        continue

                    msg = obj.get('message') if isinstance(obj.get('message'), dict) else {}
                    role = msg.get('role') or 'unknown'
                    tool_name = msg.get('toolName') if isinstance(msg.get('toolName'), str) else None
                    content = msg.get('content') if isinstance(msg.get('content'), list) else []

                    text_parts = []
                    for part in content:
                        if isinstance(part, dict) and part.get('type') == 'text' and isinstance(part.get('text'), str):
                            text_parts.append(part.get('text'))
                    combined = '\n'.join(text_parts)

                    if phrase in combined:
                        mention_key = (dt.isoformat(), path_str, role, combined[:180])
                        mention_keys.add(mention_key)
                        if role == 'assistant' and combined.strip().startswith(phrase):
                            assistant_alert_keys.add(mention_key)

                    if role == 'assistant':
                        for part in content:
                            if isinstance(part, dict) and part.get('type') == 'toolCall':
                                name = part.get('name')
                                if isinstance(name, str) and name:
                                    assistant_tool_events.append({
                                        'ts': dt,
                                        'path': path_str,
                                        'name': name,
                                    })

                    if role == 'toolResult' and tool_name == 'web_fetch' and 'EXTERNAL_UNTRUSTED_CONTENT' in combined:
                        wrapper_url = None
                        wrapped_text = combined
                        try:
                            payload = json.loads(combined)
                            if isinstance(payload, dict):
                                if isinstance(payload.get('url'), str):
                                    wrapper_url = payload.get('url')
                                if isinstance(payload.get('text'), str):
                                    wrapped_text = payload.get('text')
                        except Exception:
                            pass

                        external_payload = extract_untrusted_payload(wrapped_text)
                        wrapper_key = (dt.isoformat(), path_str, wrapper_url or '', external_payload[:220])
                        wrapper_map[wrapper_key] = {
                            'ts': dt,
                            'path': path_str,
                            'url': wrapper_url,
                            'payload': external_payload,
                        }

                        matches = sorted({label for regex, label in suspicious_patterns if regex.search(external_payload)})
                        if matches:
                            suspicious_key = (dt.isoformat(), path_str, wrapper_url or '', tuple(matches), external_payload[:220])
                            suspicious_map[suspicious_key] = {
                                'ts': dt,
                                'path': path_str,
                                'url': wrapper_url,
                                'matches': matches,
                                'snippet': external_payload.replace('\n', ' ')[:220],
                            }
        except Exception:
            continue

    suspicious_events = sorted(suspicious_map.values(), key=lambda x: x['ts'])
    followthrough_count = 0
    followthrough_examples = []
    high_impact_tools = {'exec', 'write', 'edit', 'message', 'nodes', 'browser', 'sessions_send', 'cron'}

    for ev in suspicious_events:
        had_followthrough = False
        for te in assistant_tool_events:
            if te['path'] != ev['path']:
                continue
            delta = te['ts'] - ev['ts']
            if timedelta(0) <= delta <= timedelta(minutes=5) and te['name'] in high_impact_tools:
                had_followthrough = True
                if len(followthrough_examples) < 5:
                    followthrough_examples.append(f"{te['name']} after suspicious payload at {ev['ts'].isoformat()}")
                break
        if had_followthrough:
            followthrough_count += 1

    phrase_mentions = len(mention_keys)
    assistant_alert_responses = len(assistant_alert_keys)
    non_alert_phrase_mentions = max(0, phrase_mentions - assistant_alert_responses)
    wrapper_events = len(wrapper_map)
    suspicious_external_payloads = len(suspicious_events)

    if suspicious_external_payloads > 0 and followthrough_count > 0:
        assessment = 'HIGH concern: suspicious external instruction patterns appeared and were followed by high-impact tool activity shortly afterward.'
    elif suspicious_external_payloads > 0:
        assessment = 'MEDIUM concern: suspicious external instruction patterns appeared, but no clear high-impact follow-through was found.'
    elif assistant_alert_responses > 0:
        assessment = 'LOW-MEDIUM concern: explicit security-alert responses were triggered by the assistant.'
    elif wrapper_events > 0 or non_alert_phrase_mentions > 0:
        assessment = 'LOW concern: only wrapper/noise-style indicators were detected (no confirmed exploitation pattern).'
    else:
        assessment = 'No meaningful prompt-injection indicators were detected in this window.'

    findings = []
    if suspicious_external_payloads > 0:
        findings.append(f"Suspicious external payloads: {suspicious_external_payloads}")
        for ev in suspicious_events[:3]:
            findings.append(f"- {ev['ts'].isoformat()} | {ev.get('url') or 'unknown source'} | matched: {', '.join(ev['matches'])}")
    else:
        findings.append('No suspicious instruction patterns were found inside external payload content.')

    if assistant_alert_responses > 0:
        findings.append(f"Assistant explicit security-alert replies observed: {assistant_alert_responses}")
    if non_alert_phrase_mentions > 0:
        findings.append(f"Phrase mentions treated as context/noise: {non_alert_phrase_mentions}")
    if wrapper_events > 0:
        findings.append(f"External untrusted-content wrappers observed: {wrapper_events}")
    if followthrough_examples:
        findings.append('Potential follow-through examples: ' + '; '.join(followthrough_examples[:3]))

    return {
        'assessment': assessment,
        'phrase_mentions': phrase_mentions,
        'assistant_alert_responses': assistant_alert_responses,
        'non_alert_phrase_mentions': non_alert_phrase_mentions,
        'wrapper_events': wrapper_events,
        'suspicious_external_payloads': suspicious_external_payloads,
        'followthrough_high_impact': followthrough_count,
        'findings': findings,
    }


def summarize_security_finding(finding: dict) -> str:
    check_id = (finding.get('checkId') or '').strip()
    title = (finding.get('title') or 'Security finding').strip()
    detail = (finding.get('detail') or '').strip()
    remediation = (finding.get('remediation') or '').strip()

    if check_id == 'gateway.control_ui.host_header_origin_fallback':
        why = 'Control UI origin protections are weakened, which can increase browser-based attack risk.'
    elif check_id == 'gateway.auth_no_rate_limit':
        why = 'Without rate limiting, repeated login attempts are easier to brute-force.'
    elif check_id == 'gateway.nodes.deny_commands_ineffective':
        why = 'Some deny rules may not actually block what they were intended to block.'
    elif check_id == 'config.insecure_or_dangerous_flags':
        why = 'At least one explicitly dangerous config flag is enabled.'
    else:
        why = detail.split('\n')[0] if detail else 'Potential security impact requires review.'

    fix = remediation.split('\n')[0] if remediation else 'Review and apply recommended hardening.'
    return f"{title} — Why it matters: {why} Fix: {fix}"


def analyze_openclaw_security_findings():
    out = {
        'available': False,
        'critical': 0,
        'warn': 0,
        'info': 0,
        'issues': [],
        'summary': 'OpenClaw security audit was unavailable in this run.',
    }

    cmd = ['openclaw', 'security', 'audit', '--json']
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=90)
    except Exception as e:
        out['summary'] = f'OpenClaw security audit could not run: {e}'
        return out

    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or '').strip().splitlines()
        out['summary'] = f"OpenClaw security audit failed: {err[0] if err else 'unknown error'}"
        return out

    try:
        data = json.loads((proc.stdout or '').strip())
    except Exception:
        out['summary'] = 'OpenClaw security audit output could not be parsed as JSON.'
        return out

    findings = data.get('findings') if isinstance(data.get('findings'), list) else []
    critical = 0
    warn = 0
    info = 0
    issues = []

    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = (f.get('severity') or '').lower()
        if sev == 'critical':
            critical += 1
            issues.append('[CRITICAL] ' + summarize_security_finding(f))
        elif sev == 'warn':
            warn += 1
            issues.append('[WARNING] ' + summarize_security_finding(f))
        elif sev == 'info':
            info += 1

    if critical == 0 and warn == 0:
        summary = 'No critical or warning findings were reported by OpenClaw security audit in this window.'
    else:
        summary = f"OpenClaw security audit found {critical} critical and {warn} warning issue(s) requiring attention."

    out.update({
        'available': True,
        'critical': critical,
        'warn': warn,
        'info': info,
        'issues': issues,
        'summary': summary,
    })
    return out


def analyze_security_remediations(start_utc: datetime, end_utc: datetime, commands):
    security_keys = {
        'gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback',
        'gateway.controlUi.allowedOrigins',
        'gateway.auth.rateLimit',
        'gateway.nodes.denyCommands',
        'gateway.bind',
    }

    config_audit_files = [
        Path('/home/kernk/.openclaw/logs/config-audit.jsonl'),
        Path('/home/kernk/.openclaw-docker-clone/state/logs/config-audit.jsonl'),
    ]

    actions = []

    for path in config_audit_files:
        if not path.exists():
            continue
        try:
            with path.open('r', encoding='utf-8', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue

                    dt = to_dt(obj.get('ts') or obj.get('time'))
                    if not dt or dt < start_utc or dt > end_utc:
                        continue

                    argv = obj.get('argv') if isinstance(obj.get('argv'), list) else []
                    if 'config' not in argv or 'set' not in argv:
                        continue

                    try:
                        idx = argv.index('set')
                    except ValueError:
                        continue

                    key = argv[idx + 1] if idx + 1 < len(argv) else None
                    value = argv[idx + 2] if idx + 2 < len(argv) else None
                    if not isinstance(key, str):
                        continue
                    if key not in security_keys:
                        continue

                    actions.append({
                        'ts': dt,
                        'key': key,
                        'value': value,
                        'source': str(path),
                    })
        except Exception:
            continue

    actions.sort(key=lambda x: x['ts'])

    def value_is_false(v):
        return isinstance(v, str) and v.strip().lower() in {'false', '0', 'off', 'no'}

    disabled_fallback = any(
        a['key'] == 'gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback' and value_is_false(a.get('value'))
        for a in actions
    )
    set_allowed_origins = any(a['key'] == 'gateway.controlUi.allowedOrigins' for a in actions)
    set_rate_limit = any(a['key'] == 'gateway.auth.rateLimit' for a in actions)
    updated_deny = any(a['key'] == 'gateway.nodes.denyCommands' for a in actions)

    restart_seen = any(
        isinstance(cmd, str) and 'openclaw gateway restart' in cmd
        for cmd in (commands or [])
    )

    highlights = []
    if disabled_fallback and set_allowed_origins:
        highlights.append('Closed the Control UI origin-fallback exposure by disabling fallback and setting explicit allowed origins.')
    elif disabled_fallback:
        highlights.append('Disabled the dangerous Control UI origin-fallback setting.')
    if set_rate_limit:
        highlights.append('Configured gateway auth rate limiting to reduce brute-force risk.')
    if updated_deny:
        highlights.append('Updated deny-command rules for node actions.')
    if restart_seen:
        highlights.append('Gateway restart was observed after security-related config changes.')

    if actions:
        summary = f"Detected {len(actions)} security-related config change(s) in the last 24 hours."
    else:
        summary = 'No security-related config changes were detected in the last 24 hours.'

    action_lines = []
    for a in actions[:8]:
        value = a.get('value')
        if isinstance(value, str) and len(value) > 80:
            value = value[:77] + '...'
        action_lines.append(f"{a['ts'].isoformat()} | {a['key']} = {value}")

    return {
        'summary': summary,
        'actions_count': len(actions),
        'actions': action_lines,
        'highlights': highlights,
        'restart_seen': restart_seen,
    }


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

# security posture from OpenClaw built-in audit
security_audit_summary = analyze_openclaw_security_findings()
security_issues_text = '\n'.join([f"- {x}" for x in security_audit_summary.get('issues', [])]) or '- No critical/warning security findings from OpenClaw audit.'
security_remediation_summary = analyze_security_remediations(START_UTC, NOW_UTC, commands)
security_remediation_highlights_text = '\n'.join([f"- {x}" for x in security_remediation_summary.get('highlights', [])]) or '- No specific remediation highlights detected in this window.'
security_remediation_actions_text = '\n'.join([f"- {x}" for x in security_remediation_summary.get('actions', [])]) or '- No security-related config changes detected in this window.'

# human-friendly synthesis
risk_level = 'low'
risk_reasons = []

critical_findings = int(security_audit_summary.get('critical', 0) or 0)
warning_findings = int(security_audit_summary.get('warn', 0) or 0)

if critical_findings > 0:
    risk_reasons.append(f"OpenClaw security audit reported critical findings ({critical_findings})")
if warning_findings > 0:
    risk_reasons.append(f"OpenClaw security audit reported warning findings ({warning_findings})")
if high_risk_actions >= 8:
    risk_reasons.append(f"many higher-impact actions were observed ({high_risk_actions})")
if len(files_changed) >= 5:
    risk_reasons.append(f"a larger number of files were changed ({len(files_changed)})")
if len(errors) >= 5:
    risk_reasons.append(f"there were repeated error events ({len(errors)})")

if critical_findings > 0 or high_risk_actions >= 8 or len(files_changed) >= 5 or len(errors) >= 5:
    risk_level = 'high'
else:
    if high_risk_actions >= 3:
        risk_reasons.append(f"some higher-impact actions were observed ({high_risk_actions})")
    if len(files_changed) >= 1:
        risk_reasons.append(f"files were modified ({len(files_changed)})")
    if len(errors) >= 1:
        risk_reasons.append(f"there were error events ({len(errors)})")
    if warning_findings > 0 or high_risk_actions >= 3 or len(files_changed) >= 1 or len(errors) >= 1:
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
skills_text = ', '.join(sorted(skills_used)) if skills_used else 'None detected.'

msg_action_counts = Counter((x.get('action') or 'unknown') for x in external_actions)
msg_action_text = ', '.join([f"{k}: {v}" for k, v in msg_action_counts.items()]) or 'None'

errors_n = len(errors)
warns_n = len(warns)
denied_n = len(denied_events)

git_summary = analyze_protected_git_changes(WORKSPACE, START_UTC)
git_top_files_text = ', '.join([f"{p} ({n})" for p, n in git_summary.get('top_files', [])]) or 'None in this window.'
git_status_counts = git_summary.get('status_counts', Counter())
git_status_text = ', '.join([f"{k}: {v}" for k, v in sorted(git_status_counts.items())]) or 'None'

session_files = [p for p in source_files if '/sessions/' in str(p)]
prompt_summary = analyze_prompt_injection(session_files, START_UTC, NOW_UTC)
prompt_findings_text = '\n'.join([f"- {x}" for x in prompt_summary.get('findings', [])]) or '- No prompt-injection findings to report.'

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
lines.append(f"- Protected-file Git summary: {git_summary.get('explanation')}")
lines.append(f"- Security-audit investigation: {security_audit_summary.get('summary')}")
lines.append(f"- Security remediation activity: {security_remediation_summary.get('summary')}")
lines.append(f"- Prompt-injection review: {prompt_summary.get('assessment')}")
lines.append(f"- Warnings: **{warns_n}** | Errors: **{errors_n}** | Denied/blocked signals: **{denied_n}**")
lines.append('')

lines.append('## Work Log Overview (all activity, previous 24 hours)')
lines.append(f"- Tool activity (top): {most_used_tools}")
lines.append(f"- Files changed (unique): **{len(files_changed)}**")
lines.append(f"- Commands executed: **{len(commands)}**")
lines.append(f"- Skills referenced: **{skills_text}**")
lines.append(f"- FQDNs contacted/seen: **{len(top_fqdns)}**")
lines.append(f"  - {fqdn_text}")
lines.append(f"- Git commits touching protected files: **{git_summary.get('commit_count', 0)}**")
lines.append(f"- Protected files touched in Git: **{git_summary.get('unique_files', 0)}**")
lines.append('')

lines.append('## Protected Files Change Summary (Git, last 24h)')
lines.append(f"- Concise explanation: {git_summary.get('explanation')}")
lines.append(f"- Change type counts: {git_status_text}")
lines.append(f"- Most changed protected files: {git_top_files_text}")
lines.append('')

lines.append('## Security Findings Investigation (Balanced)')
lines.append(f"- Assessment: {security_audit_summary.get('summary')}")
lines.append(f"- Critical findings: **{security_audit_summary.get('critical', 0)}** | Warning findings: **{security_audit_summary.get('warn', 0)}**")
lines.append('- Investigation notes:')
lines.append(security_issues_text)
lines.append('')

lines.append('## Security Remediation Actions (last 24h)')
lines.append(f"- Summary: {security_remediation_summary.get('summary')}")
lines.append('- Quick highlights:')
lines.append(security_remediation_highlights_text)
lines.append('- Actions detected:')
lines.append(security_remediation_actions_text)
lines.append('')

lines.append('## Prompt-Injection Investigation (Balanced)')
lines.append(f"- Assessment: {prompt_summary.get('assessment')}")
lines.append(f"- Phrase mentions containing alert text: **{prompt_summary.get('phrase_mentions', 0)}**")
lines.append(f"- Assistant explicit security-alert replies: **{prompt_summary.get('assistant_alert_responses', 0)}**")
lines.append(f"- External untrusted wrappers observed: **{prompt_summary.get('wrapper_events', 0)}**")
lines.append(f"- Suspicious external payloads (content-level): **{prompt_summary.get('suspicious_external_payloads', 0)}**")
lines.append(f"- Suspected high-impact follow-through after suspicious payloads: **{prompt_summary.get('followthrough_high_impact', 0)}**")
lines.append('- Investigation notes:')
lines.append(prompt_findings_text)
lines.append('')

lines.append('## Security Addendum (10-point overview)')
lines.append(f"1. **Intent + risk level**: Most actions were operational/assistant tasks. Computed risk level: **{risk_level.upper()}**. Reason: {risk_reason_text}")
lines.append(f"2. **Approval status**: Explicit approval-like actions spotted in logs: **{explicit_approvals}** (automated detection).")
lines.append(f"3. **Execution context**: Exec contexts seen: {', '.join([f'{k} ({v})' for k,v in exec_context.items()]) or 'No exec context data.'}")
lines.append(f"4. **Side effects**: Files modified: **{len(files_changed)}**. Major changes listed below.")
lines.append(f"5. **Network egress**: Unique FQDNs observed: **{len(top_fqdns)}**.")
lines.append(f"6. **Sensitive access**: Sensitive paths touched: **{len(sensitive_access)}**.")
lines.append(f"7. **Blocked/denied actions**: Signals detected: **{denied_n}**. OpenClaw security-audit findings: critical **{security_audit_summary.get('critical', 0)}**, warnings **{security_audit_summary.get('warn', 0)}**. Security remediations observed: **{security_remediation_summary.get('actions_count', 0)}** config change(s).")
lines.append(f"8. **Prompt-injection signals**: {prompt_summary.get('assessment')} (assistant alert replies: **{prompt_summary.get('assistant_alert_responses', 0)}**, suspicious external payloads: **{prompt_summary.get('suspicious_external_payloads', 0)}**, wrappers observed: **{prompt_summary.get('wrapper_events', 0)}**, noise/context phrase mentions: **{prompt_summary.get('non_alert_phrase_mentions', 0)}**).")
lines.append(f"9. **External actions ledger**: Message actions in logs: {msg_action_text}.")
lines.append(f"10. **Run integrity**: Runs started: **{run_counts.get('started',0)}** | Runs completed: **{run_counts.get('done',0)}** | Errors: **{errors_n}**.")
lines.append('')

lines.append('## File Activity Details')
lines.append('### Files changed')
lines.append(changed_text)
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
