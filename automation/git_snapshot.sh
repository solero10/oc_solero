#!/usr/bin/env bash
set -euo pipefail

WORKTREE="/home/kernk/.openclaw/workspace"
LOG_DIR="$WORKTREE/automation/logs"
MODE="${1:-auto}"

mkdir -p "$LOG_DIR"

TS_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
LOG_FILE="$LOG_DIR/git-snapshot.log"

{
  echo "[$TS_UTC] snapshot start mode=$MODE"

  cd "$WORKTREE"

  # Ensure commit identity exists (local repo only)
  if ! git config --local user.name >/dev/null; then
    git config --local user.name "Solero Bot"
  fi
  if ! git config --local user.email >/dev/null; then
    git config --local user.email "solero-bot@local"
  fi

  # Ensure remote exists
  if ! git remote get-url origin >/dev/null 2>&1; then
    echo "[$TS_UTC] ERROR: git remote 'origin' is not configured"
    exit 1
  fi

  TRACKED_PATHS=(
    "AGENTS.md"
    "SOUL.md"
    "USER.md"
    "TOOLS.md"
    "IDENTITY.md"
    "HEARTBEAT.md"
    "memory"
    "automation"
    "reports"
  )

  # Stage only selected paths
  for p in "${TRACKED_PATHS[@]}"; do
    if [[ -e "$p" ]]; then
      git add -A -- "$p"
    fi
  done

  # Nothing to commit?
  if [[ -z "$(git status --porcelain -- "${TRACKED_PATHS[@]}")" ]]; then
    echo "[$TS_UTC] no tracked changes"
    exit 0
  fi

  MSG="snapshot($MODE): $(date +"%Y-%m-%d %H:%M %Z")"
  git commit -m "$MSG"

  # First push may need upstream
  CURRENT_BRANCH="$(git branch --show-current)"
  if ! git rev-parse --abbrev-ref --symbolic-full-name "@{u}" >/dev/null 2>&1; then
    git push -u origin "$CURRENT_BRANCH"
  else
    git push origin "$CURRENT_BRANCH"
  fi

  echo "[$TS_UTC] snapshot success"
} >> "$LOG_FILE" 2>&1
