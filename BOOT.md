# BOOT.md

On gateway startup, run a delivery reconciliation check so missed replies after restarts are caught.

Steps:
1. Execute:
   `python3 /home/kernk/.openclaw/workspace/automation/startup_reply_reconcile.py`
2. Parse JSON result.
3. If `unresolved` is `true`, send a proactive Telegram message to Ken:
   - channel: `telegram`
   - target: `telegram:7729039890`
   - message:
     `I restarted while handling your last message and may have dropped my reply. Please resend it, or say "recover last" and I’ll reconstruct it from transcript context.`
   - Include one short quote of `last_user_excerpt` when available.
4. If `unresolved` is `false`, do nothing.
5. If you send a proactive message, finish with `NO_REPLY`.
