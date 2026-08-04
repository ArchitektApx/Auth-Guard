---
name: audit-transcripts
description: Scan all Claude Code session transcripts for leaked secrets using betterleaks (grep fallback). Reports rule ids and file paths, never the secrets themselves. Use for "audit transcripts", "did anything leak", "scan my sessions for secrets".
---

# auth-guard audit-transcripts

Run:

```
${CLAUDE_PLUGIN_ROOT}/bin/auth-guard-audit-transcripts.sh --exclude <current-session-id>
```

Substitute `<current-session-id>` with the current session's id so the live transcript (which is being appended to while the scan runs, and contains this very conversation) is skipped. If the session id is not known, use the newest `.jsonl` under `~/.claude/projects` as the exclusion. For other options (scan root, repeatable excludes, forcing the regex fallback) see `--help`.

Exit codes: 0 clean, 1 engine hits (treat as live secrets until disproven), 2 tier-2 shape hits only (expect false positives).

Report to the user:

- Verdict first: clean, needs triage, or likely leak.
- On hits: the affected transcript files (project dir + session id) and the rule ids/counts, exactly as printed.
- **Never** open a flagged transcript and quote the matching content, and never re-print anything secret-shaped: quoting a leaked secret into this session creates a second disclosure, which defeats the audit. The script itself only prints paths, rule ids and counts for the same reason.
- On tier-1/engine hits, walk the user through next steps: identify the credential from the rule id, rotate/revoke it at the provider if it could be real, then delete or scrub the affected transcript file. Point them to the "Auditing and triage" section of the plugin README for the triage procedure (checking whether a match is a real token or an accidental substring of base64/binary data).
- Remind them that a hit in an old transcript may already have left the machine (transcripts are sent as model context), so rotation beats deletion.
