---
name: global-settings
description: Add auth-guard's credential deny rules to the user's global Claude Code settings.json - Read/Bash permission denies plus sandbox.credentials.files entries. Additive and idempotent, with backup. Use for "auth-guard global-settings", "apply the deny rules", "protect my credential files".
---

# auth-guard global-settings

Two-step flow, never skip step 1:

1. **Dry run** and show the user what would change:

```
${CLAUDE_PLUGIN_ROOT}/bin/auth-guard-apply-settings.sh --dry-run
```

   Exit 0 means everything is already present: tell the user, stop here.
   Exit 2 means there are pending additions: show them the printed list, briefly grouped (Read rules / Bash rules / sandbox credential files), and ask for confirmation.

2. **Apply** only after the user confirms:

```
${CLAUDE_PLUGIN_ROOT}/bin/auth-guard-apply-settings.sh
```

   Report the summary line and the backup path it printed.

Notes for your report:

- The merge is additive: existing settings entries are never removed, reordered, or overwritten. A timestamped backup is written before any change.
- `sandbox.enabled` is set to `true` if it was not already; mention this when it applies, since it changes how Bash commands run.
- Some defaults are opinionated and can break tooling inside sessions: denying `~/.azure` breaks `az`, `~/.cloudflared` breaks cloudflared tunnel commands. Mention this if the dry run shows those entries; the user can delete individual rules from settings.json afterwards.
- Permission and sandbox changes generally apply to new sessions; suggest a restart to be safe.

Never edit settings.json directly yourself; all changes go through the script.
