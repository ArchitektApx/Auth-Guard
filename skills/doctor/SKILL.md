---
name: doctor
description: Verify the auth-guard credential protection is fully working. Checks betterleaks and jq availability, hook presence and registration, sandbox and deny-rule settings, and runs redaction self-tests with a synthetic token. Use for "auth-guard doctor", "check auth-guard", "is my secret protection working".
---

# auth-guard doctor

Run exactly one command:

```
${CLAUDE_PLUGIN_ROOT}/bin/auth-guard-doctor.sh
```

It prints one `PASS`/`WARN`/`FAIL` line per check and exits 0 (healthy, warnings allowed) or 1 (at least one FAIL).

Report to the user:

- One-line verdict first: healthy, degraded (warnings), or broken (failures).
- Then only the WARN and FAIL lines with a short plain-language explanation of the consequence of each, and the concrete fix:
  - `betterleaks` missing: `brew install betterleaks` (macOS), or see the Dependencies section of the plugin README for Linux - until then tool output is NOT scanned.
  - hook registration dormant: the plugin is installed but not enabled, or hooks were removed from settings; suggest `/plugin` to enable, or a session restart if it was just enabled.
  - sandbox / deny-rule warnings: suggest running `/auth-guard:global-settings`.
- Do not list every PASS line; summarize passes in one sentence.

Never work around a FAIL by editing files yourself; this skill only diagnoses.
