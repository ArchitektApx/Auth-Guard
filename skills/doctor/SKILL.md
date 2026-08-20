---
name: doctor
description: Verify the auth-guard credential protection is fully working. Checks betterleaks and jq availability, hook presence and registration, sandbox and deny-rule settings, which custom-checks file resolves and whether it is valid, and runs redaction and custom-check self-tests with synthetic inputs. Use for "auth-guard doctor", "check auth-guard", "is my secret protection working", "are my custom checks valid".
---

# auth-guard doctor

Run exactly one command:

```
${CLAUDE_PLUGIN_ROOT}/bin/auth-guard-doctor.sh
```

It prints one `PASS`/`WARN`/`FAIL` line per check and exits 0 (healthy, warnings allowed) or 1 (at least one FAIL).

Alongside the dependency, hook and settings checks it covers the user's custom checks: which custom-checks file resolves (or that none does), whether a lower-precedence candidate file is being shadowed by it, whether that file is valid (the guard itself validates and doctor relays its reason), and an end-to-end self-test that runs a synthetic custom-checks file through the guard.

Report to the user:

- One-line verdict first: healthy, degraded (warnings), or broken (failures).
- Then only the WARN and FAIL lines with a short plain-language explanation of the consequence of each, and the concrete fix:
  - `betterleaks` missing: `brew install betterleaks` (macOS), or see the Dependencies section of the plugin README for Linux - until then tool output is NOT scanned.
  - hook registration dormant: the plugin is installed but not enabled, or hooks were removed from settings; suggest `/plugin` to enable, or a session restart if it was just enabled.
  - sandbox / deny-rule warnings: suggest running `/auth-guard:global-settings`.
  - custom-checks file invalid: the whole file is ignored and the guard asks on everything the built-in denies do not already block; report the check name or key the FAIL line names and point the user at `docs/custom-checks.md` for that field's rules.
  - custom-checks shadowing: only the winning path is read; the others are dead until removed or merged into it.
- Do not list every PASS line; summarize passes in one sentence.

Never work around a FAIL by editing files yourself; this skill only diagnoses.
