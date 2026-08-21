# Auth Guard

Credential leak protection for [Claude Code](https://code.claude.com). Auth Guard keeps secrets out of your session transcripts with layered prevention, and finds the ones that got there anyway.


## What you get

**Two hooks**

- [`secret-guard.sh`](hooks/secret-guard.sh) (PreToolUse, Bash): blocks or questions commands whose purpose is to print credentials (`git credential fill`, `gh auth token`, `security find-generic-password`, vault/password-manager reads, credential file access), with whitespace/quote normalization so trivial respellings do not slip past. Low-confidence matches `ask` instead of deny, so you stay in the loop.

  ![A Claude Code session: the guard denies `gh auth token` outright, then asks for confirmation before `eval $(ssh-agent -s)`](docs/assets/deny-ask.gif)

- [`output-guard.sh`](hooks/output-guard.sh) (PostToolUse, Bash/Read/Grep/WebFetch): scans every tool output with [betterleaks](https://github.com/betterleaks/betterleaks) and rewrites it before the model sees it, replacing each finding with `[REDACTED:<rule-id>]`. This is the layer that catches the unanticipated route: secrets inside API responses, config dumps, logs, or files that no denylist modeled. Fails closed (output withheld) on scanner errors; fails open with a visible warning only when betterleaks is not installed at all.

  ![A Claude Code session: a local CLI prints a GitHub token, and the tool output reaches the model as `token=[REDACTED:github-pat]`](docs/assets/redact.gif)

**Three skills**

| Skill | What it does |
| --- | --- |
| [`/auth-guard:doctor`](skills/doctor/SKILL.md) | Verifies every layer: dependencies, hook presence and registration, sandbox and deny-rule settings, plus live self-tests of both hooks with a synthetic token. |
| [`/auth-guard:global-settings`](skills/global-settings/SKILL.md) | Merges the bundled deny rules (`config/deny-rules.json`) into your `~/.claude/settings.json`. Additive and idempotent: dry-run first, timestamped backup, never removes or reorders your entries. |
| [`/auth-guard:audit-transcripts`](skills/audit-transcripts/SKILL.md) | Scans all stored session transcripts with betterleaks (regex fallback without it) and reports file paths and rule ids, never the matched text. |

**A deny-rule baseline** (`config/deny-rules.json`): `Read()`/`Bash()` permission denies plus `sandbox.credentials.files` entries for common credential stores (SSH, AWS, Azure, gcloud-style caches, gh, docker, kube, gnupg, browser profiles, shell history, and more). Some entries are opinionated; denying `~/.azure` breaks `az` inside sessions, for example. Delete what does not fit after applying.

## Install

```
/plugin marketplace add ArchitektApx/Auth-Guard
/plugin install auth-guard@auth-guard
```

### Dependencies

The hooks need `jq` and [betterleaks](https://github.com/betterleaks/betterleaks) on the PATH. Without betterleaks the output scan is skipped with a warning and the audit falls back to regex patterns.

macOS (Homebrew):

```sh
brew install jq betterleaks
```

Debian / Ubuntu:

```sh
sudo apt install jq golang
go install github.com/betterleaks/betterleaks@latest
```

Fedora:

```sh
sudo dnf install jq betterleaks
```

Arch:

```sh
sudo pacman -S jq go
go install github.com/betterleaks/betterleaks@latest
```

The hooks run with the environment of the Claude Code process, which (especially when launched from a GUI) may not carry your shell's PATH. They therefore search the standard install locations themselves: `/opt/homebrew/bin`, `/usr/local/bin`, `~/go/bin`, and `~/.local/bin`. If betterleaks lives somewhere else, symlink it into one of those. A `docker pull ghcr.io/betterleaks/betterleaks` install does not work for the hooks, since they expect a native `betterleaks` binary, not a container wrapper.

After installing, run `/auth-guard:doctor` in a fresh session, then `/auth-guard:global-settings` to apply the settings-side layers.

## Customize: your own checks

The built-in PreToolUse checks are curated here and cannot know your secret stores, your internal CLIs or your company-specific credential paths. Add your own in a JSON file:

```sh
mkdir -p ~/.config/auth-guard
# start from the shipped template: config/custom-checks.example.json
$EDITOR ~/.config/auth-guard/custom-checks.json
```

A deny always beats an ask, whichever side defined it, so a custom check can harden shipped coverage but never weaken it. Any error in the file fails closed and `/auth-guard:doctor` tells you which check is wrong.

The schema, the resolution order, the `AUTH_GUARD_CUSTOM_CHECKS` override and the failure semantics are documented in **[docs/custom-checks.md](docs/custom-checks.md)**.

## Why so many layers

Claude Code has three separate enforcement domains, and a rule in one does nothing in the others:

1. **Harness file tools** (Read, Grep, Glob, and user `@`-mentions) are gated only by `permissions.deny` `Read()` rules. The Bash sandbox never sees them.
2. **Shell commands** run inside the sandbox. `sandbox.credentials.files` blocks reads at the filesystem layer and survives any command spelling (`cat`, `dd`, a Python one-liner). Plain `Bash()` deny rules are literal prefix matches and are trivially evaded, which is what the PreToolUse hook's normalization is for. Note that the sandbox translation of `Read(**/...)` globs is project-scoped: home-directory credential paths need explicit `credentials.files` entries, and they need the `Read(~/...)` twin to also bind the harness tools.
3. **Service-backed secrets** never touch a file from the caller's view. `gh auth token` asks the OS keychain via `securityd`, so no file rule can block it. Only command-level rules (the PreToolUse hook) cover this route.

And below all three: some secrets arrive through legitimate channels nobody predicted. That is what the PostToolUse output scan is for, and it is the only layer that is content-based rather than path- or command-based.

## Auditing and triage

`/auth-guard:audit-transcripts` (or `bin/auth-guard-audit-transcripts.sh` directly) reports per file which betterleaks rules matched and how often. Exit codes: `0` clean, `1` engine or tier-1 hits (treat as live until disproven), `2` tier-2 shape hits only (noisy, needs triage). Always exclude the live session with `--exclude <session-id>`: its transcript is being appended to during the scan and contains your current conversation.

Ground rules when a hit shows up:

- **Never print the match.** An audit that echoes what it found turns one disclosure into two, usually straight into a new transcript. The script only reports paths, rule ids and counts, and runs betterleaks with `--redact`. Follow the same rule when triaging by hand.
- **Not every hit is a secret.** Token-prefix patterns can appear by coincidence inside base64 or binary blobs. Check whether the match stands alone or sits mid-stream in a longer run of token-safe characters; only standalone matches are real candidates.
- **For JWTs, read the claims without printing the token**: base64-decode the middle segment and check `sub`, `iat`, and `exp`. A missing `exp` is the bad case, because the token never ages out.
- **Revoke first, scrub second.** The scrub is hygiene; the revoke is the fix. A transcript may already have left the machine as model context, so rotation beats deletion. GitHub specifics: `gh auth logout` revokes nothing server-side, and re-authorizing the same OAuth app can hand back the *same* token. Revoke the app authorization at <https://github.com/settings/applications> first.
- **Scrub carefully.** Transcripts are JSONL; after a `sed`, verify every line still parses (`jq -e .` per line). Never scrub the transcript of a session that is still running.

## Limitations

- Prevention is not retroactive: install day one, then audit what predates it.
- The audit reports that a secret is *present*, never whether it is still *valid*. Only the issuing service knows.
- Sandbox file denies apply only while the sandbox is active; a command approved to run unsandboxed bypasses them (the hooks still apply).
- The output scan is only as good as betterleaks' rules plus entropy checks. A secret in a format nothing recognizes passes through.
- Shell history, editor state, and crash dumps outside `~/.claude/projects` are not audited. Check them separately.

## License

MIT
