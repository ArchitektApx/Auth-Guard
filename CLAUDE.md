# Maintaining this repository

This repository is a Claude Code plugin and its single-plugin marketplace.
Everything committed here is cloned onto every machine that installs it, and
`hooks/hooks.json` registers commands that run on those machines on every
`Bash`, `Read`, `Grep` and `WebFetch` tool call. Treat every change under
`hooks/`, `bin/`, `skills/` and `config/` as code shipped to users with no
staged rollout.

## Working in this repository

`master` is protected by a ruleset with no bypass, so nothing lands by pushing
to it. Branch, push the branch, open a PR, merge it yourself. To merge, a PR
needs the `verify` check green and squash as its merge method; it needs no
approvals.

Every commit must be signed. Local commits inherit `commit.gpgsign`.

Repository policy requires every action to be pinned to a full commit SHA with
the version as a trailing comment. A tag reference does not fail review, it
fails the run.

Dependabot owns action versions and bumps them in one grouped PR monthly.
Bumping a SHA by hand only creates a conflict with the next one.

Any change to shipped content (`hooks/`, `bin/`, `skills/`, `config/`) bumps
`version` in both `.claude-plugin/plugin.json` and
`.claude-plugin/marketplace.json` in the same PR. Installed copies refresh by
version compare, so an unbumped fix never reaches existing users.

## What `verify` enforces

`verify.yml` is the only CI. It fails a PR when:

- any of `plugin.json`, `marketplace.json`, `hooks/hooks.json`,
  `config/deny-rules.json` does not parse
- a marketplace plugin `source` is anything but a local `./` path
- a `SKILL.md` lacks `name` or `description` frontmatter, or two skills share a
  `name`
- a hook command does not start with `${CLAUDE_PLUGIN_ROOT}/`, contains `..`,
  or points at a file that is missing or not executable
- a symlink is tracked, or an executable is tracked outside `hooks/*.sh` and
  `bin/*.sh`
- an `.mcp.json` declares an unpinned `npx` package
- `bash -n` or `shellcheck -S warning` fails on `hooks/*.sh` or `bin/*.sh`

Keep `hooks/*.sh` and `bin/*.sh` at mode `100755`; a hook that loses its
executable bit is silently never run by Claude Code, and CI catches it.

## Invariants

Preserve these through any refactor:

- **Hook commands resolve inside the plugin.** Every command in
  `hooks/hooks.json` is `${CLAUDE_PLUGIN_ROOT}/...`. Absolute paths break on
  every other machine; relative paths without the variable resolve against the
  user's cwd.
- **No network from any script.** `output-guard.sh` scans tool output that can
  contain live secrets; it runs `betterleaks` without `--validation` because
  validation posts findings to provider APIs. The audit script prints paths,
  rule ids and counts only, never matched text.
- **Fail closed on scanner error, fail open only when betterleaks is absent.**
  `output-guard.sh` withholds the whole output on any betterleaks failure or on
  a rescan hit after redaction. The missing-binary case is the single
  deliberate fail-open, and it prints a visible warning.
- **`verify.yml` triggers on `pull_request`.** It runs PR-head code, so
  `pull_request_target` would hand fork PRs write access and secrets. It keeps
  `permissions: contents: read`, `persist-credentials: false` and
  `timeout-minutes` on the job.
- **Marketplace `source` stays `./`.** A remote source delegates trust to
  another repository on every install.
- **Only shell entrypoints are executable.** Anything else with the executable
  bit, and any symlink, is refused by CI because it is redistributed verbatim.

If a workflow that opens PRs is ever added: pass the PR body via `body-path`,
never through `GITHUB_OUTPUT`, and set `sign-commits: true` on
`peter-evans/create-pull-request` under the default `GITHUB_TOKEN`. A PAT keeps
the PR working and drops the signature without warning; the ruleset then
rejects the merge.

## Gotchas

- `bin/auth-guard-doctor.sh` holds a synthetic `ghp_`-shaped token literal for
  its self-test. When this plugin is active in the session doing the editing,
  its own `output-guard` rewrites that line to `[REDACTED:github-pat]` in tool
  output. The file on disk is intact; verify with a count
  (`grep -cE 'ghp_[A-Za-z0-9]{36}' bin/auth-guard-doctor.sh` prints `1`)
  rather than by reading the line, and keep the literal in place.
- Skills install flat by frontmatter `name` under `npx skills`, so a second
  skill with the same `name` clobbers the first. Names here are `doctor`,
  `audit-transcripts`, `global-settings`; keep new ones unique and specific.
- `plugin.json` declares no `hooks` field; Claude Code auto-discovers
  `hooks/hooks.json`. Moving or renaming that file disables both hooks.
- `bin/auth-guard-apply-settings.sh` is the one script that writes outside the
  plugin directory (`~/.claude/settings.json`, with a timestamped backup, and
  it sets `sandbox.enabled` to `true`). Its skill gates it behind a dry run and
  explicit user confirmation; keep that flow.
- Every script prepends `/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin`
  to `PATH` because GUI-launched Claude Code inherits launchd's minimal PATH and
  `jq` and `betterleaks` vanish. Keep the prepend when adding scripts.
- The `Read(**/...)` deny rules in `config/deny-rules.json` bind only inside
  the project directory. Home-directory credential files are covered by the
  `sandbox.credentials.files` entries in the same file, which is why both lists
  exist.

## Agent skills

### Issue tracker

Issues live as local markdown files under `.scratch/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage labels are used as-is. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` plus `docs/adr/` at the repo root. See `docs/agents/domain.md`.
