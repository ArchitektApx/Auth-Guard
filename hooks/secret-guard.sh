#!/usr/bin/env bash
#
# PreToolUse guard for the Bash tool.
#
# Permission deny rules (permissions.deny in settings.json) match command
# strings literally, so they are trivially evaded by extra whitespace, quoting,
# pipes or command substitution. This hook normalises the command first and then
# matches a denylist of things that would print credentials into the transcript.
#
# This is a guardrail, not a sandbox. It stops a cooperative agent from leaking
# a secret by accident. It does not stop a determined bypass, and it should not
# be described as if it does. For enforcement that survives arbitrary command
# spelling, use sandbox.credentials.files with mode "deny" in settings.json,
# which blocks the read at the filesystem layer.
#
# Reads the PreToolUse payload on stdin, writes a permissionDecision on stdout.
# Anything that does not match falls through with exit 0 and no output, which
# leaves the normal permission flow untouched.

set -uo pipefail

# Hooks inherit the Claude Code process environment, which on GUI launches is
# launchd's minimal PATH; jq then vanishes and the guard silently passes
# everything. Cover the standard install locations.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

input=$(cat)
cmd=$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -z "$cmd" ] && exit 0

# Fold line continuations, newlines and runs of whitespace into single spaces so
# `security   dump-keychain` and a multi-line command match the same patterns.
full=$(printf '%s' "$cmd" | tr '\n\t' '  ' | sed 's/\\ / /g' | tr -s ' ')

# Quoted segments removed. A real invocation's command name is essentially never
# fully quoted, so matching command verbs against this kills the large class of
# false positives where the pattern only appears inside a string argument --
# test fixtures, grep patterns, commit messages, documentation heredocs.
# Heredoc bodies are not stripped; they remain a known gap.
bare=$(printf '%s' "$full" | sed "s/'[^']*'//g; s/\"[^\"]*\"//g")

decide() { # decide <deny|ask> <reason>
  jq -n --arg d "$1" --arg r "$2" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: $d,
      permissionDecisionReason: $r
    },
    systemMessage: ("secret-guard: " + $d)
  }'
  exit 0
}

# Match against the quote-stripped command: high confidence that the thing is
# actually being run, so these are hard denies.
verb() { printf '%s' "$bare" | grep -qEi "$1"; }

# Match against the whole command, quotes included: paths and variables are
# routinely quoted, so coverage matters more than precision here.
any() { printf '%s' "$full" | grep -qEi "$1"; }

# --- tier A: commands that print a secret to stdout (deny) ------------------

verb '(^|[^a-z0-9_-])git[ -]+credential[a-z-]*[ ]+(fill|approve|get)' &&
  decide deny "'git credential' prints the stored credential in cleartext. Use 'gh auth status' (masked) to check auth instead."

verb '(^|[^a-z0-9_-])security +(find-generic-password|find-internet-password|find-key|find-certificate|dump-keychain|export)' &&
  decide deny "This 'security' subcommand reads keychain items and can print secrets. Ask the user to run it themselves if the value is genuinely needed."

verb '(^|[^a-z0-9_-])gh +auth +token' &&
  decide deny "'gh auth token' prints the raw GitHub token. Use 'gh auth status', which masks it."

verb '(^|[^a-z0-9_-])gh +auth +status[^|;&]*( --show-token| -[a-z]*t)' &&
  decide deny "--show-token (and its -t alias) makes 'gh auth status' print the raw token. Run it without that flag."

verb '(^|[^a-z0-9_-])aws +configure +get .*(secret|session_token)' &&
  decide deny "Prints AWS secret credentials."

verb '(^|[^a-z0-9_-])kubectl +get +secret.*-o *(yaml|json)' &&
  decide deny "Dumps Kubernetes secret values. Use 'kubectl get secret' without -o yaml/json to list names only."

verb '(^|[^a-z0-9_-])(op +item +get|op +read|pass +show|bw +get|vault +kv +get)' &&
  decide deny "Reads a secret out of a password manager / vault."

# --- tier B: credential-shaped values (deny, quotes included) ---------------
# `echo "$GITHUB_TOKEN"` is quoted, so this one has to see the full string.

any '(^|[^a-z0-9_-])(echo|printf|print) [^|;&]*\$\{?[a-z_]*(token|secret|password|passwd|apikey|api_key|credential)' &&
  decide deny "Echoes a credential-shaped environment variable."

# --- tier C: lower confidence (ask, so the user stays in the loop) ----------
# Blunt on purpose: `chmod 600 ~/.netrc` matches here and is harmless. Asking
# beats hard-walling for matches this coarse.

any '(\.git-credentials|(^|/)\.?netrc|\.npmrc|\.pypirc|\.aws/credentials|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config|\.gnupg/|\.config/op/|\.password-store/)' &&
  decide ask "That path is a credential store. Confirm before its contents go into the transcript."

# Private SSH keys, but not their .pub counterparts.
if any '\.ssh/id_[a-z0-9_]+' && ! any '\.ssh/id_[a-z0-9_]+\.pub'; then
  decide ask "That path is an SSH private key."
fi

# .env files, but allow the committed templates.
if any '(^|[^a-z0-9_.-])\.env([^a-z0-9_.-]|$|\.[a-z]+)' &&
   ! any '\.env\.(example|sample|template|dist)'; then
  decide ask ".env files hold secrets. A .env.example is usually the safe alternative."
fi

# Constructs that defeat static inspection. No attempt is made to decode them --
# unwrapping arbitrary shell is a losing game. Surface them and let the user judge.
any '(^|[^a-z0-9_-])(eval |base64 +-{1,2}d[^|;&]*\| *(ba)?sh|curl [^|;&]*\| *(ba)?sh)' &&
  decide ask "This command builds or pipes shell code at runtime, so its real effect cannot be inspected statically."

exit 0
