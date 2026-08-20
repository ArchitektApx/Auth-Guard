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
#
# Every built-in check carries a short kebab-case id. Those ids are part of the
# guard's observable output (they appear in every systemMessage and in the
# override notice) and are stable by intent: rename a check's wording freely,
# but do not rename its id.

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

decide() { # decide <deny|ask> <id-or-name> <reason>
  jq -n --arg d "$1" --arg n "$2" --arg r "$3" '{
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: $d,
      permissionDecisionReason: $r
    },
    systemMessage: ("secret-guard: " + $d + " (" + $n + ")")
  }'
  exit 0
}

# Match against the quote-stripped command: high confidence that the thing is
# actually being run, so these are hard denies.
verb() { printf '%s' "$bare" | grep -qEi -e "$1"; }

# Match against the whole command, quotes included: paths and variables are
# routinely quoted, so coverage matters more than precision here.
any() { printf '%s' "$full" | grep -qEi -e "$1"; }

# The two built-in stages below record their first match in these, rather than
# deciding on the spot, so that custom-check stages can be interleaved between
# them and so that a shadowed built-in ask can still be reported.
hit_id=""
hit_reason=""

try() { # try <id> <verb|any> <regex> <reason>
  case "$2" in
    verb) verb "$3" || return 1 ;;
    any) any "$3" || return 1 ;;
    *) return 1 ;;
  esac
  hit_id="$1"
  hit_reason="$4"
  return 0
}

# --- built-in deny checks ---------------------------------------------------
# tier A: commands that print a secret to stdout.
# tier B: credential-shaped values, matched with quotes included.

builtin_deny() {
  hit_id=""
  hit_reason=""

  try git-credential verb \
    '(^|[^a-z0-9_-])git[ -]+credential[a-z-]*[ ]+(fill|approve|get)' \
    "'git credential' prints the stored credential in cleartext. Use 'gh auth status' (masked) to check auth instead." && return 0

  try macos-keychain verb \
    '(^|[^a-z0-9_-])security +(find-generic-password|find-internet-password|find-key|find-certificate|dump-keychain|export)' \
    "This 'security' subcommand reads keychain items and can print secrets. Ask the user to run it themselves if the value is genuinely needed." && return 0

  try gh-auth-token verb \
    '(^|[^a-z0-9_-])gh +auth +token' \
    "'gh auth token' prints the raw GitHub token. Use 'gh auth status', which masks it." && return 0

  try gh-show-token verb \
    '(^|[^a-z0-9_-])gh +auth +status[^|;&]*( --show-token| -[a-z]*t)' \
    "--show-token (and its -t alias) makes 'gh auth status' print the raw token. Run it without that flag." && return 0

  try aws-configure-get verb \
    '(^|[^a-z0-9_-])aws +configure +get .*(secret|session_token)' \
    "Prints AWS secret credentials." && return 0

  try kubectl-secret-dump verb \
    '(^|[^a-z0-9_-])kubectl +get +secret.*-o *(yaml|json)' \
    "Dumps Kubernetes secret values. Use 'kubectl get secret' without -o yaml/json to list names only." && return 0

  try vault-read verb \
    '(^|[^a-z0-9_-])(op +item +get|op +read|pass +show|bw +get|vault +kv +get)' \
    "Reads a secret out of a password manager / vault." && return 0

  # `echo "$GITHUB_TOKEN"` is quoted, so this one has to see the full string.
  try echo-credential-var any \
    '(^|[^a-z0-9_-])(echo|printf|print) [^|;&]*\$\{?[a-z_]*(token|secret|password|passwd|apikey|api_key|credential)' \
    "Echoes a credential-shaped environment variable." && return 0

  return 1
}

# --- built-in ask checks ----------------------------------------------------
# tier C: lower confidence, so the user stays in the loop. Blunt on purpose:
# `chmod 600 ~/.netrc` matches here and is harmless. Asking beats hard-walling
# for matches this coarse.

builtin_ask() {
  hit_id=""
  hit_reason=""

  try credential-path any \
    '(\.git-credentials|(^|/)\.?netrc|\.npmrc|\.pypirc|\.aws/credentials|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config|\.gnupg/|\.config/op/|\.password-store/)' \
    "That path is a credential store. Confirm before its contents go into the transcript." && return 0

  # Private SSH keys, but not their .pub counterparts.
  if any '\.ssh/id_[a-z0-9_]+' && ! any '\.ssh/id_[a-z0-9_]+\.pub'; then
    hit_id="ssh-private-key"
    hit_reason="That path is an SSH private key."
    return 0
  fi

  # .env files, but allow the committed templates.
  if any '(^|[^a-z0-9_.-])\.env([^a-z0-9_.-]|$|\.[a-z]+)' &&
     ! any '\.env\.(example|sample|template|dist)'; then
    hit_id="dotenv-file"
    hit_reason=".env files hold secrets. A .env.example is usually the safe alternative."
    return 0
  fi

  # Constructs that defeat static inspection. No attempt is made to decode them
  # -- unwrapping arbitrary shell is a losing game. Surface them and let the
  # user judge.
  try dynamic-shell any \
    '(^|[^a-z0-9_-])(eval |base64 +-{1,2}d[^|;&]*\| *(ba)?sh|curl [^|;&]*\| *(ba)?sh)' \
    "This command builds or pipes shell code at runtime, so its real effect cannot be inspected statically." && return 0

  return 1
}

# --- evaluation -------------------------------------------------------------

builtin_deny && decide deny "$hit_id" "$hit_reason"
builtin_ask && decide ask "$hit_id" "$hit_reason"

exit 0
