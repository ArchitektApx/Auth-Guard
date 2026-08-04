#!/usr/bin/env bash
#
# PostToolUse guard: scan tool output with betterleaks and rewrite it before
# the model consumes it.
#
# The PreToolUse hook (secret-guard.sh) tries to predict which commands leak
# credentials; that is inherently a denylist race. This hook instead inspects
# the bytes that actually came back, whatever path they took: files, API
# responses, logs, command output. On a hit it replaces each secret with a
# [REDACTED:<rule-id>] marker via hookSpecificOutput.updatedToolOutput and
# leaves everything else untouched.
#
# Safety properties this script maintains:
#   - Raw findings never reach the hook's stdout/stderr; secrets exist only in
#     shell variables and the kernel pipe to betterleaks.
#   - --validation is never used: it would send findings to live provider APIs.
#   - Fail closed: on scanner errors, on unparseable reports, and whenever a
#     post-redaction rescan still finds a leak, the whole output is withheld
#     rather than passed through unscanned.
#   - Fail open only when betterleaks is not installed at all, with a visible
#     warning, so a missing optional dependency does not brick every tool call.
#
# Scanning happens on the decoded string values of tool_response (jq '..|strings'),
# not on its JSON serialization. Serialized JSON escapes newlines as \n, which
# would break both detection of multi-line secrets (private key blocks) and the
# literal replacement step; decoded space keeps scan and replace consistent.

set -uo pipefail
# Hooks inherit the Claude Code process environment, which on GUI launches is
# launchd's minimal PATH. Cover the standard install locations: Homebrew
# (Apple Silicon and Intel/Linux), go install, and pip/manual user installs.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

MARKER_PREFIX="REDACTED"
BL_ARGS=(stdin --no-banner --log-level fatal --timeout 20)

withhold() { # withhold <reason>  -- fail closed, drop the entire tool output
  jq -n --arg r "$1" '{
    hookSpecificOutput: {
      hookEventName: "PostToolUse",
      updatedToolOutput: ("[output-guard] tool output withheld: " + $r)
    },
    systemMessage: ("output-guard: output withheld (" + $r + ")")
  }'
  exit 0
}

input=$(cat)

resp=$(jq -c '.tool_response // empty' <<<"$input" 2>/dev/null)
[ -z "$resp" ] || [ "$resp" = 'null' ] && exit 0

if ! command -v betterleaks >/dev/null 2>&1; then
  jq -n '{systemMessage: "output-guard: betterleaks not found on PATH, tool output was NOT scanned"}'
  exit 0
fi

# Decoded projection of every string in the response; this is what gets scanned.
text=$(jq -r '.. | strings' <<<"$resp" 2>/dev/null)
[ -z "$text" ] && exit 0

report=$(printf '%s' "$text" | betterleaks "${BL_ARGS[@]}" --report-path - --report-format json 2>/dev/null)
ec=$?

[ "$ec" -eq 0 ] && exit 0
[ "$ec" -ne 1 ] && withhold "betterleaks failed with exit code $ec"

# Exit 1: leaks found. Pull unique (Secret, RuleID) pairs; base64 keeps
# multi-line secrets (private keys) intact through the read loop.
pairs=$(jq -r '[.[] | {s: .Secret, r: (.RuleID // "secret")}] | unique_by(.s)
               | .[] | (.s | @base64) + " " + .r' <<<"$report" 2>/dev/null)
[ -z "$pairs" ] && withhold "leaks detected but the report could not be parsed"

n=0
red="$resp"
while IFS=' ' read -r s64 rule; do
  [ -z "$s64" ] && continue
  secret=$(printf '%s' "$s64" | base64 -d) || withhold "failed to decode a finding"
  # Literal replacement inside decoded string values only; split/join does no
  # regex interpretation, so metacharacters in the secret are inert.
  red=$(jq -c --arg s "$secret" --arg m "[${MARKER_PREFIX}:${rule}]" \
        'walk(if type == "string" then (split($s) | join($m)) else . end)' <<<"$red" 2>/dev/null)
  [ -z "$red" ] && withhold "redaction produced no output"
  n=$((n + 1))
done <<<"$pairs"

# Belt and suspenders: rescan the redacted result. Anything still detectable
# (overlapping matches, replacement misses) means we withhold instead of leak.
jq -r '.. | strings' <<<"$red" 2>/dev/null | betterleaks "${BL_ARGS[@]}" >/dev/null 2>&1
[ $? -eq 1 ] && withhold "rescan still detects a secret after redaction"

jq -n --argjson out "$red" --arg msg "output-guard: redacted $n secret(s)" '{
  hookSpecificOutput: {
    hookEventName: "PostToolUse",
    updatedToolOutput: $out
  },
  systemMessage: $msg
}'
exit 0
