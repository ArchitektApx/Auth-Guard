#!/usr/bin/env bash
#
# Scan Claude Code transcripts for credential-shaped strings.
#
# The hooks are preventive; this script is the detective counterpart, for
# secrets that landed before the hooks were installed or via a path they do
# not model (see "Auditing and triage" in the README).
#
# Detection engines, best available wins:
#   betterleaks (default when installed): full ruleset, entropy checks and
#     recursive decoding. Each transcript is scanned as its *decoded* string
#     values (jq '.. | strings'), not as raw JSONL: inside JSONL a newline is
#     the two characters \n, which breaks multi-line rules like private key
#     blocks. Findings are reported as rule id + count per file.
#   grep fallback (--grep-only or betterleaks missing): the original regex
#     tiers, scanning the raw JSONL.
# Tier-2 grep shapes (git-credential output, netrc lines, passhash) run in
# both modes: betterleaks has no rules for those transcript-specific formats.
#
# Match counts, rule ids and file paths are reported. Matched text is never
# printed (betterleaks additionally runs with --redact), so the audit itself
# cannot become a second disclosure.
#
# Usage:
#   auth-guard-audit-transcripts.sh [ROOT] [--exclude SUBSTRING]... [--grep-only]
#
#   ROOT        directory to scan (default: ~/.claude/projects)
#   --exclude   skip paths containing SUBSTRING; repeatable. Use it to skip
#               the live session, whose transcript is still being appended to.
#   --grep-only force the regex fallback even if betterleaks is installed
#
# Exit status:
#   0  nothing found
#   1  engine hits (betterleaks findings or tier-1 regex -- treat as live
#      until disproven)
#   2  tier-2 hits only (shapes that need triage; expect false positives)

set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

ROOT="$HOME/.claude/projects"
EXCLUDES=()
GREP_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --exclude)   EXCLUDES+=("$2"); shift 2 ;;
    --grep-only) GREP_ONLY=1; shift ;;
    -h|--help)   sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           ROOT="$1"; shift ;;
  esac
done

[ -d "$ROOT" ] || { echo "no such directory: $ROOT" >&2; exit 64; }

tier1_hits=0
tier2_hits=0

excluded() { # excluded <path> -> 0 if path matches an exclude substring
  local e
  for e in ${EXCLUDES+"${EXCLUDES[@]}"}; do
    case "$1" in *"$e"*) return 0 ;; esac
  done
  return 1
}

# --- engine: betterleaks ----------------------------------------------------

scan_betterleaks() {
  local f report rules
  echo "=== betterleaks scan (decoded transcript strings) ==="
  while IFS= read -r f; do
    excluded "$f" && continue
    report=$(jq -r '.. | strings' "$f" 2>/dev/null \
             | betterleaks stdin --no-banner --log-level fatal --redact \
                 --report-path - --report-format json 2>/dev/null)
    if [ $? -eq 1 ] && [ -n "$report" ]; then
      rules=$(jq -r 'group_by(.RuleID) | map("\(.[0].RuleID) x\(length)") | join(", ")' \
              <<<"$report" 2>/dev/null)
      printf '  HITS  %s\n        %s\n' "${f#"$ROOT"/}" "${rules:-unparseable report}"
      tier1_hits=1
    fi
  done < <(find "$ROOT" -name '*.jsonl' -type f)
  [ "$tier1_hits" = 0 ] && echo "  clean"
}

# --- engine: grep tiers (fallback + transcript-specific shapes) -------------

scan() { # scan <tier> <label> <regex>
  local tier="$1" label="$2" re="$3" out f
  out=$(grep -raEl "$re" "$ROOT" 2>/dev/null)
  local shown=0
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    excluded "$f" && continue
    [ "$shown" = 0 ] && printf '  %-28s HITS\n' "$label"
    shown=1
    printf '      %s  (%s)\n' "${f#"$ROOT"/}" "$(grep -acE "$re" "$f")"
    if [ "$tier" = 1 ]; then tier1_hits=1; else tier2_hits=1; fi
  done <<< "$out"
  [ "$shown" = 0 ] && printf '  %-28s clean\n' "$label"
}

grep_tier1() {
  echo "=== tier 1: specific token formats (near-zero false positives) ==="
  scan 1 "github classic/oauth"  'gh[pousr]_[A-Za-z0-9]{36}'
  scan 1 "github fine-grained"   'github_pat_[A-Za-z0-9_]{60,}'
  scan 1 "aws access key id"     'AKIA[0-9A-Z]{16}'
  scan 1 "aws secret key"        'aws_secret_access_key[[:space:]]*=[[:space:]]*[A-Za-z0-9/+]{40}'
  scan 1 "openai"                'sk-(proj-)?[A-Za-z0-9_-]{40,}'
  scan 1 "anthropic"             'sk-ant-[A-Za-z0-9_-]{40,}'
  scan 1 "slack"                 'xox[baprs]-[A-Za-z0-9-]{20,}'
  scan 1 "google api key"        '(^|[^A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}([^A-Za-z0-9_-]|$)'
  scan 1 "stripe live"           '(sk|rk)_live_[A-Za-z0-9]{20,}'
  scan 1 "npm"                   'npm_[A-Za-z0-9]{36}'
  scan 1 "pypi"                  'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}'
  scan 1 "private key block"     '-----BEGIN [A-Z ]*PRIVATE KEY-----'
  scan 1 "jwt"                   'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
  scan 1 "bearer header"         '[Bb]earer [A-Za-z0-9._-]{40,}'
}

grep_tier2() {
  echo "=== tier 2: credential output shapes (needs triage) ==="
  # The \\n alternative: inside JSONL this text lives in a JSON string, so the
  # newline before it is the two characters \ and n, not a real line break.
  scan 2 "git credential output" '(^|\\n|")(password|username)=[^"[:space:]\\]+'
  scan 2 "netrc password line"   'machine [^[:space:]]+ login [^[:space:]]+ password [^[:space:]]+'
  scan 2 "prtg passhash"         'passhash=[0-9]{6,}'
}

# --- run --------------------------------------------------------------------

echo "scanning: $ROOT"
printf 'files: %s\n\n' "$(find "$ROOT" -name '*.jsonl' -type f | wc -l | tr -d ' ')"

if [ "$GREP_ONLY" = 0 ] && command -v betterleaks >/dev/null 2>&1; then
  scan_betterleaks
else
  [ "$GREP_ONLY" = 0 ] && echo "note: betterleaks not found, using grep fallback" && echo
  grep_tier1
fi
echo
grep_tier2

echo
if [ "$tier1_hits" = 1 ]; then
  echo "hits found. Triage before assuming the worst: check whether each match"
  echo "is standalone or an accidental substring inside base64 or binary data."
  echo "See 'Auditing and triage' in the README for the procedure."
  exit 1
elif [ "$tier2_hits" = 1 ]; then
  echo "tier 2 hits only. Expect false positives; triage individually."
  exit 2
fi
echo "clean."
exit 0
