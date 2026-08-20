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
#
# The user can add custom checks in a JSON file (see docs/custom-checks.md).
# They are evaluated alongside the built-ins, and any error in that file fails
# closed: the user never silently loses protection they wrote themselves.

set -uo pipefail

# Hooks inherit the Claude Code process environment, which on GUI launches is
# launchd's minimal PATH; jq then vanishes and the guard silently passes
# everything. Cover the standard install locations.
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

# The custom-checks file candidates, most preferred first, and the one place
# the resolution order is written down. An unset or empty XDG_CONFIG_HOME drops
# its candidate, per the XDG spec.
custom_candidates() {
  [ -n "${XDG_CONFIG_HOME:-}" ] &&
    printf '%s\n' "$XDG_CONFIG_HOME/auth-guard/custom-checks.json"
  printf '%s\n' "$HOME/.config/auth-guard/custom-checks.json"
  printf '%s\n' "$HOME/.auth-guard/custom-checks.json"
  return 0
}

# `--candidates` exists so the doctor can report and rank the same candidates
# without keeping a second copy of the list that would drift from this one.
# Claude Code passes no arguments, so the hook path is unaffected.
if [ "${1:-}" = "--candidates" ]; then
  custom_candidates
  exit 0
fi

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

# --- custom checks ----------------------------------------------------------
#
# Resolution, schema and failure semantics are documented in
# docs/custom-checks.md. In short: AUTH_GUARD_CUSTOM_CHECKS (when set and
# non-empty) names the file outright; any error in the file, including a
# missing override target, fails closed with `ask` on everything a built-in
# deny does not already stop.

cfg_file=""
cfg_error=""

custom_count=0
custom_names=()
custom_matches=()
custom_regexes=()
custom_decisions=()
custom_messages=()
custom_cases=()

# Structural validation lives in jq: it reports every schema violation it can
# see, naming the offending check (by name where the entry has a usable one,
# by index otherwise). On success it prints OK followed by one line per check,
# each field base64-encoded so a regex or message containing spaces or
# newlines survives the trip through the shell intact. An empty field is
# encoded as "-", which base64 never produces.
custom_jq='
def allowed: ["name","match","regex","decision","message","case_sensitive"];
def required: ["name","match","regex","decision"];

# The guard reports a fail-closed decision as if it came from a check of this
# name, and the doctor decides file validity by matching that systemMessage
# exactly. A user check by the same name would make the doctor call a valid
# file invalid, so the name belongs to the guard and is refused here.
def reserved: ["custom-checks-error"];
def flat: gsub("[\n\r\t]"; " ");
def b64: if . == "" then "-" else @base64 end;

def entry_label($i):    # "label" is a jq keyword, hence the prefix
  if (type == "object") and has("name")
     and ((.name | type) == "string") and (.name != "")
  then "check \"" + (.name | flat) + "\""
  else "checks[" + ($i | tostring) + "]"
  end;

def entry_errors($i):
  . as $c
  | if type != "object"
    then ["checks[" + ($i | tostring) + "]: entry is not a JSON object"]
    else
      ([ keys_unsorted[]
         | select((. as $k | allowed | index($k)) == null)
         | ($c | entry_label($i)) + ": unknown key \"" + flat + "\"" ])
      + ([ required[] as $k
           | select(($c | has($k)) | not)
           | ($c | entry_label($i)) + ": missing required key \"" + $k + "\"" ])
      + (if ($c | has("name"))
            and ((($c.name | type) != "string") or ($c.name == ""))
         then ["checks[" + ($i | tostring)
               + "]: \"name\" must be a non-empty string"] else [] end)
      + (if ($c | has("name")) and (($c.name | type) == "string")
            and ((reserved | index($c.name)) != null)
         then [($c | entry_label($i))
               + ": \"name\" is reserved by the guard, choose another"]
         else [] end)
      + (if ($c | has("match")) and ($c.match != "verb") and ($c.match != "any")
         then [($c | entry_label($i)) + ": \"match\" must be \"verb\" or \"any\""]
         else [] end)
      + (if ($c | has("regex"))
            and ((($c.regex | type) != "string") or ($c.regex == ""))
         then [($c | entry_label($i)) + ": \"regex\" must be a non-empty string"]
         else [] end)
      + (if ($c | has("decision"))
            and ($c.decision != "deny") and ($c.decision != "ask")
         then [($c | entry_label($i)) + ": \"decision\" must be \"deny\" or \"ask\""]
         else [] end)
      + (if ($c | has("message")) and (($c.message | type) != "string")
         then [($c | entry_label($i)) + ": \"message\" must be a string"] else [] end)
      + (if ($c | has("case_sensitive"))
            and (($c.case_sensitive | type) != "boolean")
         then [($c | entry_label($i)) + ": \"case_sensitive\" must be true or false"]
         else [] end)
    end;

def top_errors:
  if type != "object" then ["top-level value is not a JSON object"]
  elif (has("checks") | not)
  then ["top-level object is missing the \"checks\" key"]
  elif (keys_unsorted | length) != 1
  then ["top-level object has unknown key(s): "
        + ([keys_unsorted[] | select(. != "checks") | flat] | join(", "))]
  elif (.checks | type) != "array" then ["\"checks\" must be an array"]
  else [] end;

def dup_errors:
  [ .checks[]? | select(type == "object") | .name
    | select((type == "string") and (. != "")) ]
  | group_by(.) | map(select(length > 1) | .[0])
  | map("duplicate check name \"" + flat + "\"");

top_errors as $top
| if ($top | length) > 0 then "ERR " + ($top | join("; "))
  else
    (([ .checks | to_entries[] | .key as $i | .value | entry_errors($i) ]
      | add) // []) as $entry
    | dup_errors as $dups
    | ($entry + $dups) as $errs
    | if ($errs | length) > 0 then "ERR " + ($errs | join("; "))
      else
        ("OK",
         (.checks[]
          | [ (.name | b64), (.match | b64), (.regex | b64), (.decision | b64),
              ((.message // "") | b64),
              (((.case_sensitive // false) | tostring) | b64) ]
          | join(" ")))
      end
  end
'

# --decode rather than -d: BSD and GNU base64 both accept the long form, while
# older macOS base64 knows only -D.
#
# A field that fails to decode must not simply turn into an empty string. When
# decoding breaks, every field empties at once, and the field that decides the
# outcome is `decision`: an empty one equals neither "deny" nor "ask", so
# custom_pick matches nothing in either stage and the user's checks stop firing
# without a word. Note that an empty `regex` does the opposite, since an empty
# ERE matches everything (`printf 'abc' | grep -qE -e ''` exits 0), so a
# half-decoded file would fire on every command instead. Both are wrong, and
# CANARY below is what catches either before it can happen.
b64d() { # b64d <field>
  if [ "$1" = "-" ]; then
    printf ''
  else
    printf '%s' "$1" | base64 --decode 2>/dev/null
  fi
}

# "auth-guard" in base64, hard-coded so the probe tests decoding and nothing
# else.
CANARY_B64="YXV0aC1ndWFyZA=="
CANARY_PLAIN="auth-guard"

resolve_custom_file() {
  local candidate
  if [ -n "${AUTH_GUARD_CUSTOM_CHECKS:-}" ]; then
    cfg_file="$AUTH_GUARD_CUSTOM_CHECKS"
    if [ ! -f "$cfg_file" ] || [ ! -r "$cfg_file" ]; then
      cfg_error="AUTH_GUARD_CUSTOM_CHECKS names \"$cfg_file\", which is not a readable file"
      cfg_file=""
    fi
    return 0
  fi

  # The probe is the whole rule: the first candidate that exists wins, and a
  # directory that exists but holds no file gates nothing. Finding none is a
  # silent no-op, which is what a user who never opted in must get.
  #
  # A candidate that exists but cannot be read is not skipped. Skipping it
  # would hand the user the next file down, or no file at all, for a file they
  # did write; and reading it later would surface as "not valid JSON:
  # Permission denied", which sends them looking for a syntax error that is not
  # there. It resolves, and it fails closed naming itself.
  while IFS= read -r candidate; do
    if [ -f "$candidate" ]; then
      if [ ! -r "$candidate" ]; then
        cfg_error="custom-checks file \"$candidate\" exists but is not readable"
        return 0
      fi
      cfg_file="$candidate"
      return 0
    fi
  done <<<"$(custom_candidates)"
  return 0
}

load_custom() {
  [ -n "$cfg_error" ] && return 0
  [ -z "$cfg_file" ] && return 0

  local out st line first f1 f2 f3 f4 f5 f6 i

  # Parse and validate in two steps, so a syntax error in the file and an
  # internal error in the validator can never be reported as each other.
  out=$(jq empty "$cfg_file" 2>&1 >/dev/null)
  st=$?
  if [ "$st" -ne 0 ]; then
    out=$(printf '%s' "$out" | tr '\n\t' '  ' | tr -s ' ' | cut -c1-200)
    cfg_error="custom-checks file \"$cfg_file\" is not valid JSON: $out"
    return 0
  fi

  out=$(jq -r "$custom_jq" "$cfg_file" 2>&1)
  st=$?
  if [ "$st" -ne 0 ]; then
    out=$(printf '%s' "$out" | tr '\n\t' '  ' | tr -s ' ' | cut -c1-200)
    cfg_error="custom-checks file \"$cfg_file\" could not be validated: $out"
    return 0
  fi

  # A validated file with at least one check is about to send its fields from
  # jq into the shell through base64. If decoding is broken, every field comes
  # back empty and every custom check quietly stops matching: a fail-open of
  # protection the user wrote themselves. Prove the round trip first, and treat
  # a failure as a file error like any other. `out` is exactly "OK" when the
  # checks array is empty, and then there is nothing to decode and nothing to
  # lose.
  if [ "$out" != "OK" ] && [ "$(b64d "$CANARY_B64")" != "$CANARY_PLAIN" ]; then
    cfg_error="custom-checks file \"$cfg_file\" could not be loaded: base64 decoding is not working on this system, so no custom check can be read"
    return 0
  fi

  first=1
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if [ "$first" = 1 ]; then
      first=0
      case "$line" in
        OK) continue ;;
        "ERR "*)
          cfg_error="custom-checks file \"$cfg_file\" is invalid: ${line#ERR }"
          return 0 ;;
        *)
          cfg_error="custom-checks file \"$cfg_file\" could not be validated"
          return 0 ;;
      esac
    fi
    IFS=' ' read -r f1 f2 f3 f4 f5 f6 <<<"$line"
    custom_names[$custom_count]=$(b64d "$f1")
    custom_matches[$custom_count]=$(b64d "$f2")
    custom_regexes[$custom_count]=$(b64d "$f3")
    custom_decisions[$custom_count]=$(b64d "$f4")
    custom_messages[$custom_count]=$(b64d "$f5")
    custom_cases[$custom_count]=$(b64d "$f6")
    custom_count=$((custom_count + 1))
  done <<<"$out"

  # grep is the arbiter of what a regex is, so ask it rather than reimplement
  # POSIX ERE. Patterns go through -e here exactly as they do when matching,
  # so a regex starting with "-" is data in both places and the two agree.
  i=0
  while [ "$i" -lt "$custom_count" ]; do
    printf '' | grep -qE -e "${custom_regexes[$i]}" >/dev/null 2>&1
    st=$?
    if [ "$st" -gt 1 ]; then
      cfg_error="custom-checks file \"$cfg_file\" is invalid: check \"${custom_names[$i]}\": \"regex\" is not an extended regular expression grep -E accepts"
      return 0
    fi
    i=$((i + 1))
  done
  return 0
}

custom_match() { # custom_match <index>
  local subject
  if [ "${custom_matches[$1]}" = "verb" ]; then
    subject="$bare"
  else
    subject="$full"
  fi
  if [ "${custom_cases[$1]}" = "true" ]; then
    printf '%s' "$subject" | grep -qE -e "${custom_regexes[$1]}"
  else
    printf '%s' "$subject" | grep -qEi -e "${custom_regexes[$1]}"
  fi
}

# The winning custom check of one decision, with every other match of that
# same decision appended to the reason. All custom checks are evaluated, so a
# deny is never hidden by an ask that happens to sit earlier in the file.
cwin_name=""
cwin_reason=""

custom_pick() { # custom_pick <deny|ask>
  local want="$1" i winner also
  winner=-1
  also=""
  i=0
  while [ "$i" -lt "$custom_count" ]; do
    if [ "${custom_decisions[$i]}" = "$want" ] && custom_match "$i"; then
      if [ "$winner" -lt 0 ]; then
        winner=$i
      else
        also="${also:+$also, }${custom_names[$i]}"
      fi
    fi
    i=$((i + 1))
  done
  [ "$winner" -lt 0 ] && return 1

  cwin_name="${custom_names[$winner]}"
  cwin_reason="${custom_messages[$winner]}"
  [ -z "$cwin_reason" ] &&
    cwin_reason="decision $want defined by custom-check $cwin_name"
  [ -n "$also" ] && cwin_reason="$cwin_reason (also matched: $also)"
  return 0
}

# --- evaluation -------------------------------------------------------------
#
# Built-in denies, then custom denies, then built-in asks, then custom asks. A
# deny is therefore never shadowed by an ask from either side, and built-ins
# win ties. Custom-check validation sits after the built-in deny stage on
# purpose: a broken file must not weaken a shipped hard wall.

builtin_deny && decide deny "$hit_id" "$hit_reason"

resolve_custom_file
load_custom

[ -n "$cfg_error" ] &&
  decide ask "custom-checks-error" "$cfg_error. Auth-Guard fails closed until the file is fixed or removed: every command a built-in deny does not already block will ask."

# A custom deny that preempts a built-in ask is reported as such: the user's
# regex overlaps shipped coverage, which is worth knowing before they judge it
# wrong or risky. The built-in ask stage runs anyway to find that out.
if custom_pick deny; then
  if builtin_ask; then
    # The notice is a second sentence, so the message in front of it has to end
    # like one. Neither the fallback text nor a user's `message` is required to
    # carry terminal punctuation, and without this the two run together into
    # one unreadable line.
    case "$cwin_reason" in
      *[.!?]) ;;
      *) cwin_reason="$cwin_reason." ;;
    esac
    decide deny "$cwin_name overriding $hit_id" \
      "$cwin_reason Override notice: custom check \"$cwin_name\" took precedence over built-in check $hit_id, which would also have matched (as an ask)."
  fi
  decide deny "$cwin_name" "$cwin_reason"
fi

builtin_ask && decide ask "$hit_id" "$hit_reason"

custom_pick ask && decide ask "$cwin_name" "$cwin_reason"

exit 0
