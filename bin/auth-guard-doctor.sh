#!/usr/bin/env bash
#
# auth-guard doctor: verify that every layer of the credential guard is
# actually in place on this machine.
#
# Checks are grouped and each prints exactly one line:
#   PASS <check>          working as intended
#   WARN <check>: <why>   degraded but not broken (e.g. optional layer absent)
#   FAIL <check>: <why>   a protection the plugin relies on is not working
#
# Exit status: 0 all pass (warnings allowed), 1 at least one FAIL.
#
# The self-tests use a synthetic token built at runtime; nothing is read from
# or written to real credential stores, and no secret-shaped string is printed.

set -uo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

HERE=$(cd "$(dirname "$0")" && pwd)
PLUGIN_ROOT=$(dirname "$HERE")
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"

fails=0
pass() { printf 'PASS %s\n' "$1"; }
warn() { printf 'WARN %s: %s\n' "$1" "$2"; }
fail() { printf 'FAIL %s: %s\n' "$1" "$2"; fails=1; }

# --- dependencies -----------------------------------------------------------

if command -v jq >/dev/null 2>&1; then
  pass "jq available ($(jq --version 2>/dev/null))"
else
  fail "jq" "not on PATH; both hooks and this doctor depend on it"
  echo "aborting: remaining checks need jq"
  exit 1
fi

if command -v betterleaks >/dev/null 2>&1; then
  pass "betterleaks available ($(betterleaks version 2>/dev/null))"
  HAVE_BL=1
else
  fail "betterleaks" "not on PATH; output-guard will fail open (unscanned output, with warning)"
  HAVE_BL=0
fi

# --- hook scripts -----------------------------------------------------------

for h in secret-guard.sh output-guard.sh; do
  if [ -x "$PLUGIN_ROOT/hooks/$h" ]; then
    pass "hooks/$h present and executable"
  elif [ -f "$PLUGIN_ROOT/hooks/$h" ]; then
    fail "hooks/$h" "present but not executable (chmod +x needed)"
  else
    fail "hooks/$h" "missing"
  fi
done

# --- hook self-tests --------------------------------------------------------

if [ -f "$PLUGIN_ROOT/hooks/secret-guard.sh" ]; then
  d=$(printf '{"tool_input":{"command":"gh auth token"}}' \
      | bash "$PLUGIN_ROOT/hooks/secret-guard.sh" 2>/dev/null \
      | jq -r '.hookSpecificOutput.permissionDecision // empty')
  [ "$d" = "deny" ] && pass "secret-guard denies 'gh auth token'" \
                    || fail "secret-guard self-test" "expected deny, got '${d:-no output}'"

  d=$(printf '{"tool_input":{"command":"ls -la"}}' \
      | bash "$PLUGIN_ROOT/hooks/secret-guard.sh" 2>/dev/null)
  [ -z "$d" ] && pass "secret-guard passes harmless command" \
              || fail "secret-guard self-test" "harmless command did not pass through"
fi

if [ "$HAVE_BL" = 1 ] && [ -f "$PLUGIN_ROOT/hooks/output-guard.sh" ]; then
  # Synthetic GitHub-classic-shaped token: ghp_ + 36 alnum, obviously fake to
  # a human but with enough character variety to clear betterleaks' entropy
  # threshold. An all-caps-plus-zero-padding fake sits right at the cutoff and
  # can silently stop matching when the ruleset tightens.
  fake="ghp_Fake9DoctorTest7Token3Qx5Vw2Zr8Kp4Mn"
  out=$(printf '{"tool_response":{"stdout":"x=%s"}}' "$fake" \
        | bash "$PLUGIN_ROOT/hooks/output-guard.sh" 2>/dev/null)
  if printf '%s' "$out" | grep -q "$fake"; then
    fail "output-guard self-test" "synthetic token survived redaction"
  elif printf '%s' "$out" | jq -e '.hookSpecificOutput.updatedToolOutput' >/dev/null 2>&1; then
    pass "output-guard redacts a synthetic token"
  else
    fail "output-guard self-test" "no updatedToolOutput produced (betterleaks rule miss or script error)"
  fi

  out=$(printf '{"tool_response":{"stdout":"hello world"}}' \
        | bash "$PLUGIN_ROOT/hooks/output-guard.sh" 2>/dev/null)
  [ -z "$out" ] && pass "output-guard passes clean output untouched" \
                || fail "output-guard self-test" "clean output was modified"
fi

# --- custom checks ----------------------------------------------------------
#
# Which file the guard would load, whether a second candidate is being
# shadowed, whether the file is valid, and whether the guard really loads one.
# Validation is not reimplemented here: the guard is pointed at the file and
# its own fail-closed reason is relayed, so there is exactly one implementation
# of the schema and the two can never disagree. Nothing below prints command
# text or matched text; paths, check names, counts and verdicts only.

GUARD="$PLUGIN_ROOT/hooks/secret-guard.sh"

if [ -f "$GUARD" ]; then
  resolved=""
  shadowed=""

  if [ -n "${AUTH_GUARD_CUSTOM_CHECKS:-}" ]; then
    if [ -f "$AUTH_GUARD_CUSTOM_CHECKS" ] && [ -r "$AUTH_GUARD_CUSTOM_CHECKS" ]; then
      resolved="$AUTH_GUARD_CUSTOM_CHECKS"
      pass "custom-checks file (AUTH_GUARD_CUSTOM_CHECKS): $resolved"
    else
      fail "custom-checks file" \
        "AUTH_GUARD_CUSTOM_CHECKS names $AUTH_GUARD_CUSTOM_CHECKS, which is not a readable file; the guard fails closed on every command"
    fi
  else
    # XDG_CONFIG_HOME is very often exactly $HOME/.config, which makes the
    # first two candidates the same path. The guard does not care, it takes the
    # first hit either way, but ranking that list without de-duplicating it
    # would report a file as shadowing itself and print the same path twice.
    probed=""
    seen=""
    while IFS= read -r candidate; do
      case "$seen" in
        *"[$candidate]"*) continue ;;
      esac
      seen="${seen}[$candidate]"
      probed="${probed:+$probed, }$candidate"
      [ -f "$candidate" ] || continue
      if [ -z "$resolved" ]; then
        resolved="$candidate"
      else
        shadowed="${shadowed:+$shadowed, }$candidate"
      fi
    done <<<"$(bash "$GUARD" --candidates)"

    if [ -n "$resolved" ]; then
      pass "custom-checks file resolved: $resolved"
    else
      # Naming the chain rather than counting it: this line is what a user who
      # wants to opt in reads to find out where the file goes, and the first
      # path listed is the one that would win.
      pass "no custom-checks file found; probed: $probed; built-in checks only"
    fi
  fi

  if [ -n "$shadowed" ]; then
    warn "custom-checks shadowing" \
      "$resolved wins; these lower-precedence files are never read: $shadowed"
  fi

  if [ -n "$resolved" ] && [ ! -r "$resolved" ]; then
    # The relay below points AUTH_GUARD_CUSTOM_CHECKS at the resolved file, so
    # the guard answers from its override branch and names that variable. For a
    # file found by probing, the user never set it, and being told about a
    # variable they have never heard of is the same misdirection the guard's
    # own candidate wording exists to avoid. Answer this one case directly, in
    # the guard's words for it.
    fail "custom-checks file valid" \
      "custom-checks file \"$resolved\" exists but is not readable; the guard fails closed on every command a built-in deny does not already block"
  elif [ -n "$resolved" ]; then
    out=$(printf '{"tool_input":{"command":"auth-guard-doctor-probe"}}' \
          | AUTH_GUARD_CUSTOM_CHECKS="$resolved" bash "$GUARD" 2>/dev/null)
    if [ "$(printf '%s' "$out" | jq -r '.systemMessage // empty')" \
         = "secret-guard: ask (custom-checks-error)" ]; then
      fail "custom-checks file valid" \
        "$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecisionReason')"
    else
      n=$(jq -r '.checks | length' "$resolved" 2>/dev/null)
      pass "custom-checks file valid (checks: ${n:-0})"
    fi
  fi

  # End-to-end: a synthetic file through the real guard, asserting the decision
  # JSON that comes back. Same seam as the redaction self-tests above.
  #
  # This is the only thing this script writes outside the plugin directory: one
  # transient file under $TMPDIR, holding a synthetic check and nothing from
  # the user's environment. The trap is armed on the line after mktemp and
  # covers the signals that can arrive before the rm below, so an interrupted
  # doctor run leaves nothing behind.
  synth=$(mktemp "${TMPDIR:-/tmp}/auth-guard-selftest.XXXXXX")
  trap 'rm -f "$synth"' EXIT HUP INT TERM
  printf '%s\n' '{"checks":[{"name":"auth-guard-selftest","match":"verb","regex":"auth-guard-selftest-trigger","decision":"deny","message":"auth-guard self-test check"}]}' >"$synth"
  out=$(printf '{"tool_input":{"command":"auth-guard-selftest-trigger --now"}}' \
        | AUTH_GUARD_CUSTOM_CHECKS="$synth" bash "$GUARD" 2>/dev/null)
  rm -f "$synth"
  trap - EXIT HUP INT TERM
  d=$(printf '%s' "$out" | jq -r '.hookSpecificOutput.permissionDecision // empty')
  s=$(printf '%s' "$out" | jq -r '.systemMessage // empty')
  if [ "$d" = "deny" ] && [ "$s" = "secret-guard: deny (auth-guard-selftest)" ]; then
    pass "secret-guard loads a custom-checks file end to end"
  else
    fail "custom-checks self-test" \
      "expected deny from check auth-guard-selftest, got '${d:-no output}' / '${s:-no systemMessage}'"
  fi
fi

# --- hook registration ------------------------------------------------------

# Hooks may be wired either by this plugin (hooks/hooks.json, when installed
# as a plugin) or manually in settings.json. Warn if neither is detectable.
if [ -f "$SETTINGS" ] && jq -e '.enabledPlugins | keys[] | select(startswith("auth-guard@"))' "$SETTINGS" >/dev/null 2>&1; then
  pass "auth-guard plugin enabled in settings"
elif [ -f "$SETTINGS" ] && jq -e '[.hooks.PreToolUse[]?.hooks[]?.command, .hooks.PostToolUse[]?.hooks[]?.command] | any(. != null and (contains("secret-guard") or contains("output-guard")))' "$SETTINGS" >/dev/null 2>&1; then
  pass "hooks wired manually in settings.json"
else
  warn "hook registration" "neither the plugin nor a manual hook entry found; hooks are dormant"
fi

# --- settings layers --------------------------------------------------------

if [ -f "$SETTINGS" ]; then
  if jq -e '.sandbox.enabled == true' "$SETTINGS" >/dev/null 2>&1; then
    pass "sandbox enabled"
  else
    warn "sandbox" "not enabled; filesystem-level credential denies are inactive"
  fi

  n=$(jq -r '.sandbox.credentials.files | length' "$SETTINGS" 2>/dev/null)
  case "$n" in
    ''|null|0) warn "sandbox.credentials.files" "no entries; home-dir credential files readable by shell commands" ;;
    *)         pass "sandbox.credentials.files has $n entries" ;;
  esac

  n=$(jq -r '[.permissions.deny[]? | select(startswith("Read("))] | length' "$SETTINGS" 2>/dev/null)
  case "$n" in
    ''|null|0) warn "Read deny rules" "none found; harness tools (Read/Grep/@-mentions) unrestricted" ;;
    *)         pass "$n Read() deny rules present" ;;
  esac
else
  warn "settings" "no settings file at $SETTINGS"
fi

echo
[ "$fails" = 0 ] && echo "doctor: all critical checks passed" || echo "doctor: FAILURES present, see above"
exit "$fails"
