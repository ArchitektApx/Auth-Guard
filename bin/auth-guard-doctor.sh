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
