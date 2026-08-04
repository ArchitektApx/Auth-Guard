#!/usr/bin/env bash
#
# auth-guard global-settings: merge the plugin's deny rules into the user's
# Claude Code settings.json.
#
# Source of truth is config/deny-rules.json (permissions.deny entries plus
# sandbox.credentials.files). The merge is additive and idempotent:
#   - existing entries are never removed or reordered
#   - only rules not already present are appended
#   - sandbox.enabled is set to true, other sandbox keys are preserved
#
# Usage:
#   auth-guard-apply-settings.sh [--dry-run]
#
# --dry-run prints what would be added and leaves the file untouched.
# A timestamped backup is written next to settings.json before any change.
#
# Exit status: 0 applied or nothing to do, 2 dry-run found pending additions,
# 64+ on errors.

set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin${PATH:+:$PATH}"

HERE=$(cd "$(dirname "$0")" && pwd)
RULES="$(dirname "$HERE")/config/deny-rules.json"
SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
DRY=0
[ "${1:-}" = "--dry-run" ] && DRY=1

[ -f "$RULES" ] || { echo "rules file missing: $RULES" >&2; exit 64; }
[ -f "$SETTINGS" ] || { echo "settings file not found: $SETTINGS (set CLAUDE_SETTINGS to override)" >&2; exit 64; }
jq -e . "$SETTINGS" >/dev/null || { echo "refusing to touch $SETTINGS: not valid JSON" >&2; exit 65; }

# What would be added, computed first so dry-run and apply agree exactly.
pending=$(jq -n --slurpfile s "$SETTINGS" --slurpfile r "$RULES" '
  ($s[0].permissions.deny // []) as $have_deny
  | ($s[0].sandbox.credentials.files // []) as $have_files
  | {
      deny:  ($r[0].permissions.deny - $have_deny),
      files: ($r[0].sandbox.credentials.files
              | map(select(.path as $p | ($have_files | map(.path) | index($p)) | not))),
      sandbox_off: (($s[0].sandbox.enabled // false) | not)
    }')

n_deny=$(jq -r '.deny | length' <<<"$pending")
n_files=$(jq -r '.files | length' <<<"$pending")
sandbox_off=$(jq -r '.sandbox_off' <<<"$pending")

echo "pending additions: $n_deny permission deny rule(s), $n_files sandbox credential file(s)"
[ "$sandbox_off" = "true" ] && echo "pending change: sandbox.enabled will be set to true"

if [ "$n_deny" = 0 ] && [ "$n_files" = 0 ] && [ "$sandbox_off" = "false" ]; then
  echo "nothing to do: all rules already present"
  exit 0
fi

if [ "$DRY" = 1 ]; then
  echo "--- would add (dry run) ---"
  jq -r '(.deny[] | "  permissions.deny: \(.)"),
         (.files[] | "  sandbox.credentials.files: \(.path)")' <<<"$pending"
  exit 2
fi

backup="$SETTINGS.bak-$(date +%Y%m%d-%H%M%S)"
cp "$SETTINGS" "$backup"
echo "backup written: $backup"

tmp=$(mktemp "${TMPDIR:-/tmp}/settings.XXXXXX")
jq --slurpfile p <(printf '%s' "$pending") '
  .permissions.deny = ((.permissions.deny // []) + $p[0].deny)
  | .sandbox.enabled = true
  | .sandbox.credentials.files = ((.sandbox.credentials.files // []) + $p[0].files)
' "$SETTINGS" > "$tmp"

jq -e . "$tmp" >/dev/null || { echo "merge produced invalid JSON, aborting (settings untouched)" >&2; rm -f "$tmp"; exit 65; }
mv "$tmp" "$SETTINGS"
echo "applied. $n_deny deny rule(s) and $n_files credential file(s) added."
