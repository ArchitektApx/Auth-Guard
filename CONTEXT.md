# Auth-Guard

A Claude Code plugin that keeps credentials out of tool calls and transcripts: a PreToolUse guard blocks commands that would print secrets, a PostToolUse guard redacts secrets that slip through.

## Language

**Built-in check**:
A credential-leak pattern shipped in `secret-guard.sh` itself, curated by this repository.
_Avoid_: default rule, stock check

**Custom check**:
A user-authored credential-leak pattern loaded from the user's custom-checks file and evaluated by the PreToolUse guard alongside the built-in checks.
_Avoid_: user rule, custom rule

**Match mode**:
Which form of the command a check's regex runs against: `verb` matches the quote-stripped command (high confidence the named program is actually invoked), `any` matches the full normalized command including quoted segments.
_Avoid_: match type, target

**Decision**:
The permission outcome a matching check produces: `deny` blocks the tool call, `ask` routes it to the user for confirmation.
_Avoid_: action, verdict, severity (severity orders decisions; the decision itself is deny or ask)

**Check id**:
The short stable identifier of a built-in check (e.g. `gh-auth-token`), named in diagnostic output and in the override notice.
_Avoid_: rule id, check name (a name belongs to a custom check; an id to a built-in)

**Override notice**:
The note appended to a decision when a custom deny preempts a built-in ask that would also have matched, naming the custom check and the shadowed built-in id.
_Avoid_: shadow warning, precedence message
