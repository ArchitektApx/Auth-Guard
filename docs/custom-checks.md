# Custom checks

The PreToolUse guard (`hooks/secret-guard.sh`) ships with **built-in checks**:
credential-leak patterns curated in this repository. No shipped list can know
every environment, so you can add **custom checks** of your own in a JSON file.
The guard loads that file on every Bash call and evaluates your checks
alongside the built-ins.

Custom checks apply to the **Bash tool only**. The guard's behaviour on Read,
Grep and WebFetch is unchanged.

Start from [`config/custom-checks.example.json`](../config/custom-checks.example.json),
which exercises every field below.

## Where the file lives

Without the override variable the guard probes these paths in order and the
**first one that exists wins**:

1. `$XDG_CONFIG_HOME/auth-guard/custom-checks.json` (skipped when
   `XDG_CONFIG_HOME` is unset or empty, per the XDG convention)
2. `~/.config/auth-guard/custom-checks.json`
3. `~/.auth-guard/custom-checks.json`

The probe is the whole rule. A directory that exists but holds no
`custom-checks.json` gates nothing, so a file you wrote is never silently dead
just because a preferred directory happens to exist.

If no candidate exists, the guard behaves exactly as it does without this
feature: built-in checks only, no output on a command none of them match.

`AUTH_GUARD_CUSTOM_CHECKS`, when set to a non-empty value, **replaces**
resolution entirely: that path is the file, and no candidate is probed. An
empty value reads as unset. If the path does not name a readable file, that is
a configuration error and the guard fails closed (see
[Failure semantics](#failure-semantics)) rather than quietly running without
your checks.

Only one file is ever read. There is no per-project file and no merging.
`/auth-guard:doctor` reports which file resolved and warns when a
lower-precedence candidate is being shadowed by it.

## Schema

The top-level value is an object with **exactly one key**, `checks`, holding an
array. An empty array is valid and does nothing, so you can stub the file
before writing your first check. Any other top-level key is an error.

```json
{
  "checks": [
    {
      "name": "acme-vault-print",
      "match": "verb",
      "regex": "(^|[^a-z0-9_-])acme-vault +(print|export) ",
      "decision": "deny",
      "message": "'acme-vault print' writes the secret to stdout.",
      "case_sensitive": false
    }
  ]
}
```

| Field | Required | Type | Constraint |
| --- | --- | --- | --- |
| `name` | yes | string | Non-empty, and unique across the file. `custom-checks-error` is reserved by the guard (it is the name a fail-closed decision reports under) and is rejected. The name appears in every message the check produces, so make it identify the check to you. |
| `match` | yes | string | `"verb"` or `"any"`. See [Match modes](#match-modes). |
| `regex` | yes | string | Non-empty POSIX extended regular expression (ERE), as `grep -E` accepts it. |
| `decision` | yes | string | `"deny"` blocks the command, `"ask"` routes it to you for confirmation. |
| `message` | no | string | The reason shown when the check fires. Defaults to `decision <decision> defined by custom-check <name>`. |
| `case_sensitive` | no | boolean | Defaults to `false`, matching the built-ins. Set `true` when case carries meaning, for example an environment variable name. |

Unknown keys, at either level, are an error: a misspelled key would otherwise
silently drop the constraint you meant to write.

Regexes are passed to `grep` via `-e`, both when matching and when validating,
so a regex that begins with `-` is treated as data rather than as an option,
and the guard and the doctor always agree on what is valid. Remember that JSON
requires backslashes to be escaped: a literal dot is `"\\."` in the file.

The dialect is POSIX ERE. PCRE constructs (`\d`, `\b`, lookarounds, non-greedy
quantifiers) are not supported.

## Match modes

Before any check runs, the guard normalises the command: line continuations,
newlines, tabs and runs of whitespace collapse into single spaces. It then
produces two forms of it.

- **`any`** matches the whole normalised command, quoted segments included.
  Paths and variables are routinely quoted, so this is the mode to use when
  coverage matters more than precision. It is what the built-in credential-path
  checks use.
- **`verb`** matches the command with quoted segments stripped out. A real
  invocation's command name is essentially never fully quoted, so matching
  against this form gives high confidence the program is actually being run,
  and it removes the large class of false positives where your pattern appears
  only inside a string argument: test fixtures, grep patterns, commit messages,
  documentation heredocs.

A `verb` check on `acme-vault print` does not fire on
`echo "acme-vault print"`. An `any` check with the same regex does.

Heredoc bodies are not stripped from either form. That is a known gap.

## Evaluation order

The guard evaluates in four stages and stops at the first one that produces a
decision:

1. built-in **deny** checks
2. custom **deny** checks
3. built-in **ask** checks
4. custom **ask** checks

Two consequences follow. A deny is never shadowed by an ask, whichever side
defined it, so adding a custom `ask` can never weaken a shipped hard wall. And
built-ins win ties: when a built-in and a custom check of the same decision
both match, the built-in's id and reason are the ones you see.

Within your own checks, every check is evaluated rather than only the first
match. Any matching `deny` beats every matching `ask`. Among the matches of the
winning decision, the **first in file order** supplies the message, and the
remaining ones are appended to the reason as `also matched: <name>, <name>`, so
you can see that more than one of your patterns covers that command.

## The override notice

When a custom `deny` wins, the guard still runs the built-in ask stage to find
out whether a built-in would also have matched. If one would have, the decision
carries an **override notice**: both the reason and the `systemMessage` state
that your check took precedence over that built-in, naming your check and the
built-in's id.

```
secret-guard: deny (acme-netrc-hardwall overriding credential-path)
```

It is a notice, not a warning: hardening a built-in `ask` into a `deny` is a
legitimate thing to do. It exists so that an overlap you did not intend, or a
regex broader than you thought, does not stay invisible.

The reverse case is not reported: when a built-in fires and one of your checks
was redundant, nothing is said.

## Messages and ids

Every decision names the check that produced it:

```
secret-guard: <deny|ask> (<built-in id or custom-check name>)
```

Built-in checks carry short kebab-case ids (`gh-auth-token`,
`credential-path`, `ssh-private-key`, …) that are stable by intent, so a
message you saw once keeps meaning the same thing. Custom checks are named by
their `name` field, which is why it has to be unique.

## Failure semantics

Any parse or validation error invalidates the **whole file**. There is no
per-entry skipping: a file half in force is a protection you cannot reason
about.

A broken file does not weaken anything the plugin ships. Validation runs
**after** the built-in deny stage, so a command a built-in deny catches is
denied exactly as it would be with no file at all. Every other Bash command
gets an `ask`, with a reason naming the resolved file, the specific error, and
the offending check name (or the key, or the entry's index, where no usable
name is available; a JSON parse error has none). That state lasts until you fix
or remove the file.

```
secret-guard: ask (custom-checks-error)
```

Failing closed is deliberate. The alternative, ignoring a broken file, would
leave you believing in protection you wrote and are no longer getting.

`/auth-guard:doctor` reports the same error before a blocked command does. Run
it after every edit to this file.

## Cost and constraints

The file is read on every Bash call. It costs one `jq` invocation and a `grep`
per check, which is negligible against the hook overhead that is already there.
The guard makes no network calls. Besides `jq` and `grep` it runs one more
tool, `base64`, which carries each validated field from `jq` into the shell
intact; it is part of POSIX and present on every system that can run the rest
of the plugin. If it is ever not working, the guard fails
closed rather than running with checks that silently decoded to nothing.
