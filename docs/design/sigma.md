# Sigma interoperability

Sentinel's detection rules are its own. Sigma is the format the rest of the
industry writes detections in. This note covers how the two are bridged, and
what the bridge deliberately refuses to do.

## Why the transpiler is in Python and the evaluator is in Go

Sigma is YAML. The Go ingestor has an empty `go.mod` — no third-party
dependencies at all — and it is the component that parses attacker-controlled
input, runs closest to the log source, and ships `FROM scratch`. Adding a YAML
parser there would put a few thousand lines of untrusted-input parsing into the
one place the project has been strict about.

So the split is:

```
rules/sigma/*.yml  ──[ sentinel sigma ]──▶  rules/external/sigma.json  ──▶  ingestor
     (YAML)            Python, has PyYAML         (JSON)                    encoding/json
```

The Python engine already carries a YAML dependency, and has a pure-Python
fallback parser for the subset Sigma actually uses, so the transpiler works even
in the no-dependencies configuration the rest of the engine supports.

This also answers the operational question directly: **adding a detection never
requires a Go rebuild.** Drop a rule in `rules/sigma/`, run `make sigma`, restart
the ingestor. The binary is unchanged. A build-script approach — regenerating Go
source and recompiling — would have coupled detection content to release
cadence, which is exactly backwards for the thing you most want to change fast.

## A predicate tree, not a flattened regex

The obvious implementation is to compile a Sigma selection into one big regex and
hand it to the existing rule engine. That is wrong, and the reason is `not`.

The most common shape in real Sigma rules is:

```yaml
condition: selection and not filter_internal
```

Regex alternation cannot express "matches A and does not match B" in the general
case, and the workarounds (lookahead) are not available in Go's RE2. A transpiler
that flattened this would silently drop the filter, turning a tuned rule into a
false-positive generator. So the output is a tree:

```json
{"op": "and", "children": [
  {"op": "match", "field": "message", "match": "contains", "values": ["Failed password"]},
  {"op": "not", "children": [
    {"op": "match", "field": "source_ip", "match": "startswith", "values": ["10."]}]}]}
```

Both implementations walk this structure. Regexes are compiled once at load, and
case-insensitive values are pre-folded, so matching allocates nothing per line.

## The Sentinel subset, and what it refuses

The goal was never a complete Sigma implementation — it was the 80% of SSH and
syslog rules that are useful on this system. Everything outside that is
**skipped with a stated reason**, never approximated:

| Refused | Why |
|---|---|
| `product: windows`, Windows event fields | Sentinel parses syslog. There is nothing to match against. |
| `\| count() > 5`, `\| near` | Stateful aggregation. Dropping the aggregation turns "5 failures from one host" into "1 failure" — a rule that fires constantly. Sentinel's correlator handles this class; the per-line evaluator cannot. |
| `base64offset`, `windash`, `utf16` | These change the *encoding* of the match. Translating them approximately alters the detection silently. |
| Unmappable fields | A field with no Sentinel equivalent would compile to a match that can never fire. |

`compile_directory` reports `rules / skipped / failed` separately, and one bad
rule never stops the batch. Importing 40 community rules of which 6 are Windows
rules should give you 34 working detections and a list of what was left out —
not a stack trace, and not 40 rules of which 6 quietly never fire.

Two translations are deliberately *not* literal:

- **Bare equality on free text widens to `contains`.** Sigma's `message: foo`
  means equality. On a syslog line — which carries a timestamp and a PID around
  the interesting part — a literal reading produces a rule that never fires.
- **Bare equality on a structured field stays exact.** `user: root` must not
  match `rooted`.

## How imported rules compose with built-in ones

The first version ran Sigma only when no built-in rule had matched, on the theory
that the hand-tuned built-ins should win. Testing it end to end showed why that
is wrong: the built-ins already cover the common SSH and sudo lines, so an
imported rule was shadowed on essentially every event it was written for. The
import bought nothing.

The rule now is:

- **Attribution always merges.** Tags and ATT&CK techniques from the Sigma rule
  are added regardless. This is most of the value — a built-in that knows a line
  is an SSH failure gains `T1110.001` from the Sigma rule that knows it is brute
  force, and a Japanese-speaking analyst filtering on 認証情報アクセス finds a
  rule imported from an English-language ruleset.
- **The verdict is taken over only on escalation.** A Sigma rule replaces the
  rule name, category and score only when nothing built-in matched, or when it
  scores strictly higher. When it escalates, the built-in's verdict is preserved
  in `fields.builtin_rule`. An imported rule can raise an alert; it cannot
  quietly lower one.
- **Outcome is never overwritten.** Sigma has no outcome concept, so the
  transpiler guesses one from the rule's level, while a built-in rule read
  success/failure off the log line itself. An unconditional assignment here let
  an imported rule silently disable brute-force correlation — the correlator
  keys on `outcome == "failure"` — and the sample fixture dropped from 25 events
  to 23. A fabricated field must not overwrite a derived one.
- **Honeytokens still outrank everything.** Deception is the one signal with no
  benign reading, so it overrides both.

Severity maps from Sigma's `level`: informational 15, low 35, medium 55, high 72,
critical 88. These sit inside Sentinel's existing bands rather than at the
boundaries, so the score modifiers (public source, root involved) still move an
imported rule across a threshold the way they move a native one.

## Keeping the two implementations honest

A transpiler whose output the consumer interprets differently is worse than no
transpiler: `sentinel sigma` would report "3 compiled" while the ingestor
silently reads one of them another way — confident, wrong coverage.

So both implementations are pinned to one shared vector file,
`ingestor/internal/sigma/testdata/agreement.json`, generated by
`scripts/gen-sigma-vectors.py`. The expected verdicts come from the Python
reference evaluator rather than from hand authorship, so the file records what
the transpiler's semantics actually are; the Go test then has to agree.
Hand-written expectations would let one mistake be written into both sides at
once.

Coverage is itself asserted: the suite fails if it stops exercising every
operator and every boolean form, if it ever contains only matches (which would
pass against an evaluator that always returns `true`), or if a rule ships without
a vector.

Re-run `make sigma-check` after touching the transpiler and read the diff — a
changed verdict is a semantic change, and the diff is where you notice.

## Operational notes

- `-sigma <dir>` defaults to `rules/external`. A missing default directory is
  silent, since most installs import nothing. A missing **explicit** `-sigma` is
  a fatal error: the operator asked for those detections and must not be told
  everything is fine while running with none of them. `-sigma=""` disables
  imported rules outright.
- The committed sample fixture is generated with `-sigma=""`, because it has to
  describe a *default* install. Letting it absorb whatever rules happen to be
  compiled on the machine that ran `make sample` would make the drift check
  depend on local state, and would make an opt-in feature look mandatory. Phase
  11 gets its own CI step instead, which asserts that rules are armed, that
  events actually carry the attribution, and that correlation still fires.
- Bundles carry a schema version. A bundle from a newer transpiler is refused
  outright rather than half-understood — ignoring constructs this build does not
  implement would silently under-match.
- The JSON decoder runs with `DisallowUnknownFields`, so the bundle key set is a
  contract between the two halves, enforced at load.
- Rules load in filename order, so first-match-wins does not depend on what order
  the filesystem happened to return directory entries in.
