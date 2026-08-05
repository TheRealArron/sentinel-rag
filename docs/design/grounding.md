# Keeping the analyst honest

Three limits are applied to every model response. Each exists because the failure
it prevents produces an alert that *reads* correct.

## Citations are validated, and the verdict is machine-readable

The model must cite `[S#]` markers. After parsing, citations that do not resolve
to a retrieved source are dropped, and `Alert.grounding` records a verdict:

| Verdict | Meaning |
|---|---|
| `GROUNDED` | every citation resolved |
| `PARTIALLY_GROUNDED` | some resolved, some invented |
| `UNGROUNDED` | the model cited nothing |
| `POTENTIALLY_HALLUCINATED` | every citation was invented |
| `NOT_APPLICABLE` | rule-based output, no model involved |

The distinction that matters is between "cited nothing" and "cited things that do
not exist". The first is an unhelpful answer. The second is confabulation, and it
is worse precisely because it looks grounded. A prose note is not enough — a
consumer routing alerts needs to filter on this without parsing English.

## Severity is clamped

The Go ingestor already computed a deterministic score from explicit rules. The
model may raise severity by at most one step above it; a larger jump is clamped
and noted. An LLM that decides a cron job is critical must not be able to page
someone at 03:00.

## The prompt is bounded, not just the completion

Output caps stop a runaway answer. They do nothing about a long-form injection
padded with megabytes of attacker-chosen log text, which costs money per request
and pushes the real evidence out of the context window.

`SENTINEL_LLM_MAX_PROMPT_CHARS` bounds the assembled prompt. The log block is
truncated first, because retrieved advisories are trusted and log text is not.

## Prompt injection

Log content is attacker-controlled — a remote user picks their own SSH username.
Defences, in order of reliability: the ingestor neutralises control characters;
log text and retrieved sources are fenced in labelled delimiters; the system
prompt states that fenced content is never an instruction; output is constrained
to a fixed JSON schema, so a successful injection has little room to express
itself. Defence in depth, not a guarantee — which is why the grounding verdict
above exists.
