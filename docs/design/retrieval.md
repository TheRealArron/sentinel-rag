# Bilingual retrieval

## The per-language floor

`multilingual-e5` puts an English query and a Japanese passage about the same
attack near each other. That is necessary but not sufficient: an English query
against a 70%-English corpus returns an English-only top-k most of the time, and
the Japanese advisory that would have explained the attack never reaches the
model.

So retrieval runs a targeted second query per language and reserves slots for
each. Two bugs found while building it, both worth knowing:

1. **Truncation undoes the floor.** Merge → sort by score → cut to `k` removes
   exactly the topped-up hits, because they are lower-scoring by construction —
   that is why they needed forcing. Candidates are collapsed to parents *before*
   selection.
2. **Sequential allocation starves the second language.** Filling English's quota
   of 2 first consumes both slots at `k=2`. Allocation is round-robin, so it
   degrades to "one of each".

## The e5 prefixes are mandatory

e5 is trained with `query: ` on queries and `passage: ` on documents. Omitting
them, or using the same prefix for both, costs a large chunk of retrieval quality.
It is the most common way this model is misused.

## Script-aware chunking

A character-count splitter tuned for English produces Japanese chunks roughly four
times over budget, because Japanese is close to one token per character while
English is about four characters per token. And splitting Japanese on `". "` finds
nothing, so it falls through to a hard cut mid-word.

`lang.estimate_tokens` counts CJK code points as one token each; the separator
list includes `。`, `、`, `！`, `？`.

## Hierarchical parent-document retrieval

Embedding a 2000-token advisory into one vector averages away the sentence that
matters. Embedding 400-token chunks retrieves precisely but hands the model a
fragment with no context — the condition under which LLMs invent a
plausible-sounding remediation. So: search small children, return large parents.

Child ids are content-addressed, so re-indexing an unchanged corpus embeds
nothing.
