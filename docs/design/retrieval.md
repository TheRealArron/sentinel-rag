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

A character-count splitter tuned for English produces Japanese chunks about twice
over budget. And splitting Japanese on `". "` finds nothing, so it falls through
to a hard cut mid-word.

`lang.estimate_tokens` counts CJK code points as one token each, letters and
whitespace at four characters per token, and digits, punctuation and symbols at
one token each; the separator list includes `。`, `、`, `！`, `？`.

### Measured against the real tokenizer

This section used to say *four times*, from a rule of thumb: one token per
Japanese character, four characters per English token. Neither half survives the
tokenizer multilingual-e5 actually uses (XLM-R's SentencePiece vocabulary).
Measured on this corpus, with the estimator as it now stands:

| Text | n | chars / token | `estimate_tokens` ÷ real |
|---|---:|---:|---:|
| English, hand-written summaries | 3 | 3.33 | 1.15 |
| English, NVD records | 39 | 3.02 | 1.22 |
| Japanese documents, whole | 5 | 2.02 | 1.42 |
| Japanese script only | 5 | 1.78 | 1.78 |

A character budget sized for English still holds roughly twice its tokens on
Japanese script, which is what justifies a script-aware splitter — about half
the figure this document originally claimed.

The ratio column previously read 0.87 / 0.74 / 1.58 / 1.19, against an estimator
that counted everything non-CJK at four characters per token. The chars-per-token
column moved a little too (from 3.43 / 2.97 / 1.58 / 2.07); that column is a
property of the tokenizer and not of the estimator, and it shifts here because
this grouping counts 39 NVD records against 3 hand-written summaries, where the
earlier split counted five summaries.

### The third character class, and the truncation it caused

Counting everything non-CJK at four characters per token was wrong in the
direction that loses data. SentencePiece merges letters into multi-character
word pieces, so prose really does run about four characters to the token. It does
not merge digits and punctuation: `CVE-2026-46279` and `mm/alloc_tag:` become a
long run of one-character pieces, and an NVD record is dense with exactly those.

Measured with the real tokenizer, before the fix: the worst child chunk estimated
433 tokens and held **788**, a ratio of 1.82. Nine of 93 chunks were over e5's
512-token input limit, the largest at 824, and sentence-transformers truncates
silently — 1397 tokens were discarded before they were ever embedded. Eight of
the nine were already past the limit before the prepended title was counted, so
the title was never the cause.

`estimate_tokens` now counts three classes, and the defect is closed:

| | before | after |
|---|---:|---:|
| child chunks | 93 | 126 |
| chunks over the 512-token limit | 9 | **0** |
| longest chunk, real tokens | 824 | 497 |
| tokens discarded by truncation | 1397 | **0** |
| real ÷ estimate, worst chunk | 1.80 | 1.05 |

**The remaining margin is thin, and it is empirical rather than structural.**
`child_tokens` bounds the chunk *body*; the prepended title and the overlap tail
are added on top of it, so the embedded string's estimate reaches 502 against a
400-token budget. At the worst observed ratio that arithmetic permits about 529
real tokens, which would not fit. It does not happen only because the chunks that
run longest are ones this estimator overestimates. The longest is 497 of 512 —
fifteen tokens of headroom, and a longer document could consume it.

Nothing detects that on its own, so it is pinned instead.
`engine/tests/testdata/tokenizer_vectors.json` holds the 49 longest chunks with
their token counts from the real tokenizer, and
`engine/tests/test_tokenizer_vectors.py` — which needs no dependencies to run —
fails if a chunk reaches the limit, if the estimator drifts from the committed
numbers, or if the headroom disappears. `make tokenizer-check` regenerates it,
and must be re-run when the corpus, the chunking settings, or the estimator
change. It is the arrangement the Go/Python Sigma and IOC bridges already use,
for the same reason: an approximation of something you are not allowed to import
has to be held against it somewhere, or it drifts in silence. That is precisely
how this defect survived — every test that measured a chunk against its budget
measured it with the same estimator that was wrong, so they all agreed.

A second change was built, measured, and **rejected**: reserving the title and
overlap inside `child_tokens`, so the budget would bound the embedded string
structurally instead of empirically. It works — 174 chunks, longest 380 — but
smaller chunks retrieve worse, and it cost e5-large overall hit@5 0.936 → 0.894,
cross-lingual 0.594 → 0.531, and misses 3 → 5. The headroom was not worth that.

## Hierarchical parent-document retrieval

Embedding a 2000-token advisory into one vector averages away the sentence that
matters. Embedding 400-token chunks retrieves precisely but hands the model a
fragment with no context — the condition under which LLMs invent a
plausible-sounding remediation. So: search small children, return large parents.

Child ids are content-addressed, so re-indexing an unchanged corpus embeds
nothing.


---

## Recall@k: the numbers, and how the query set avoids being circular

Everything above this line is a mechanism. None of it had a number attached until
`data/eval/retrieval.jsonl` existed: 47 queries, each with one to three expected
documents (binary relevance, judged by one person), over the 47-document corpus,
run by `make retrieval-report`.

### The methodology, and its weaker half

A query written by reading a document and inverting its wording measures nothing.
It reproduces one level up exactly the circularity the bilingual `keywords` lists
create — the answer sits inside the question.

So **32 of the 47 pairs (`origin: "event"`) were written from the event side
first**: the 33 rule names, the correlated incidents, and the lines in
`data/samples/sample_syslog.log`. *"Five failed passwords from the same address
inside a minute, what should I do about it"* is what an analyst types after
seeing `correlated_brute_force`. Only afterwards was the corpus consulted to
decide which document answers it — and some queries were kept precisely because
the answer is thin.

**15 pairs (`origin: "software"`) are weaker and are labelled so.** *"Is our
OpenSSH vulnerable to unauthenticated RCE"* is a real question, but choosing
*OpenSSH* rather than some product the corpus does not cover means the corpus was
consulted first. They are reported as a separate row so the bias is visible
rather than averaged away. It shows: the software half scores **0.867** at hit@5
against the event half's **0.812**. A modest gap, in the direction predicted.

### The floor has to be switched off to measure anything

`per_language_floor` reserves slots per language regardless of score. Left on, it
makes cross-lingual recall meaningless: the Japanese document is in the results
because the floor put it there. The report therefore runs both ways. Floor-off is
ranking quality; floor-on is what the operator receives.

> **These tables were re-measured after the chunking fix above.** Every number
> here comes from a run on the current code; the pre-fix figures are kept
> alongside so the effect of the fix is visible rather than quietly replaced.
> Each run used a fresh index directory — see the next section for why that is
> not merely tidiness.

### The index the numbers are measured against

Indexing is incremental and child ids are content-addressed. Both are deliberate:
re-indexing an unchanged corpus must embed nothing, because embedding is by far
the most expensive step. The consequence nobody had accounted for is that
changing the chunker, the token estimator, or a document produces *new* ids and
**leaves every superseded vector in the store**. Only `index --rebuild` calls
`reset()`, and nothing on the read path checked.

So the stale chunks stayed retrievable and competed for the top k against the
chunks that replaced them. Measured here, immediately after the estimator change
above:

```
store after `make retrieval-report`:  1203 vectors
a clean build of the same corpus:      908 vectors
overall hit@5, stale index:  0.702
overall hit@5, clean index:  0.851
```

A headline figure wrong by 0.149, with no warning. This is the same shape as the
`--cases` default that broke `make retrieval-report` for weeks: the failure only
exists on the path a real user takes. CI starts from an empty directory every
time, and so does every fixture in the test suite, so neither could see it.

`eval-retrieval` now compares the store's vector count against the number of
chunks the current corpus and chunking actually produce, and **refuses to print a
report** when the store holds more, naming the gap and the command that fixes it.
A quietly wrong benchmark is worse than no benchmark. Measured: a clean index
reports normally; re-running with `SENTINEL_CHILD_TOKENS=200` against an index
built at 400 refuses with *"index is stale: 2742 vectors in the store, but the
current corpus and chunking produce 1869"*.

Two things this does not do. It does not prune — the store is left alone and
`make reindex` is the remedy, which on e5-large means re-embedding the corpus.
And it cannot tell a superseded chunk from a legitimately extra one, because it
compares counts rather than id sets; anything that adds vectors outside
`index_all` would read as staleness. Ordinary further ingestion does not trip it:
indexing 400 events and then re-running against the full log reported normally,
because later events form new windows rather than rewriting existing ones. A
truncation landing mid-window would rewrite that window's document, and I did not
test that case.

### Results — dependency-free backend (`hashing-512`, `LocalVectorStore`)

| Slice | queries | hit@1 | hit@3 | hit@5 | MRR |
|---|---:|---:|---:|---:|---:|
| overall | 47 | 0.638 | 0.766 | **0.851** | 0.713 |
| **cross-lingual** | 32 | 0.125 | 0.219 | **0.312** | 0.183 |
| query lang = en | 33 | 0.636 | 0.727 | 0.849 | 0.702 |
| query lang = ja | 14 | 0.643 | 0.857 | 0.857 | 0.738 |
| origin = event | 32 | 0.562 | 0.750 | 0.844 | 0.664 |
| origin = software | 15 | 0.800 | 0.800 | 0.867 | 0.817 |

Before the fix: overall 0.660 / 0.787 / 0.830 / 0.720 and cross-lingual 0.062 /
0.156 / 0.188 / 0.112, with 8 misses against 7 now. The fix helps this backend
at k=5 and cross-lingually — smaller chunks give a lexical retriever more
specific vectors to match — and costs it a little at hit@1.

With the floor **on**, cross-lingual hit@5 goes from 0.312 to **0.562** (it was
0.188 → 0.656 before the fix).

That pattern is the whole finding in one line. The floor reserves a slot near the
bottom of the result set, so it can only change the figure at the k where the
reservation lands. Every cross-lingual "success" this system produces on the
default backend is the floor doing its job, not the embedder understanding
anything. Same-language retrieval is genuinely decent — 0.830 overall is a
working lexical retriever. Cross-lingual retrieval, on this backend, does not
exist.

None of that is a defect. The floor was built for exactly this case and the
keyword bridge was built as its companion. What is new is that the claim now has
a number instead of an argument, and the number says which mechanism is load
bearing.

### Results — the real embedders (`multilingual-e5-small` and `-large`)

Run locally, outside CI, on the same 47 queries and the same corpus, with the
exact `LocalVectorStore`. Large is the project default; small is the 470 MB
option `requirements.txt` offers for constrained hosts. Both tables are floor off.

**multilingual-e5-small**

| Slice | queries | hit@1 | hit@3 | hit@5 | MRR |
|---|---:|---:|---:|---:|---:|
| overall | 47 | 0.830 | 0.915 | **0.936** | 0.870 |
| **cross-lingual** | 32 | 0.094 | 0.281 | **0.438** | 0.213 |
| query lang = en | 33 | 0.818 | 0.909 | 0.939 | 0.860 |
| query lang = ja | 14 | 0.857 | 0.929 | 0.929 | 0.893 |
| origin = event | 32 | 0.812 | 0.906 | 0.938 | 0.855 |
| origin = software | 15 | 0.867 | 0.933 | 0.933 | 0.900 |

Before the fix: overall 0.787 / 0.894 / 0.936 / 0.839, cross-lingual 0.125 /
0.250 / 0.438 / 0.212. Overall hit@1 gains most (0.787 → 0.830); cross-lingual
hit@5 does not move and cross-lingual hit@1 falls. The same three queries miss
before and after (q08, q14, q46).

**multilingual-e5-large**

| Slice | queries | hit@1 | hit@3 | hit@5 | MRR |
|---|---:|---:|---:|---:|---:|
| overall | 47 | 0.830 | 0.894 | **0.936** | 0.871 |
| **cross-lingual** | 32 | 0.094 | 0.312 | **0.594** | 0.258 |
| query lang = en | 33 | 0.788 | 0.849 | 0.909 | 0.832 |
| query lang = ja | 14 | 0.929 | 1.000 | 1.000 | 0.964 |
| origin = event | 32 | 0.781 | 0.844 | 0.906 | 0.827 |
| origin = software | 15 | 0.933 | 1.000 | 1.000 | 0.967 |

Before the fix: overall 0.830 / 0.872 / 0.915 / 0.858, cross-lingual 0.094 /
0.344 / 0.562 / 0.249. Overall hit@5 0.915 → 0.936 and cross-lingual hit@5
0.562 → 0.594, with the miss list going from four queries to three — `q21`, the
reverse shell launched from a sudo command line, is now found, and nothing that
was found before is lost. Cross-lingual hit@3 is the one figure that drops
(0.344 → 0.312), which is one query.

With the floor **on**, e5-large now answers every query in the top five
(overall hit@5 1.000, from 0.957); cross-lingual floor-on is unchanged at 0.938.

### The gap, which is the point

| | hashing-512 | e5-small | e5-large |
|---|---:|---:|---:|
| overall hit@5 | 0.851 | 0.936 | 0.936 |
| overall MRR | 0.713 | 0.870 | 0.871 |
| **cross-lingual hit@5** | **0.312** | **0.438** | **0.594** |
| cross-lingual MRR | 0.183 | 0.213 | 0.258 |
| cross-lingual hit@5, floor **on** | 0.562 | 0.719 | 0.938 |
| misses at k=5 | 7 | 3 | 3 |

**e5 does beat the fallback, on exactly the axis it was chosen for.**
Cross-lingual hit@5 goes from 0.312 to 0.594, roughly double. Before the
chunking fix the same comparison was 0.188 to 0.562, roughly triple — the gap
narrowed because the fix helped the lexical fallback more than it helped the
model, not because e5 got worse.

**Large is no longer uniformly behind small on the overall figures.** The two now
tie on overall hit@1 (0.830) and hit@5 (0.936) and are within a thousandth on MRR
(0.871 against 0.870); small is ahead on overall hit@3 (0.915 against 0.894), and
large is well ahead cross-lingually (0.594 against 0.438). They miss the same
number of queries, three, though not the same ones. Before the fix large lost on
overall hit@5 and missed one more query than small; that is no longer true. An
earlier version of this note, written before large could be run, called small's
0.438 "a lower bound" on the default configuration. For cross-lingual hit@5 it
was; as a general statement it was not.

**And cross-lingual is still only about six in ten at k=5.** A query finds the
answer sitting in the other language 59% of the time with large, and at rank 1
fewer than one time in ten — cross-lingual hit@1 did not move at all. Switching
the per-language floor on takes hit@5 to 0.938, which is what the operator
receives, but floor-on hit@5 measures a guarantee rather than ranking. Over the
fallback, the model now contributes +0.282 and the floor a further +0.344; the
model contributes real cross-lingual signal and the floor is still what makes the
guarantee.

With 32 cross-lingual queries, the difference between 0.562 and 0.594 is one
query. Nothing in this section has been tested for significance, and most of the
movement in this iteration is of that size.

> **Not re-measured after the chunking fix.** The two subsections below — the
> asymmetry between query directions, and the same-language-preference analysis —
> were measured on the pre-fix chunking and have not been re-run. Chunk
> boundaries moved underneath them, so treat their figures as describing the
> earlier configuration. The per-direction split needs the `--json` report rather
> than the table above, and re-deriving it was not part of this change.

**The two directions are not symmetric.** Split by query language (e5-large,
floor off, *pre-fix chunking*), English queries find the Japanese answer in the
top five in 6 of 20 cases (0.300) and Japanese queries find the English answer in
12 of 12 (1.000); at rank 1 it is 0 of 20 and 3 of 12. Part of that is corpus
composition rather than the model: an English query competes with 42 English
documents for five slots, a Japanese query with five Japanese ones. The overall
0.929 hit@1 for Japanese queries is mostly same-language hits and says nothing
about this.

### Why cross-lingual is weak: a same-language preference, not the score band

This section used to blame e5's narrow score band, and that was wrong. The band is
real — every query–document score fell between 0.789 and 0.923 with small and
between 0.764 and 0.917 with large, 90% of them inside a window about 0.06 wide —
but it is by design: the
[model card](https://huggingface.co/intfloat/multilingual-e5-small) attributes
it to the 0.01 temperature of the contrastive loss, and ranking depends only on
the order of the scores, which a narrow band does not change. It also quoted
three scores (0.8254 / 0.8170 / 0.8153) that a re-run on the committed code does
not reproduce, so they are withdrawn.

The measurement that does explain it uses a property of the query set. Twenty-four
queries have a relevant document in each language — typically the English
technique note and the Japanese advisory on the same attack. Wherever both were
retrieved, score them against the same query (floor off, best child chunk per
document):

| | e5-small | e5-large |
|---|---:|---:|
| queries with both relevant documents retrieved (of 24) | 17 | 22 |
| same-language document scores higher | 16 | **22** |
| — English queries | 9 of 10 | 14 of 14 |
| — Japanese queries | 7 of 7 | 8 of 8 |
| mean gap | 0.034 | 0.031 |

The winner flips with the language of the query: for the same pair of documents,
the English one wins English queries and the Japanese one wins Japanese queries.
That argues against the obvious confound — one document simply covering the topic
better — and points at a same-language preference in the embedding. On this scale
a 0.03 gap is large, about half the width of the middle 90% of all scores, so it
outweighs the topical differences that should decide the ranking. One English
query shows it at the margin with e5-small: *"how do I stop automated password
guessing against port 22 on an internet facing server"* puts the Japanese
brute-force advisory third at 0.8370, one ten-thousandth behind a 2002 OpenSSL
buffer overflow (0.8371).

Caveats, all of which cut against over-reading it: 22 pairs at most; the pairs
are conditioned on both documents being retrieved, and the queries where one was
not are excluded; the paired documents are topical counterparts, not
translations; relevance was judged by one person; and the Japanese side is five
synthetic documents. It is a hypothesis with evidence rather than a result, and
it is exactly the question a parallel test collection would settle.

The misses are informative rather than random. e5-small misses three:

* `q08` "an account I do not recognise was created with uid 0" — the persistence
  documents discuss SSH keys, systemd units and cron at length and account
  creation briefly, so the topic is genuinely thin in the corpus.
* `q14` "someone ran rm on /var/log and cleared the shell history" — the only
  answer is Japanese, and this is the hardest cross-lingual case in the set.
* `q46` nginx directory traversal asked in Japanese — the answer is a
  one-paragraph NVD record whose distinguishing words are all English product
  identifiers.

e5-large now misses three, all English queries, and all three — `q14`, `q19` and
`q20`, the last two about failed sudo attempts — have only a Japanese answer.
Large still fixes `q08` and `q46`, which small misses. Before the chunking fix it
also missed `q21`, a reverse shell launched from a sudo command line, which
retrieved the sudo CVEs instead of the persistence note; that one is now found,
and it is the only change to either miss list. The remaining three are the
same-language preference showing up in the miss list, and they are the cases a
better Japanese corpus would address before a better model would.

### What this run does *not* establish

**The chunking defect is fixed, and the margin that replaced it is thin.** No
chunk now exceeds the 512-token limit, but the longest is 497 of 512 and the
guarantee is empirical — see "The third character class" above. A larger corpus
can consume that headroom, and only `make tokenizer-check` would notice.

**Whether any of this movement is real.** The largest change to a headline figure
is e5-large's cross-lingual hit@5, 0.562 → 0.594, which is one query out of 32.
Overall hit@5 moved by one query too. Nothing here is tested for significance,
and a 47-query set judged by one person cannot support much.

**The two analyses above were not re-run** on the new chunk boundaries: the
per-direction asymmetry and the same-language-preference comparison both describe
the pre-fix configuration.

Also unmeasured: ChromaDB's approximate index (this used the exact
`LocalVectorStore`, so no recall was lost to ANN), any k above 5, and whether
chunk *size* rather than chunk correctness is what moved these numbers — the fix
changed the count from 93 to 126, and the rejected variant that took it to 174
was worse, which hints that size matters here but does not isolate it.
