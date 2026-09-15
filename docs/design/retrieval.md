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

`lang.estimate_tokens` counts CJK code points as one token each and everything
else at four characters per token; the separator list includes `。`, `、`, `！`,
`？`.

### Measured against the real tokenizer

This section used to say *four times*, from a rule of thumb: one token per
Japanese character, four characters per English token. Neither half survives the
tokenizer multilingual-e5 actually uses (XLM-R's SentencePiece vocabulary).
Measured on this corpus:

| Text | chars / token | `estimate_tokens` ÷ real |
|---|---:|---:|
| English, hand-written summaries | 3.43 | 0.87 |
| English, NVD records | 2.97 | 0.74 |
| Japanese script only | 1.58 | 1.58 |
| Japanese documents, whole | 2.07 | 1.19 |

So a character budget sized for English holds about **2.2×** its tokens on
Japanese script, and 1.7× on whole Japanese documents, which carry ASCII
identifiers. That still justifies a script-aware splitter. It is half the figure
previously claimed.

The estimator errs in both directions. Overestimating Japanese is the safe one:
Japanese chunks come out smaller than budget. Underestimating English is not.
**9 of the 93 child chunks exceed e5's 512-token input limit** once the
`passage: ` prefix and the prepended title are counted — all English, the
largest at 824 tokens — and sentence-transformers truncates silently, so the
tail of those chunks is never embedded. The retrieval numbers below were measured
with that defect present. Fixing it changes chunk boundaries, and therefore every
number below, so it is recorded here rather than folded into this measurement.

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

### Results — dependency-free backend (`hashing-512`, `LocalVectorStore`)

| Slice | queries | hit@1 | hit@3 | hit@5 | MRR |
|---|---:|---:|---:|---:|---:|
| overall | 47 | 0.660 | 0.787 | **0.830** | 0.720 |
| **cross-lingual** | 32 | 0.062 | 0.156 | **0.188** | 0.112 |
| query lang = en | 33 | 0.697 | 0.788 | 0.818 | 0.740 |
| query lang = ja | 14 | 0.571 | 0.786 | 0.857 | 0.673 |
| origin = event | 32 | 0.625 | 0.750 | 0.812 | 0.688 |
| origin = software | 15 | 0.733 | 0.867 | 0.867 | 0.789 |

With the floor **on**, cross-lingual hit@5 goes from 0.188 to **0.656** — while
hit@1 and hit@3 do not move at all (0.062 and 0.156 in both runs).

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
| overall | 47 | 0.787 | 0.894 | **0.936** | 0.839 |
| **cross-lingual** | 32 | 0.125 | 0.250 | **0.438** | 0.212 |
| query lang = en | 33 | 0.758 | 0.879 | 0.939 | 0.822 |
| query lang = ja | 14 | 0.857 | 0.929 | 0.929 | 0.881 |
| origin = event | 32 | 0.750 | 0.875 | 0.938 | 0.816 |
| origin = software | 15 | 0.867 | 0.933 | 0.933 | 0.889 |

**multilingual-e5-large**

| Slice | queries | hit@1 | hit@3 | hit@5 | MRR |
|---|---:|---:|---:|---:|---:|
| overall | 47 | 0.830 | 0.872 | **0.915** | 0.858 |
| **cross-lingual** | 32 | 0.094 | 0.344 | **0.562** | 0.249 |
| query lang = en | 33 | 0.788 | 0.818 | 0.879 | 0.818 |
| query lang = ja | 14 | 0.929 | 1.000 | 1.000 | 0.952 |
| origin = event | 32 | 0.781 | 0.812 | 0.875 | 0.812 |
| origin = software | 15 | 0.933 | 1.000 | 1.000 | 0.956 |

### The gap, which is the point

| | hashing-512 | e5-small | e5-large |
|---|---:|---:|---:|
| overall hit@5 | 0.830 | 0.936 | 0.915 |
| overall MRR | 0.720 | 0.839 | 0.858 |
| **cross-lingual hit@5** | **0.188** | **0.438** | **0.562** |
| cross-lingual MRR | 0.112 | 0.212 | 0.249 |
| cross-lingual hit@5, floor **on** | 0.656 | 0.750 | 0.938 |
| misses at k=5 | 8 | 3 | 4 |

**e5 does beat the fallback, and by a lot on exactly the axis it was chosen
for.** Cross-lingual hit@5 roughly triples from the fallback to e5-large. That is
the claim in the README finally carrying evidence rather than an argument.

**Large is not uniformly better than small.** It is better cross-lingually
(0.562 against 0.438) and at the top of the overall ranking (hit@1 0.830 against
0.787, MRR 0.858 against 0.839), but overall hit@5 is lower, it misses one more
query, and cross-lingually at rank 1 it is *worse* (0.094 against 0.125). An
earlier version of this note, written before large could be run, called small's
0.438 "a lower bound" on the default configuration. For cross-lingual hit@5 it
was; as a general statement it was not.

**And cross-lingual is still only about half at k=5.** A query finds the answer
that sits in the other language 56% of the time with large, and at rank 1 fewer
than one time in ten. Switching the per-language floor on takes that to 0.938 —
what the operator receives, but floor-on hit@5 measures a guarantee, not ranking.
With e5-small the floor added more than the model did (+0.31 against +0.25 over
the fallback); with e5-large the two are the same size (+0.375 and +0.374). The
model contributes real cross-lingual signal, and the floor is still what makes
the guarantee.

With 32 cross-lingual queries, the difference between 0.438 and 0.562 is four
queries. Nothing in this section has been tested for significance.

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

e5-large misses four, all English queries, and three of them — `q14` again,
`q19` and `q20`, both about failed sudo attempts — have only a Japanese answer.
The fourth, `q21`, a reverse shell launched from sudo, retrieves the sudo CVEs
instead of the persistence note. Large fixes `q08` and `q46` and newly misses
`q19`, `q20` and `q21`; two of those three have only a Japanese answer, which is
the same-language preference showing up in the miss list.

### What this run does *not* establish

**The chunking defect above was present in both runs.** Nine of 93 child chunks
exceed the 512-token input limit both models share and are truncated when
embedded. Fixing the estimator changes chunk boundaries and would move every
number here.

Also unmeasured: ChromaDB's approximate index (this used the exact
`LocalVectorStore`, so no recall was lost to ANN), any k above 5, and whether
better chunking would move the cross-lingual number more cheaply than a bigger
model would.
