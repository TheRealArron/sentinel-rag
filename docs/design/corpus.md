# The corpus, and what the retrieval numbers actually show

## What was wrong with ten documents

`data/advisories` held ten hand-written files: five English CVE summaries and
five Japanese documents written in JPCERT/CC's house style for this repository.
The README was honest that the Japanese half was synthetic — their ids are
prefixed `sample-ja-` and their `publisher` field says so.

It was less clear about the consequence. At ten documents, `k=6` returns most of
the corpus. The hierarchical index, the parent-document retrieval and the
per-language floor are all correct mechanisms, and at that size they are
**indistinguishable from returning everything**. Neither of the two bugs recorded
in [retrieval.md](retrieval.md) was found by measurement, because there was no
measurement available to make.

## Licensing decides what can be committed

The two sources are not equally redistributable, and that difference — not
convenience — decides where each one lands.

**NVD is a work of the United States government and is in the public domain.**
NIST asks for attribution as a courtesy, not as a licence condition. So
`make feeds` writes to `data/advisories/nvd/` and 37 real CVE documents are
committed. A clean checkout now has a real English corpus covering the software
this tool actually watches: OpenSSH, sudo, OpenSSL, polkit, the kernel, nginx.

**JVN is © JPCERT/CC and IPA.** Their terms
(<https://www.jpcert.or.jp/guide.html>) draw a line worth quoting:

- 引用 (citation) is free, with the source name, document title and URL shown.
- 転載・再配布 (reproduction and redistribution) require **prior email
  coordination** with `office@jpcert.or.jp`, because parts of an advisory may be
  owned by a third-party copyright holder.

Committing fetched JVN text to a public MIT-licensed repository is
redistribution, not citation. So `make feeds-jvn` is a **separate target**, it
writes to a **gitignored** directory, and it prints the notice. Using the result
locally is ordinary use. Publishing it is a conversation with JPCERT/CC that a
build script cannot have on anyone's behalf.

`TestJVNIsNotRedistributed` enforces this rather than trusting the comment: it
fails if any committed advisory contains fetched JVN text, and if the fetch
target ever leaves `.gitignore`.

Two smaller decisions follow from the same reasoning. The RDF feed is parsed with
a regex rather than `xml.etree`, because both stdlib XML parsers are exposed to
entity-expansion attacks and this is a document fetched over the network. And
`--source` is required rather than defaulting to "all", so nobody pulls
non-redistributable content by accident.

## No invented bilingual keywords

Every document in the hand-written corpus carries a `keywords` list holding both
languages — `brute force` **and** `ブルートフォース` — which the indexer folds into
the indexed text. It is a deliberate lexical bridge under the semantic one, and
it works.

It also means a Japanese document in that corpus is retrievable by an English
query with **no cross-lingual understanding whatsoever**, because the English
string is sitting in the document. Fetched documents therefore get keywords only
where the source supplies them (CWE names), and nothing bilingual is invented.
That is what makes the claim testable instead of circular.

## The measurement, and what it says

Index a Japanese advisory in the shape a fetched JVN document takes — real
Japanese security prose, no keyword list — alongside twelve real NVD documents,
and run an English query. On the default zero-dependency backend:

| Corpus | Best Japanese score | Best English score |
|---|---:|---:|
| Japanese advisory with **no** keyword list | **0.0093** | 0.2032 |
| Same document **with** the bilingual keyword list | **0.3114** | 0.2032 |

Query: `"SSH brute force password guessing"`, `k=6`, `hashing-256` embedder,
`LocalVectorStore`.

Read off it:

**0.0093 is noise.** The hashing embedder is word unigrams plus character
3-grams. An English query and Japanese prose share almost no features — the
0.0093 is carried by the literal substring `SSH`. There is no cross-lingual
signal here, because there is no mechanism by which there could be.

**The Japanese document was still returned.** Not because it matched, but because
the per-language floor *reserves* a slot for it. That guarantee is real and it
holds regardless of backend — it would hold with a random projection.

**The keyword list is worth 33×.** Adding it takes the same document from 0.0093
to 0.3114, past the best English hit. On this backend, the bilingual behaviour
the demo shows is **entirely lexical**.

None of that contradicts the design. The floor is supposed to guarantee a
Japanese source; the keyword bridge is supposed to work when the model is
unavailable. What it does contradict is any reading of the existing test suite as
evidence for cross-lingual *understanding*. `test_per_language_floor_surfaces_
japanese_for_an_english_query` passes because of the floor, and it would pass if
the embedder were replaced with `random.random`.

**CI has never loaded `multilingual-e5-large`.** It runs deliberately without
`requirements.txt` — a good decision, and it keeps the zero-dependency path
honest — but it means the cross-lingual claim is the one thing in this repository
that the test suite does not touch. `tests/test_feeds.py` now pins the fallback's
behaviour so the suite cannot be mistaken for evidence it is not.

## What is still not measured

- ~~**Retrieval quality with the real model.**~~ Measured locally with both
  `multilingual-e5-small` and `multilingual-e5-large`: cross-lingual hit@5 of
  0.438 and 0.562, against the fallback's 0.188. See [retrieval.md](retrieval.md).
  CI still loads neither.
- ~~**Recall@k against ground truth.**~~ Built: 47 queries with one to three
  expected documents each, in `data/eval/retrieval.jsonl`. Method and results
  are in [retrieval.md](retrieval.md#recallk-the-numbers-and-how-the-query-set-avoids-being-circular).
- **Whether the fetched corpus improves alerts.** The advisories are real and
  relevant, but no experiment compares alert quality with and without them.
