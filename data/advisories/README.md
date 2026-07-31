# Threat-intelligence corpus

The bilingual corpus Sentinel retrieves against. Two directories, two languages,
one purpose: give the retriever a genuine cross-lingual test rather than a
translated copy of the same text.

```
advisories/
├── cve/       English — vulnerability advisories and technique notes
└── jpcert/    日本語 — Japanese-language advisories and 注意喚起
```

## Provenance — read this before citing anything here

**The English CVE documents describe real vulnerabilities and the technical
details are accurate** (identifiers, affected versions, mechanisms, mitigations).
They are written summaries, not verbatim copies of NVD or vendor text.

**The Japanese documents are representative sample documents**, written in the
house style of a JPCERT/CC 注意喚起 for this corpus. They are *not* copies of, and
do not claim to be, real JPCERT/CC publications — their `id` fields are prefixed
`sample-ja-` and their `publisher` field says so explicitly. They exist because
the cross-lingual retrieval claim needs Japanese security prose to be testable,
and redistributing real advisories verbatim is a licensing question this project
does not need to take on.

For a real deployment, replace this directory with your actual feed:

```bash
# JPCERT/CC publishes RSS for 注意喚起 and 脆弱性関連情報
# https://www.jpcert.or.jp/rss/jpcert.rdf
# NVD publishes a JSON API and bulk feeds
# https://nvd.nist.gov/developers/vulnerabilities
python -m sentinel index --rebuild
```

## Document format

Markdown with a small front-matter block:

```markdown
---
id: cve-2024-6387
title: "regreSSHion — unauthenticated RCE in OpenSSH server"
publisher: NVD / OpenSSH
published: 2024-07-01
lang: en
severity: critical
cve: CVE-2024-6387
mitre: [T1190, T1068]
keywords:
  - openssh
  - remote code execution
  - リモートコード実行
---

Body text…
```

Notes on the fields that matter to retrieval:

* **`keywords` are the bilingual lexical bridge.** They are folded into the
  indexed text, not just stored as metadata. Listing both `brute force` and
  `ブルートフォース` on a document lets it be retrieved from either language even
  when the embedding backend is the non-semantic fallback. Always give both.
* **`lang`** is optional — `sentinel.lang.detect_language` infers it from script
  ratios, and gets Japanese security prose right despite its heavy ASCII content.
  Set it explicitly for mixed-language documents.
* **`mitre`** ids are matched against the ids the Go ingestor attaches to events,
  so an advisory tagged `T1110.001` surfaces for a brute-force detection.

Any `*.md` file under this directory is indexed. `README.md` files are skipped.
