"""Fetching a real advisory corpus, and the licensing that shapes how.

Until this existed, ``data/advisories`` held ten hand-written documents — five
English CVE summaries and five Japanese samples written in JPCERT/CC's house
style for this repository. The README was honest that the Japanese half was
synthetic. It was less clear about the consequence: at ten documents, ``k=6``
returns most of the corpus, so the hierarchical index, the per-language floor and
the parent-document retrieval are all *indistinguishable from returning
everything*. They are correct mechanisms with no evidence behind them.

This module fetches the real thing.

# The licensing is the design constraint, not a footnote

The two sources are not equally redistributable, and that difference decides what
may be committed to this repository.

**NVD is a work of the United States government and is in the public domain.**
NIST asks for attribution as a courtesy, not as a licence condition. Documents
derived from it are committed under ``data/advisories/nvd/`` and ship with the
repo, so a clean checkout has a real English corpus.

**JVN is copyright JPCERT/CC and IPA.** Their terms
(https://www.jpcert.or.jp/guide.html) draw a line this code has to respect:

* 引用 (citation) is free, with the source name, document title and URL shown.
* 転載・再配布 (reproduction and redistribution) requires **prior email
  coordination** with office@jpcert.or.jp, because third-party copyright holders
  may own parts of any given advisory.

Committing fetched JVN text to a public MIT-licensed repository is
redistribution. So this module fetches it to a **gitignored** directory, prints
the notice, and stops. Running the fetcher on your own machine for your own
monitoring is ordinary use; publishing the result is a conversation you have with
JPCERT/CC first, and it is not one a build script can have on your behalf.

That asymmetry is why ``--source`` is explicit rather than defaulting to "all".

# No invented bilingual keywords

The hand-written corpus gives every document a `keywords` list carrying both
languages (`brute force` / `ブルートフォース`), which the indexer folds into the
indexed text as a lexical bridge under the semantic one. It is a real mechanism
and it works.

It also means a Japanese document in that corpus is retrievable by an English
query *without any cross-lingual understanding at all* — the English string is
right there in the document. Fetched documents therefore get keywords only where
the source supplies them (CWE names, vendor, product). Nothing bilingual is
invented. That is what makes the retrieval claim testable rather than circular;
see ``tests/test_feeds.py``.
"""

from __future__ import annotations

import json
import re
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
JVN_RDF = "https://jvn.jp/rss/jvn.rdf"

USER_AGENT = "sentinel-rag/1.0 (+https://github.com/TheRealArron/sentinel-rag)"

# Both endpoints are read-only public feeds and neither needs a key for the
# volumes here. NVD rate-limits unauthenticated callers to 5 requests per rolling
# 30 seconds, which one page-of-2000 request does not come near.
HTTP_TIMEOUT = 30

# The API returns a bare 404 for a wider window rather than an error message.
NVD_MAX_WINDOW_DAYS = 120

JPCERT_REDISTRIBUTION_NOTICE = """\
JVN content is © JPCERT/CC and IPA.

  Citation (引用) is free with attribution: source name, document title, URL.
  Reproduction and redistribution (転載・再配布) require PRIOR email
  coordination with office@jpcert.or.jp — parts of an advisory may be owned by
  a third-party copyright holder.
  https://www.jpcert.or.jp/guide.html

Fetched documents are written to a gitignored directory. Using them locally is
ordinary use. Publishing or redistributing them is not something this tool can
authorise for you: contact JPCERT/CC first."""


class FeedError(RuntimeError):
    """A feed could not be fetched or understood."""


@dataclass
class Advisory:
    """One normalised advisory, ready to be written as front-matter markdown."""

    id: str
    title: str
    publisher: str
    published: str
    lang: str
    body: str
    source_url: str
    severity: str = ""
    cve: str = ""
    keywords: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = ["---", f"id: {self.id}", f'title: "{_escape(self.title)}"',
                 f'publisher: "{_escape(self.publisher)}"', f"published: {self.published}",
                 f"lang: {self.lang}"]
        if self.severity:
            lines.append(f"severity: {self.severity}")
        if self.cve:
            lines.append(f"cve: {self.cve}")
        lines.append(f"source_url: {self.source_url}")
        if self.keywords:
            lines.append("keywords:")
            lines.extend(f"  - {k}" for k in self.keywords)
        lines += ["---", "", self.body.rstrip(), ""]
        return "\n".join(lines)

    def filename(self) -> str:
        return f"{_slug(self.id)}.md"


# --------------------------------------------------------------------------- #
# transport
# --------------------------------------------------------------------------- #

def _get(url: str) -> bytes:
    """One GET, standard library only.

    `urllib` rather than `requests` for the same reason `local_llm.py` uses it:
    the engine must work on a clean checkout with nothing pip-installed, and
    pulling in an HTTP client to fetch two public feeds would make the corpus
    depend on PyPI being reachable.
    """
    # Pin the scheme rather than suppressing the warning. urllib happily opens
    # file: and ftp: URLs, so a fetcher that accepts an arbitrary string is a
    # local-file read waiting to be pointed somewhere interesting. Today the only
    # callers pass module constants; this keeps that true when they stop.
    if not url.startswith("https://"):
        raise FeedError(f"refusing to fetch a non-HTTPS URL: {url!r}")

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310 - scheme checked above
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as exc:
        raise FeedError(f"{url} returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise FeedError(f"{url} unreachable: {exc}") from exc


# --------------------------------------------------------------------------- #
# NVD (public domain)
# --------------------------------------------------------------------------- #

def fetch_nvd(days: int = 30, limit: int = 40, keyword: str = "") -> list[Advisory]:
    """Recent CVEs from the NVD 2.0 API.

    ``keyword`` narrows the pull to a product area. The default is a plain
    recency window, which is what a host operator actually wants: what is new.
    """
    params = {"resultsPerPage": str(min(2000, max(1, limit)))}
    if keyword:
        params["keywordSearch"] = keyword

    # NVD rejects a publication window wider than 120 days with a bare 404 — no
    # message, no error body — which reads as "endpoint gone" rather than
    # "argument out of range". Checked here so the failure names the cause.
    #
    # days <= 0 omits the window entirely, which the API allows and which is what
    # a keyword search wants: "every OpenSSH CVE", not "OpenSSH CVEs from the
    # last month", where the last month usually has none.
    if days > NVD_MAX_WINDOW_DAYS:
        raise FeedError(
            f"NVD accepts a publication window of at most {NVD_MAX_WINDOW_DAYS} days "
            f"(asked for {days}). Use --days 0 with --keyword to search without a window."
        )
    if days > 0:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
    payload = _get(f"{NVD_API}?{urllib.parse.urlencode(params)}")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise FeedError(f"NVD returned malformed JSON: {exc}") from exc

    advisories: list[Advisory] = []
    for entry in data.get("vulnerabilities", [])[:limit]:
        advisory = _nvd_advisory(entry.get("cve", {}))
        if advisory is not None:
            advisories.append(advisory)
    return advisories


def _nvd_advisory(cve: dict) -> Advisory | None:
    cve_id = cve.get("id", "")
    if not cve_id:
        return None
    description = ""
    for item in cve.get("descriptions", []):
        if item.get("lang") == "en":
            description = item.get("value", "").strip()
            break
    if not description:
        return None

    severity, score = _nvd_severity(cve.get("metrics", {}))
    weaknesses = _nvd_weaknesses(cve)
    references = [
        r.get("url", "") for r in cve.get("references", []) if r.get("url")
    ][:6]

    body_parts = ["## Description", "", description, ""]
    if weaknesses:
        body_parts += ["## Weakness", "", ", ".join(weaknesses), ""]
    if score:
        body_parts += ["## Severity", "", f"CVSS base score {score} ({severity or 'unrated'}).", ""]
    if references:
        body_parts += ["## References", ""] + [f"- {u}" for u in references] + [""]
    body_parts += [
        "## Provenance", "",
        "Derived from the National Vulnerability Database, a work of the United States",
        "government in the public domain. Retrieved via the NVD 2.0 API.",
    ]

    # Keywords come only from what NVD supplies: CWE names. Nothing bilingual is
    # invented — see this module's docstring.
    keywords = [w.lower() for w in weaknesses if w and not w.startswith("NVD-CWE")]

    return Advisory(
        id=cve_id.lower(),
        title=f"{cve_id} — {_headline(description)}",
        publisher="NVD (public domain)",
        published=(cve.get("published", "") or "")[:10],
        lang="en",
        body="\n".join(body_parts),
        source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        severity=(severity or "").lower(),
        cve=cve_id,
        keywords=keywords,
    )


def _nvd_severity(metrics: dict) -> tuple[str, float | None]:
    """Highest-priority CVSS metric present.

    The metrics block is a grab-bag whose shape varies by CVE — v3.1, v4.0, v2,
    and non-CVSS entries such as `ssvcV203` that carry no `cvssData` at all. A
    naive `metrics[k][0]["cvssData"]` raises KeyError on those, so each candidate
    is checked rather than assumed.
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []):
            data = entry.get("cvssData")
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entry.get("baseSeverity") or ""
            if score is not None:
                return str(severity), float(score)
    return "", None


def _nvd_weaknesses(cve: dict) -> list[str]:
    out: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for item in weakness.get("description", []):
            value = item.get("value", "").strip()
            if value and value not in out:
                out.append(value)
    return out


# --------------------------------------------------------------------------- #
# JVN (© JPCERT/CC and IPA — fetch, do not redistribute)
# --------------------------------------------------------------------------- #

_ITEM_RE = re.compile(r"<item\s+rdf:about=\"(?P<url>[^\"]+)\">(?P<body>.*?)</item>", re.DOTALL)


def fetch_jvn(limit: int = 40) -> list[Advisory]:
    """Recent entries from the JVN RDF feed.

    The feed carries a Japanese title and summary per entry. That is real
    Japanese security prose written by Japanese security engineers, which is
    exactly what the cross-lingual retrieval claim needs and what a corpus
    written for this repository cannot honestly supply.

    The RDF is parsed with a regex rather than an XML parser, deliberately:
    `xml.etree` and `xml.dom` are both exposed to entity-expansion attacks on
    untrusted XML, and this is a document fetched over the network. A regex over
    a two-tag structure cannot be made to allocate a gigabyte.
    """
    payload = _get(JVN_RDF).decode("utf-8", errors="replace")
    advisories: list[Advisory] = []
    for match in _ITEM_RE.finditer(payload):
        if len(advisories) >= limit:
            break
        body = match.group("body")
        title = _tag(body, "title")
        summary = _tag(body, "description")
        identifier = _tag(body, "dc:identifier") or _id_from_url(match.group("url"))
        if not title or not identifier:
            continue
        advisories.append(Advisory(
            id=identifier.lower(),
            title=title,
            publisher="JVN (JPCERT/CC and IPA) — 引用元を明記のこと",
            published=(_tag(body, "dc:date") or "")[:10],
            lang="ja",
            body="\n".join([
                "## 概要", "", summary or title, "",
                "## 出典", "",
                f"JVN: {match.group('url')}",
                "",
                "本文書は JVN（JPCERT/CC・IPA）の公開情報を引用したものです。",
                "転載・再配布には JPCERT/CC 広報（office@jpcert.or.jp）への事前連絡が必要です。",
            ]),
            source_url=match.group("url"),
            # No keywords at all. JVN supplies none, and inventing an English
            # keyword list here would smuggle the answer into the document and
            # make cross-lingual retrieval untestable.
            keywords=[],
        ))
    return advisories


def _tag(body: str, name: str) -> str:
    match = re.search(rf"<{re.escape(name)}[^>]*>(.*?)</{re.escape(name)}>", body, re.DOTALL)
    if not match:
        return ""
    text = re.sub(r"<[^>]+>", "", match.group(1))
    text = (text.replace("&lt;", "<").replace("&gt;", ">")
                .replace("&quot;", '"').replace("&#39;", "'").replace("&amp;", "&"))
    return re.sub(r"\s+", " ", text).strip()


def _id_from_url(url: str) -> str:
    match = re.search(r"(JVN[A-Z]*[-\d]+)", url)
    return match.group(1) if match else ""


# --------------------------------------------------------------------------- #
# writing
# --------------------------------------------------------------------------- #

def write_advisories(advisories: list[Advisory], out_dir: Path) -> list[Path]:
    """Write each advisory as front-matter markdown. Returns the paths written."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for advisory in advisories:
        path = out_dir / advisory.filename()
        path.write_text(advisory.to_markdown(), encoding="utf-8")
        written.append(path)
    return written


def _escape(text: str) -> str:
    return text.replace('"', "'").replace("\n", " ").strip()


def _headline(description: str) -> str:
    """A short title from the first sentence.

    Kernel CVE descriptions open with a fixed preamble and often run for a
    paragraph before the first full stop, so a sentence split alone yields a
    title longer than the document. Cut on a word boundary as well.
    """
    text = _escape(description.strip())
    text = re.sub(r"^In the Linux kernel, the following vulnerability has been resolved:\s*", "", text)
    first = re.split(r"(?<=[.!?])\s", text)[0]
    if len(first) <= 96:
        return first
    return first[:96].rsplit(" ", 1)[0] + "…"


def _slug(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return (text or "advisory").lower()[:80]


__all__ = [
    "Advisory", "FeedError", "JPCERT_REDISTRIBUTION_NOTICE",
    "fetch_nvd", "fetch_jvn", "write_advisories",
]
