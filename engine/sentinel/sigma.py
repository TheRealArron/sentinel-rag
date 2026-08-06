"""Sigma → Sentinel rule transpiler.

Sigma is the industry's portable detection format. This reads the SSH/syslog
subset and emits the JSON rule bundle the Go ingestor hot-loads, so a rule from
the community repo becomes a Sentinel detection without a recompile.

Two decisions shape everything here; see docs/design/sigma.md.

*   It compiles to a **predicate tree**, not a flattened regex. Sigma's `and`,
    `or`, `not` and `1 of` do not survive being mashed into one pattern, and a
    rule that silently means something other than what its author wrote is worse
    than no rule.
*   It **refuses** what it cannot translate faithfully. A partially-understood
    detection that still loads is the failure mode this design exists to avoid.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Sigma field name -> Sentinel event field. Case-insensitive on the Sigma side,
# because community rules are inconsistent about it.
FIELD_MAP: dict[str, str] = {
    # identity
    "user": "user", "username": "user", "targetusername": "user",
    "subjectusername": "user", "account": "user", "accountname": "user",
    # network
    "sourceip": "source_ip", "src_ip": "source_ip", "srcip": "source_ip",
    "ipaddress": "source_ip", "clientip": "source_ip",
    "destinationip": "dest_ip", "dst_ip": "dest_ip", "dstip": "dest_ip",
    "sourceport": "source_port", "src_port": "source_port",
    "destinationport": "dest_port", "dst_port": "dest_port",
    # process / command
    "image": "process", "processname": "process", "process": "process",
    "commandline": "command", "command": "command", "cmd": "command",
    "parentimage": "process",
    # host
    "computer": "host", "hostname": "host", "host": "host",
    # free text — where most syslog rules actually live
    "message": "message", "msg": "message", "keywords": "message",
    "data": "message", "rawdata": "message",
}

# Sentinel's own field names are accepted as input too. Without this, a rule
# written against `source_ip` — the name Sentinel emits, the name the dashboard
# shows, the name a local author would reach for — is refused as unmappable,
# while the refusal message unhelpfully lists `source_ip` among the known fields.
FIELD_MAP.update({canonical: canonical for canonical in set(FIELD_MAP.values())})

# Sigma value modifiers this transpiler understands.
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}
# ...and the ones it deliberately refuses rather than approximating.
REFUSED_MODIFIERS = {"base64offset", "windash", "utf16", "utf16le", "utf16be", "wide", "expand"}

# logsource combinations this subset covers.
SUPPORTED_PRODUCTS = {"linux", ""}
SUPPORTED_SERVICES = {
    "sshd", "ssh", "syslog", "auth", "authlog", "auditd", "sudo", "cron",
    "systemd", "modsecurity", "clamav", "guacamole", "vsftpd", "",
}

# ATT&CK technique -> (English, Japanese) tag pair. The Japanese half is what
# lets a Sigma rule's finding retrieve a JPCERT advisory; without it an imported
# rule is monolingual and the bilingual corpus may as well not exist.
ATTACK_TAGS: dict[str, tuple[str, str]] = {
    "t1110": ("brute-force", "ブルートフォース"),
    "t1110.001": ("password-guessing", "パスワード推測"),
    "t1110.003": ("password-spraying", "パスワードスプレー"),
    "t1078": ("valid-accounts", "正規アカウント"),
    "t1078.003": ("local-accounts", "ローカルアカウント"),
    "t1021.004": ("remote-ssh", "SSHリモートアクセス"),
    "t1059": ("command-execution", "コマンド実行"),
    "t1059.004": ("shell-execution", "シェル実行"),
    "t1068": ("privilege-escalation-exploit", "権限昇格の脆弱性"),
    "t1548": ("elevation-control", "昇格制御の回避"),
    "t1548.003": ("sudo-abuse", "sudoの悪用"),
    "t1543.002": ("systemd-service", "systemdサービス"),
    "t1053.003": ("cron", "定期実行"),
    "t1136": ("account-creation", "アカウント作成"),
    "t1136.001": ("local-account-creation", "ローカルアカウント作成"),
    "t1098": ("account-manipulation", "アカウント操作"),
    "t1098.004": ("ssh-key-persistence", "SSH鍵による永続化"),
    "t1070": ("indicator-removal", "痕跡の削除"),
    "t1070.002": ("log-tampering", "ログ改ざん"),
    "t1070.003": ("history-clearing", "履歴消去"),
    "t1562": ("defense-impairment", "防御機能の無効化"),
    "t1562.001": ("disable-tools", "セキュリティツールの無効化"),
    "t1105": ("ingress-tool-transfer", "ツールの持ち込み"),
    "t1496": ("resource-hijacking", "リソース不正利用"),
    "t1499": ("denial-of-service", "サービス妨害"),
    "t1595": ("active-scanning", "能動的スキャン"),
    "t1589": ("identity-gathering", "識別情報の収集"),
    "t1589.001": ("credential-gathering", "認証情報の収集"),
    "t1190": ("exploit-public-app", "公開アプリの脆弱性攻撃"),
    "t1046": ("network-service-discovery", "ネットワークサービス探索"),
    "t1087": ("account-discovery", "アカウント探索"),
    "t1087.001": ("local-account-discovery", "ローカルアカウント探索"),
    "t1083": ("file-discovery", "ファイル探索"),
    "t1211": ("defense-evasion-exploit", "防御回避の脆弱性"),
}

# Tactic tags (attack.credential_access etc.) -> Sentinel category + bilingual pair.
TACTIC_MAP: dict[str, tuple[str, str, str]] = {
    "credential_access": ("authentication", "credential-access", "認証情報アクセス"),
    "initial_access": ("authentication", "initial-access", "初期侵入"),
    "persistence": ("persistence", "persistence", "永続化"),
    "privilege_escalation": ("privilege-escalation", "privilege-escalation", "権限昇格"),
    "defense_evasion": ("defense-evasion", "defense-evasion", "防御回避"),
    "execution": ("execution", "execution", "実行"),
    "discovery": ("reconnaissance", "discovery", "探索"),
    "lateral_movement": ("authentication", "lateral-movement", "横展開"),
    "collection": ("impact", "collection", "情報収集"),
    "exfiltration": ("impact", "exfiltration", "情報持ち出し"),
    "impact": ("impact", "impact", "影響"),
    "command_and_control": ("execution", "command-and-control", "遠隔操作"),
    "reconnaissance": ("reconnaissance", "reconnaissance", "偵察"),
    "resource_development": ("reconnaissance", "resource-development", "リソース準備"),
}

# Sigma level -> Sentinel 0-100 score. Sigma levels are coarse; these land in the
# same bands the built-in rules use so imported and native rules stay comparable.
LEVEL_SCORE = {"informational": 15, "low": 35, "medium": 55, "high": 72, "critical": 88}


class SigmaError(Exception):
    """A rule this transpiler will not translate."""


class SigmaUnsupported(SigmaError):
    """Valid Sigma, outside the supported subset. Skipped, not fatal."""


@dataclass
class Predicate:
    """One node of the compiled matcher tree."""

    op: str                       # and | or | not | match
    children: list[Predicate] = field(default_factory=list)
    field_name: str = ""
    match_op: str = ""            # contains | equals | startswith | endswith | regex
    values: list[str] = field(default_factory=list)
    cased: bool = False

    def to_dict(self) -> dict[str, Any]:
        if self.op == "match":
            return {
                "op": "match", "field": self.field_name, "match": self.match_op,
                "values": list(self.values), "cased": self.cased,
            }
        return {"op": self.op, "children": [c.to_dict() for c in self.children]}


@dataclass
class SentinelRule:
    """A Sigma rule compiled into Sentinel's shape."""

    name: str
    title: str
    predicate: Predicate
    category: str = "uncategorised"
    score: int = 50
    outcome: str = "suspicious"
    mitre: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    source: str = ""
    sigma_id: str = ""
    level: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "category": self.category,
            "score": self.score,
            "outcome": self.outcome,
            "mitre": list(self.mitre),
            "tags": list(self.tags),
            "processes": list(self.processes),
            "source": self.source,
            "sigma_id": self.sigma_id,
            "level": self.level,
            "predicate": self.predicate.to_dict(),
        }


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #

def load_yaml(text: str) -> dict[str, Any]:
    """Parse a Sigma document.

    PyYAML when available. The fallback handles only the flat/nested-map subset
    Sigma actually uses and raises on anything else — a half-understood YAML
    parser silently mis-reading a detection is exactly the outcome to avoid.
    """
    try:
        import yaml
    except ImportError:
        return _minimal_yaml(text)
    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    if not docs:
        raise SigmaError("no YAML document found")
    if len(docs) > 1:
        # Sigma collections: the first doc is the rule, the rest are derivations.
        raise SigmaUnsupported("multi-document Sigma collections are not supported")
    return docs[0]


def _minimal_yaml(text: str) -> dict[str, Any]:
    """Indentation-based parser for the Sigma subset, used only without PyYAML.

    Handles what Sigma rules actually contain: nested maps, block sequences,
    inline flow sequences, and folded/literal block scalars. Anything else
    raises — a half-understood YAML parser silently mis-reading a detection is
    the outcome to avoid.

    A container's type is not known when its key is read: ``tags:`` could open a
    map or a sequence, and only the first child line says which. So the key is
    recorded as pending and materialised when that line arrives.
    """
    root: dict[str, Any] = {}
    # Each frame is (indent, container). A container is a dict, a list, or a
    # _Pending standing in for one whose type is not yet known.
    stack: list[tuple[int, Any]] = [(-1, root)]

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()

        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]

        if isinstance(parent, _Pending):
            parent = parent.resolve(list if line.startswith("- ") else dict)
            stack[-1] = (stack[-1][0], parent)

        if line.startswith("- ") or line == "-":
            if not isinstance(parent, list):
                raise SigmaError(f"list item outside a list: {line!r}")
            parent.append(_scalar(line[2:]) if len(line) > 2 else None)
            continue

        if ":" not in line:
            raise SigmaError(f"cannot parse line: {line!r}")
        if not isinstance(parent, dict):
            raise SigmaError(f"mapping key inside a sequence: {line!r}")

        key, _, rest = line.partition(":")
        key, rest = key.strip(), rest.strip()

        if rest in {"|", ">", "|-", ">-", "|+", ">+"}:
            block, i = _block_scalar(lines, i, indent)
            parent[key] = block if rest[0] == "|" else " ".join(block.split())
            continue

        if rest:
            parent[key] = _scalar(rest)
            continue

        pending = _Pending(parent, key)
        parent[key] = None
        stack.append((indent, pending))

    return root


class _Pending:
    """A container whose type is decided by its first child line."""

    __slots__ = ("parent", "key")

    def __init__(self, parent: dict[str, Any], key: str) -> None:
        self.parent = parent
        self.key = key

    def resolve(self, kind: type) -> Any:
        container = kind()
        self.parent[self.key] = container
        return container


def _block_scalar(lines: list[str], start: int, parent_indent: int) -> tuple[str, int]:
    """Collect the body of a `|` or `>` block scalar, returning it and the next index."""
    body: list[str] = []
    i = start
    while i < len(lines):
        raw = lines[i]
        if raw.strip() and (len(raw) - len(raw.lstrip())) <= parent_indent:
            break
        body.append(raw.strip())
        i += 1
    while body and not body[-1]:
        body.pop()
    return "\n".join(body), i


def _scalar(text: str) -> Any:
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return [_scalar(p) for p in text[1:-1].split(",") if p.strip()]
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    low = text.lower()
    if low in {"true", "yes"}:
        return True
    if low in {"false", "no"}:
        return False
    if low in {"null", "~", ""}:
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


# --------------------------------------------------------------------------- #
# transpiling
# --------------------------------------------------------------------------- #

def _check_logsource(logsource: dict[str, Any], path: str) -> list[str]:
    """Validate the log source and return the process filter it implies."""
    product = str(logsource.get("product", "") or "").lower()
    service = str(logsource.get("service", "") or "").lower()
    category = str(logsource.get("category", "") or "").lower()

    if product and product not in SUPPORTED_PRODUCTS:
        raise SigmaUnsupported(
            f"logsource product {product!r} is outside the Linux/syslog subset "
            f"(Sentinel parses syslog, not {product} event logs)"
        )
    if service and service not in SUPPORTED_SERVICES:
        raise SigmaUnsupported(f"logsource service {service!r} is not in the supported subset")
    if category in {"process_creation", "network_connection", "file_event"} and not product:
        raise SigmaUnsupported(f"logsource category {category!r} needs a product to map safely")

    if service in {"sshd", "ssh"}:
        return ["sshd"]
    if service == "sudo":
        return ["sudo"]
    if service == "cron":
        return ["CRON", "cron", "crond"]
    if service == "systemd":
        return ["systemd"]
    if service == "auditd":
        return ["audit", "auditd"]
    return []


def _split_modifiers(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], [p.lower() for p in parts[1:]]


def _leaf(sigma_field: str, raw_value: Any, path: str) -> Predicate:
    """Compile one `Field|modifiers: value` entry."""
    name, modifiers = _split_modifiers(sigma_field)

    refused = set(modifiers) & REFUSED_MODIFIERS
    if refused:
        raise SigmaUnsupported(
            f"modifier(s) {sorted(refused)} change the encoding of the match; "
            f"translating them approximately would silently alter the detection"
        )
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaUnsupported(f"unknown modifier(s) {sorted(unknown)}")

    key = name.lower()
    target = FIELD_MAP.get(key)
    if target is None:
        raise SigmaUnsupported(
            f"field {name!r} has no Sentinel equivalent "
            f"(known: {', '.join(sorted(set(FIELD_MAP.values())))})"
        )

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    strings = [str(v) for v in values if v is not None]
    if not strings:
        raise SigmaError(f"field {name!r} has no values")

    if "re" in modifiers:
        for pattern in strings:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise SigmaError(f"invalid regex for {name!r}: {exc}") from exc
        match_op = "regex"
    elif "startswith" in modifiers:
        match_op = "startswith"
    elif "endswith" in modifiers:
        match_op = "endswith"
    elif "contains" in modifiers:
        match_op = "contains"
    else:
        # Sigma's bare form is equality, but on a free-text field (message,
        # command) equality against a whole syslog line never matches. Those
        # degrade to substring, which is what the rule author meant.
        match_op = "contains" if target in {"message", "command"} else "equals"

    # `all` means every value must match, not any. Represent it structurally
    # rather than as a flag, so the Go evaluator needs no special case.
    if "all" in modifiers:
        return Predicate(op="and", children=[
            Predicate(op="match", field_name=target, match_op=match_op,
                      values=[s], cased="cased" in modifiers)
            for s in strings
        ])

    return Predicate(op="match", field_name=target, match_op=match_op,
                     values=strings, cased="cased" in modifiers)


def _compile_selection(name: str, body: Any, path: str) -> Predicate:
    """Compile one named selection block."""
    # A bare list is Sigma's keyword form: match any of these anywhere in the line.
    if isinstance(body, list):
        if all(isinstance(item, dict) for item in body) and body:
            # List of maps = OR over each map.
            return Predicate(op="or", children=[
                _compile_selection(name, item, path) for item in body
            ])
        return Predicate(op="match", field_name="message", match_op="contains",
                         values=[str(v) for v in body if v is not None])

    if not isinstance(body, dict):
        raise SigmaError(f"selection {name!r} must be a map or list")

    # Fields within one selection are ANDed; values within a field are ORed.
    children = [_leaf(key, value, path) for key, value in body.items()]
    if not children:
        raise SigmaError(f"selection {name!r} is empty")
    return children[0] if len(children) == 1 else Predicate(op="and", children=children)


_COND_TOKEN = re.compile(r"\s+")


def _compile_condition(condition: str, selections: dict[str, Predicate], path: str) -> Predicate:
    """Compile Sigma's condition expression over the named selections.

    Supports: `and`, `or`, `not`, parentheses, `1 of x*`, `all of x*`,
    `1 of them`, `all of them`. Anything else is refused — Sigma's full grammar
    includes aggregations (`| count() > 5`) that are a different kind of
    detection entirely, and pretending to support them would be a lie.
    """
    text = condition.strip().lower()
    if "|" in text:
        raise SigmaUnsupported(
            "aggregation conditions (`| count()`, `| near`) describe stateful "
            "correlation, which is the correlator's job, not a per-line rule"
        )

    def expand(match: re.Match[str]) -> str:
        quantifier, pattern = match.group(1), match.group(2)
        if pattern == "them":
            names = list(selections)
        else:
            prefix = pattern.rstrip("*")
            names = [n for n in selections if n.startswith(prefix)]
        if not names:
            raise SigmaError(f"`{quantifier} of {pattern}` matched no selection")
        joiner = " or " if quantifier == "1" else " and "
        return "(" + joiner.join(names) + ")"

    text = re.sub(r"\b(1|all)\s+of\s+([\w*]+)", expand, text)

    tokens = _COND_TOKEN.split(text.replace("(", " ( ").replace(")", " ) ").strip())
    tokens = [t for t in tokens if t]
    pos = 0

    def parse_or() -> Predicate:
        nonlocal pos
        node = parse_and()
        while pos < len(tokens) and tokens[pos] == "or":
            pos += 1
            node = Predicate(op="or", children=[node, parse_and()])
        return node

    def parse_and() -> Predicate:
        nonlocal pos
        node = parse_not()
        while pos < len(tokens) and tokens[pos] == "and":
            pos += 1
            node = Predicate(op="and", children=[node, parse_not()])
        return node

    def parse_not() -> Predicate:
        nonlocal pos
        if pos < len(tokens) and tokens[pos] == "not":
            pos += 1
            return Predicate(op="not", children=[parse_not()])
        return parse_atom()

    def parse_atom() -> Predicate:
        nonlocal pos
        if pos >= len(tokens):
            raise SigmaError("unexpected end of condition")
        word = tokens[pos]
        if word == "(":
            pos += 1
            node = parse_or()
            if pos >= len(tokens) or tokens[pos] != ")":
                raise SigmaError("unbalanced parentheses in condition")
            pos += 1
            return node
        if word in {"and", "or", "not", ")"}:
            raise SigmaError(f"unexpected token {word!r} in condition")
        pos += 1
        if word not in selections:
            raise SigmaError(f"condition references unknown selection {word!r}")
        return selections[word]

    node = parse_or()
    if pos != len(tokens):
        raise SigmaError(f"trailing tokens in condition: {' '.join(tokens[pos:])}")
    return node


def _metadata(rule: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    """(category, MITRE ids, bilingual tags) from Sigma `tags`."""
    category = "uncategorised"
    mitre: list[str] = []
    tags: list[str] = []

    for raw in rule.get("tags", []) or []:
        tag = str(raw).lower().strip()
        if not tag.startswith("attack."):
            continue
        body = tag[len("attack."):]

        if re.fullmatch(r"t\d{4}(\.\d{3})?", body):
            mitre.append(body.upper())
            pair = ATTACK_TAGS.get(body)
            if pair:
                tags.extend(pair)
            continue
        mapped = TACTIC_MAP.get(body)
        if mapped:
            if category == "uncategorised":
                category = mapped[0]
            tags.extend(mapped[1:])

    # Deduplicate, order-preserving.
    seen: set[str] = set()
    tags = [t for t in tags if not (t in seen or seen.add(t))]
    mitre = list(dict.fromkeys(mitre))
    return category, mitre, tags


def _slug(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")
    return slug[:60] or "sigma_rule"


def transpile(document: dict[str, Any], source: str = "") -> SentinelRule:
    """Compile one parsed Sigma document into a Sentinel rule."""
    for required in ("title", "detection"):
        if required not in document:
            raise SigmaError(f"missing required field {required!r}")

    detection = document["detection"]
    if not isinstance(detection, dict):
        raise SigmaError("`detection` must be a map")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaUnsupported("`condition` must be a single string (lists are not supported)")

    processes = _check_logsource(document.get("logsource") or {}, source)

    selections = {
        name: _compile_selection(name, body, source)
        for name, body in detection.items()
        if name != "condition"
    }
    if not selections:
        raise SigmaError("detection has no selections")

    predicate = _compile_condition(condition, selections, source)
    category, mitre, tags = _metadata(document)
    level = str(document.get("level", "medium")).lower()

    tags.append("sigma")
    tags.append("シグマ")
    if category != "uncategorised":
        tags.append(category)

    return SentinelRule(
        name="sigma_" + _slug(document["title"]),
        title=str(document["title"]),
        predicate=predicate,
        category=category,
        score=LEVEL_SCORE.get(level, 50),
        outcome="suspicious",
        mitre=mitre,
        tags=tags,
        processes=processes,
        source=source,
        sigma_id=str(document.get("id", "")),
        level=level,
    )


# --------------------------------------------------------------------------- #
# bundle
# --------------------------------------------------------------------------- #

@dataclass
class CompileReport:
    rules: list[SentinelRule] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)   # (path, why)
    failed: list[tuple[str, str]] = field(default_factory=list)

    def to_bundle(self) -> dict[str, Any]:
        return {
            "version": 1,
            "generator": "sentinel sigma compile",
            "rules": [r.to_dict() for r in self.rules],
        }

    def summary(self) -> str:
        return (f"{len(self.rules)} compiled, {len(self.skipped)} skipped "
                f"(outside the subset), {len(self.failed)} failed")


def compile_file(path: Path) -> SentinelRule:
    return transpile(load_yaml(Path(path).read_text(encoding="utf-8")), source=Path(path).name)


def compile_directory(directory: Path) -> CompileReport:
    """Compile every .yml/.yaml under ``directory``.

    Unsupported rules are *skipped with a reason*, not silently dropped and not
    fatal: importing 40 community rules of which 6 use Windows event fields
    should give you 34 working detections and a list of what was left out.
    """
    report = CompileReport()
    directory = Path(directory)
    if not directory.exists():
        return report

    for path in sorted(directory.rglob("*.y*ml")):
        try:
            report.rules.append(compile_file(path))
        except SigmaUnsupported as exc:
            report.skipped.append((str(path.name), str(exc)))
        except (SigmaError, OSError, UnicodeDecodeError) as exc:
            report.failed.append((str(path.name), f"{type(exc).__name__}: {exc}"))
        except Exception as exc:  # noqa: BLE001 - a bad rule must not stop the batch
            report.failed.append((str(path.name), f"{type(exc).__name__}: {exc}"))
    return report


def write_bundle(report: CompileReport, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report.to_bundle(), ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def evaluate(predicate: dict[str, Any], event: dict[str, Any]) -> bool:
    """Reference evaluator, mirroring ingestor/internal/sigma.

    Exists so the two implementations can be tested against each other: a
    transpiler whose output the consumer interprets differently is worse than no
    transpiler.
    """
    op = predicate.get("op")
    if op == "and":
        return all(evaluate(c, event) for c in predicate.get("children", []))
    if op == "or":
        return any(evaluate(c, event) for c in predicate.get("children", []))
    if op == "not":
        children = predicate.get("children", [])
        return not evaluate(children[0], event) if children else False
    if op != "match":
        return False

    actual = str(event.get(predicate.get("field", ""), "") or "")
    cased = bool(predicate.get("cased"))
    haystack = actual if cased else actual.lower()
    match_op = predicate.get("match", "contains")

    for value in predicate.get("values", []):
        needle = str(value) if cased else str(value).lower()
        if match_op == "equals" and haystack == needle:
            return True
        if match_op == "contains" and needle in haystack:
            return True
        if match_op == "startswith" and haystack.startswith(needle):
            return True
        if match_op == "endswith" and haystack.endswith(needle):
            return True
        if match_op == "regex":
            flags = 0 if cased else re.IGNORECASE
            if re.search(str(value), actual, flags):
                return True
    return False
