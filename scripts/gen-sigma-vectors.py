#!/usr/bin/env python3
"""Generate the Go/Python agreement vectors for the Sigma matcher.

The expected verdicts come from the Python reference evaluator, not from hand
authorship, so the file records what the transpiler's own semantics actually are.
The Go test then has to agree with them. Hand-written expectations would let a
mistake be written into both sides at once.

    python3 scripts/gen-sigma-vectors.py

Writes ingestor/internal/sigma/testdata/agreement.json. Re-run it after changing
the transpiler or adding a rule, and read the diff: a changed verdict is a
semantic change, and the diff is where you notice.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "engine"))

from sentinel.sigma import compile_directory, evaluate

OUT = REPO / "ingestor" / "internal" / "sigma" / "testdata" / "agreement.json"

# Hand-built cases covering each operator and each boolean form. These exist
# independently of the shipped rules so operator coverage does not silently
# regress when a rule is edited.
SYNTHETIC: list[tuple[str, dict, dict]] = [
    ("contains_hit",
     {"op": "match", "field": "message", "match": "contains",
      "values": ["Failed password"], "cased": False},
     {"message": "Failed password for root from 10.0.0.1"}),
    ("contains_miss",
     {"op": "match", "field": "message", "match": "contains",
      "values": ["Failed password"], "cased": False},
     {"message": "Accepted password for root"}),
    ("contains_case_folded",
     {"op": "match", "field": "message", "match": "contains",
      "values": ["FAILED PASSWORD"], "cased": False},
     {"message": "failed password for root"}),
    ("contains_case_sensitive_miss",
     {"op": "match", "field": "message", "match": "contains",
      "values": ["FAILED PASSWORD"], "cased": True},
     {"message": "failed password for root"}),
    ("equals_exact",
     {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     {"user": "root"}),
    ("equals_rejects_substring",
     {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     {"user": "rooted"}),
    ("startswith_hit",
     {"op": "match", "field": "command", "match": "startswith",
      "values": ["/etc/"], "cased": False},
     {"command": "/etc/shadow"}),
    ("startswith_miss",
     {"op": "match", "field": "command", "match": "startswith",
      "values": ["/etc/"], "cased": False},
     {"command": "/var/etc/shadow"}),
    ("endswith_hit",
     {"op": "match", "field": "command", "match": "endswith",
      "values": [".pem"], "cased": False},
     {"command": "/root/key.pem"}),
    ("endswith_miss",
     {"op": "match", "field": "command", "match": "endswith",
      "values": [".pem"], "cased": False},
     {"command": "/root/key.pem.bak"}),
    ("regex_hit",
     {"op": "match", "field": "message", "match": "regex",
      "values": [r"port \d+"], "cased": False},
     {"message": "from 10.0.0.1 port 22 ssh2"}),
    ("regex_miss",
     {"op": "match", "field": "message", "match": "regex",
      "values": [r"port \d+"], "cased": False},
     {"message": "from 10.0.0.1 port unknown"}),
    ("regex_case_folded",
     {"op": "match", "field": "message", "match": "regex",
      "values": ["FAILED"], "cased": False},
     {"message": "failed password"}),
    ("value_list_is_or",
     {"op": "match", "field": "message", "match": "contains",
      "values": ["nope", "yes"], "cased": False},
     {"message": "say yes"}),
    ("missing_field_never_matches",
     {"op": "match", "field": "command", "match": "contains", "values": ["x"], "cased": False},
     {"message": "no command field here"}),
    ("and_both_true",
     {"op": "and", "children": [
         {"op": "match", "field": "message", "match": "contains",
          "values": ["Failed"], "cased": False},
         {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     ]},
     {"message": "Failed password", "user": "root"}),
    ("and_one_false",
     {"op": "and", "children": [
         {"op": "match", "field": "message", "match": "contains",
          "values": ["Failed"], "cased": False},
         {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     ]},
     {"message": "Failed password", "user": "arron"}),
    ("or_one_true",
     {"op": "or", "children": [
         {"op": "match", "field": "message", "match": "contains",
          "values": ["nope"], "cased": False},
         {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     ]},
     {"message": "Failed password", "user": "root"}),
    ("or_all_false",
     {"op": "or", "children": [
         {"op": "match", "field": "message", "match": "contains",
          "values": ["nope"], "cased": False},
         {"op": "match", "field": "user", "match": "equals", "values": ["root"], "cased": False},
     ]},
     {"message": "Failed password", "user": "arron"}),
    ("not_excludes",
     {"op": "not", "children": [
         {"op": "match", "field": "source_ip", "match": "equals",
          "values": ["127.0.0.1"], "cased": False},
     ]},
     {"source_ip": "127.0.0.1"}),
    ("not_admits",
     {"op": "not", "children": [
         {"op": "match", "field": "source_ip", "match": "equals",
          "values": ["127.0.0.1"], "cased": False},
     ]},
     {"source_ip": "203.0.113.9"}),
    ("filtered_selection",
     {"op": "and", "children": [
         {"op": "match", "field": "message", "match": "contains",
          "values": ["Failed password"], "cased": False},
         {"op": "not", "children": [
             {"op": "match", "field": "source_ip", "match": "startswith",
              "values": ["10."], "cased": False},
         ]},
     ]},
     {"message": "Failed password for root", "source_ip": "10.0.0.5"}),
]

# Events replayed against every shipped rule, so the rules the repo actually
# ships are covered too — including the negative case for each.
RULE_EVENTS: list[dict[str, str]] = [
    {"message": "Failed password for invalid user oracle from 203.0.113.45 port 55021 ssh2",
     "user": "oracle", "source_ip": "203.0.113.45", "process": "sshd",
     "command": "Failed password for invalid user oracle from 203.0.113.45 port 55021 ssh2"},
    {"message": "Failed password for root from 127.0.0.1 port 22 ssh2",
     "user": "root", "source_ip": "127.0.0.1", "process": "sshd",
     "command": "Failed password for root from 127.0.0.1 port 22 ssh2"},
    {"message": "Accepted publickey for arron from 192.168.1.20 port 55022 ssh2",
     "user": "arron", "source_ip": "192.168.1.20", "process": "sshd",
     "command": "Accepted publickey for arron from 192.168.1.20 port 55022 ssh2"},
    {"message": "mallory : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash",
     "user": "mallory", "process": "sudo",
     "command": "mallory : user NOT in sudoers ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"},
    {"message": "echo ssh-rsa AAAAB3 attacker@evil >> /home/arron/.ssh/authorized_keys",
     "user": "arron", "process": "bash",
     "command": "echo ssh-rsa AAAAB3 attacker@evil >> /home/arron/.ssh/authorized_keys"},
    {"message": "cat /home/arron/.ssh/authorized_keys",
     "user": "arron", "process": "bash",
     "command": "cat /home/arron/.ssh/authorized_keys"},
]


def main() -> int:
    vectors: list[dict] = []

    for name, predicate, event in SYNTHETIC:
        vectors.append({
            "name": name,
            "predicate": predicate,
            "event": event,
            "want": evaluate(predicate, event),
        })

    report = compile_directory(REPO / "rules" / "sigma")
    for rule in report.rules:
        predicate = rule.predicate.to_dict()
        for i, event in enumerate(RULE_EVENTS):
            vectors.append({
                "name": f"{rule.name}__event{i}",
                "rule": rule.name,
                "predicate": predicate,
                "event": event,
                "want": evaluate(predicate, event),
            })

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(vectors, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    positive = sum(1 for v in vectors if v["want"])
    print(f"wrote {OUT.relative_to(REPO)}")
    print(f"  {len(vectors)} vectors — {positive} match, {len(vectors) - positive} non-match")
    print(f"  covering {len(report.rules)} shipped rule(s) plus {len(SYNTHETIC)} operator cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
