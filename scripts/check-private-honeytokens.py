#!/usr/bin/env python3
"""Refuse a deployment canary file that reuses the published demo canaries.

config/honeytokens.json is committed to a public repository. It is the demo
set: `make demo`, the sample fixture, the test suites and CI all depend on its
exact values. Those values are therefore known to anyone who has read the repo,
and a canary an attacker knows about is one they simply avoid.

A real host runs config/honeytokens.local.json instead (gitignored). This check
is what keeps that file honest. It fails when the file:

  - is missing                 (a deploy with no canaries must not look armed)
  - arms nothing               (an empty set is a silently disabled detector)
  - shares any value with the public set, compared case-insensitively, because
    the ingestor matches case-insensitively

Exit 0 when the file is private, 1 otherwise. Standard library only.

    python3 scripts/check-private-honeytokens.py [LOCAL] [PUBLIC]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LOCAL = ROOT / "config" / "honeytokens.local.json"
DEFAULT_PUBLIC = ROOT / "config" / "honeytokens.json"
KINDS = ("users", "paths", "hosts", "processes")


def load_values(path: Path) -> dict[str, set[str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TypeError(f"{path}: top level must be an object")
    out: dict[str, set[str]] = {}
    for kind in KINDS:
        values: set[str] = set()
        for entry in data.get(kind, []) or []:
            value = entry.get("value") if isinstance(entry, dict) else entry
            if isinstance(value, str) and value.strip():
                values.add(value.strip().lower())
        out[kind] = values
    return out


def main(argv: list[str]) -> int:
    local = Path(argv[1]) if len(argv) > 1 else DEFAULT_LOCAL
    public = Path(argv[2]) if len(argv) > 2 else DEFAULT_PUBLIC

    if not local.is_file():
        print(
            f"error: {local} does not exist.\n"
            f"  A real host needs its own canaries; the committed {public.name} is\n"
            "  public, so its values are known to anyone who reads the repository.\n"
            "  See config/README.md, 'Deploying: use your own canaries'.",
            file=sys.stderr,
        )
        return 1

    try:
        mine = load_values(local)
        published = load_values(public)
    except (OSError, TypeError, ValueError) as exc:  # JSONDecodeError is a ValueError
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not any(mine.values()):
        print(f"error: {local} arms no canaries", file=sys.stderr)
        return 1

    reused = sorted(
        f"{kind}: {value}" for kind in KINDS for value in mine[kind] & published[kind]
    )
    if reused:
        print(
            f"error: {local} reuses {len(reused)} published canary value(s):",
            file=sys.stderr,
        )
        for item in reused:
            print(f"  {item}", file=sys.stderr)
        print(
            f"  These are committed in {public.name} on a public repository. Replace them.",
            file=sys.stderr,
        )
        return 1

    total = sum(len(v) for v in mine.values())
    print(f"ok: {total} canary value(s) in {local.name}, none of them published")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
