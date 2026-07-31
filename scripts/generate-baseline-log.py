#!/usr/bin/env python3
"""Generate a week of routine syslog, so Shadow Search has a baseline to be
surprised against.

Anomaly detection needs history. The committed `sample_syslog.log` is five
minutes of intrusion with no "before", which makes every value in it novel and
every finding meaningless — the exact failure mode `shadow_min_baseline` exists
to refuse. This produces the boring week that has to precede it.

    python3 scripts/generate-baseline-log.py --days 7 --out data/samples/baseline.log
    cat data/samples/baseline.log data/samples/sample_syslog.log > /tmp/full.log
    ./ingestor/bin/sentinel-ingestor -in /tmp/full.log -out data/events.jsonl
    python -m sentinel shadow

Or just: make shadow-demo

The output is SYNTHETIC and deliberately boring: a fixed cast of users, hosts,
and jobs behaving on a daily rhythm, with the low-grade internet background noise
any exposed host sees. It is not a capture of real traffic and is not committed —
it is regenerated on demand, seeded for reproducibility.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

# A small, stable cast. Shadow Search's job is to notice departures from this, so
# the set has to be genuinely narrow — a baseline containing everything makes
# nothing surprising.
USERS = ["arron", "deploy"]
CRON_JOBS = [
    "/usr/bin/certbot renew --quiet",
    "/usr/lib/sysstat/debian-sa1 1 1",
    "/usr/bin/find /var/tmp -type f -mtime +7 -delete",
]
# Opportunistic scanners: high volume, low interest. Present so that the
# brute-force campaign in the sample log is a *rate* anomaly rather than a novel
# one, which is the more realistic and harder case.
SCANNER_USERS = ["admin", "test", "ubuntu", "user", "oracle", "postgres", "git"]


def octet(rng: random.Random) -> str:
    return f"{rng.randint(1, 254)}"


def scanner_ip(rng: random.Random) -> str:
    # RFC 5737 documentation ranges, so nothing here resolves to a real host.
    return rng.choice([f"198.51.100.{octet(rng)}", f"192.0.2.{octet(rng)}"])


def generate(days: int, seed: int, end: datetime) -> list[tuple[datetime, str]]:
    rng = random.Random(seed)
    lines: list[tuple[datetime, str]] = []
    start = end - timedelta(days=days)

    def at(when: datetime, text: str) -> None:
        if when < end:
            lines.append((when, text))

    day = start.replace(hour=0, minute=0, second=0, microsecond=0)
    while day < end:
        # --- cron: the metronome of a healthy host ---------------------------
        for hour in range(0, 24, 6):
            for job in CRON_JOBS:
                when = day.replace(hour=hour, minute=rng.randint(0, 5), second=rng.randint(0, 59))
                at(when, f"CRON[{rng.randint(1000, 9999)}]: (root) CMD ({job})")

        # --- the operator's working day: logins clustered 09:00-18:00 --------
        # This rhythm is the point. A login at 04:00 is only anomalous because
        # the baseline establishes that logins happen during office hours.
        for _ in range(rng.randint(2, 5)):
            user = rng.choice(USERS)
            when = day.replace(hour=rng.randint(9, 18), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            pid = rng.randint(2000, 9000)
            at(when, f"sshd[{pid}]: Accepted publickey for {user} from 192.168.1.{rng.randint(10, 40)} "
                     f"port {rng.randint(40000, 60000)} ssh2: ED25519 SHA256:{'x' * 12}")
            at(when + timedelta(seconds=1),
               f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user} by (uid=0)")
            at(when + timedelta(minutes=rng.randint(5, 90)),
               f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}")

        # --- routine sudo, by the people who normally use it -----------------
        for _ in range(rng.randint(1, 4)):
            when = day.replace(hour=rng.randint(9, 18), minute=rng.randint(0, 59), second=rng.randint(0, 59))
            at(when, f"sudo[{rng.randint(3000, 9000)}]: {rng.choice(USERS)} : TTY=pts/0 ; PWD=/home ; "
                     f"USER=root ; COMMAND={rng.choice(['/usr/bin/apt-get update', '/bin/systemctl status ssh', '/usr/bin/journalctl -u ssh'])}")

        # --- internet background radiation: constant, ignorable --------------
        for _ in range(rng.randint(25, 60)):
            when = day + timedelta(seconds=rng.randint(0, 86399))
            ip = scanner_ip(rng)
            if rng.random() < 0.55:
                at(when, f"sshd[{rng.randint(1000, 9999)}]: Failed password for invalid user "
                         f"{rng.choice(SCANNER_USERS)} from {ip} port {rng.randint(40000, 60000)} ssh2")
            else:
                at(when, f"sshd[{rng.randint(1000, 9999)}]: Connection closed by {ip} "
                         f"port {rng.randint(40000, 60000)} [preauth]")

        # --- firewall drops --------------------------------------------------
        for _ in range(rng.randint(5, 20)):
            when = day + timedelta(seconds=rng.randint(0, 86399))
            at(when, f"kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff SRC={scanner_ip(rng)} "
                     f"DST=192.168.1.42 LEN=60 PROTO=TCP SPT={rng.randint(40000, 60000)} "
                     f"DPT={rng.choice([23, 3389, 445, 8080])} WINDOW=1024 SYN")

        # --- unattended upgrades, weekly ------------------------------------
        if day.weekday() == 6:
            when = day.replace(hour=6, minute=25)
            at(when, "systemd[1]: Starting Daily apt upgrade and clean activities...")
            at(when + timedelta(minutes=2), "systemd[1]: Finished Daily apt upgrade and clean activities.")

        day += timedelta(days=1)

    lines.sort(key=lambda pair: pair[0])
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=7, help="days of history to synthesise")
    ap.add_argument("--seed", type=int, default=20260730, help="RNG seed, for reproducibility")
    ap.add_argument("--out", default="-", help="output file, or - for stdout")
    ap.add_argument(
        "--end",
        default="2026-07-30T05:29:00",
        help="ISO timestamp the history runs up to; defaults to just before the sample intrusion",
    )
    args = ap.parse_args()

    end = datetime.fromisoformat(args.end)
    lines = generate(args.days, args.seed, end)
    # RFC 3164: "Jul  3" with a space-padded day, matching the sample log's format.
    rendered = "\n".join(
        f"{when.strftime('%b')} {when.day:2d} {when.strftime('%H:%M:%S')} sentinel {text}"
        for when, text in lines
    )

    if args.out == "-":
        print(rendered)
    else:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(f"wrote {len(lines)} lines covering {args.days} day(s) to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
