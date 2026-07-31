"""Pseudonymisation of log data before it leaves the machine.

The project's privacy claim is that raw logs stay on the home server and only the
minimum needed for reasoning reaches a hosted model. This module is that claim's
implementation, so it is worth being precise about what it does and does not do.

**What is pseudonymised:** internal hostnames, local usernames, private and
link-local IP addresses, MAC addresses, and email addresses. Each is replaced
with a stable placeholder (``HOST_1``, ``USER_2``, ``IP_PRIVATE_1``) and the
mapping is held in memory only, never written to disk and never sent anywhere.
``restore`` reverses the substitution locally, so the operator reads a normal
alert while the model only ever saw placeholders.

**What is deliberately *not* pseudonymised:** the attacker's public IP address.
It is not the operator's personal data, it is the single most actionable field in
the whole alert, and masking it would make the LLM's remediation advice
unusable and break the Phase 4 firewall response. ``SENTINEL_ANONYMIZE_PUBLIC_IPS=1``
turns it on for anyone whose threat model differs.

**Detection strategy:** hostnames and usernames are matched from a *learned
vocabulary* — the exact host and user strings the Go ingestor already extracted —
not from a regex guessing at what looks like a username. Guessing at usernames in
prose produces both misses and absurd false positives ("Failed" as a username);
matching known values is exact. IPs, MACs, and emails are structural enough to
regex safely.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .schemas import LogEvent

# Private ranges, defined explicitly rather than via ipaddress.is_private.
#
# Python's is_private is much broader than Go's net.IP.IsPrivate: it also covers
# the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), carrier-grade NAT, benchmarking ranges, and more. The Go
# ingestor scores those as *public* and adds +8 to their risk score, so relying on
# is_private here would make the two halves of the system disagree about the same
# address — and would silently mask exactly the addresses used to represent
# attackers in documentation and test data. These lists mirror Go's definition.
_PRIVATE_V4 = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6 = (ipaddress.ip_network("fc00::/7"),)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

# Usernames that carry no personal information and are load-bearing for
# reasoning: masking "root" would make an escalation alert incomprehensible.
_GENERIC_USERS = frozenset(
    {
        "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
        "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody",
        "systemd-network", "systemd-resolve", "messagebus", "syslog", "sshd",
        "admin", "administrator", "test", "guest", "oracle", "ubuntu", "user",
        "postgres", "mysql", "ftp", "pi", "docker", "git",
    }
)


@dataclass
class Anonymizer:
    """Reversible pseudonymiser. Not thread-safe; use one per request."""

    enabled: bool = True
    anonymize_public_ips: bool = False
    _forward: dict[str, str] = field(default_factory=dict)
    _counters: dict[str, int] = field(default_factory=dict)
    _hosts: set[str] = field(default_factory=set)
    _users: set[str] = field(default_factory=set)

    # -- vocabulary --------------------------------------------------------

    def learn(self, events: Iterable[LogEvent]) -> Anonymizer:
        """Collect the host and user strings that appear in these events."""
        for ev in events:
            if ev.host:
                self._hosts.add(ev.host)
            if ev.user and ev.user.lower() not in _GENERIC_USERS:
                self._users.add(ev.user)
            target = ev.fields.get("target_user", "")
            if target and target.lower() not in _GENERIC_USERS:
                self._users.add(target)
        return self

    def learn_terms(self, hosts: Sequence[str] = (), users: Sequence[str] = ()) -> Anonymizer:
        self._hosts.update(h for h in hosts if h)
        self._users.update(u for u in users if u and u.lower() not in _GENERIC_USERS)
        return self

    # -- substitution ------------------------------------------------------

    def _placeholder(self, kind: str, value: str) -> str:
        existing = self._forward.get(value)
        if existing:
            return existing
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{kind}_{self._counters[kind]}"
        self._forward[value] = token
        return token

    def _ip_kind(self, text: str) -> str | None:
        """Classify an IP-looking string, returning None if it must not be masked."""
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return None
        if ip.is_loopback:
            return "IP_LOOPBACK"
        networks = _PRIVATE_V4 if ip.version == 4 else _PRIVATE_V6
        if ip.is_link_local or any(ip in net for net in networks):
            return "IP_PRIVATE"
        return "IP_PUBLIC" if self.anonymize_public_ips else None

    def scrub(self, text: str) -> str:
        """Replace sensitive values in ``text`` with stable placeholders."""
        if not self.enabled or not text:
            return text

        # Emails first: they contain substrings that the host and IP passes would
        # otherwise chew into pieces, producing un-restorable fragments.
        text = _EMAIL_RE.sub(lambda m: self._placeholder("EMAIL", m.group(0)), text)
        text = _MAC_RE.sub(lambda m: self._placeholder("MAC", m.group(0)), text)

        def sub_ip(match: re.Match[str]) -> str:
            value = match.group(0)
            kind = self._ip_kind(value)
            return self._placeholder(kind, value) if kind else value

        text = _IPV4_RE.sub(sub_ip, text)
        text = _IPV6_RE.sub(sub_ip, text)

        # Longest first, so "sentinel-server" is not partially replaced by a rule
        # for "sentinel", which would leave "HOST_1-server" in the output.
        for host in sorted(self._hosts, key=len, reverse=True):
            if host in text:
                text = text.replace(host, self._placeholder("HOST", host))
        for user in sorted(self._users, key=len, reverse=True):
            # Word-bounded: a username like "al" must not rewrite "already".
            pattern = re.compile(rf"(?<![\w.-]){re.escape(user)}(?![\w.-])")
            if pattern.search(text):
                text = pattern.sub(self._placeholder("USER", user), text)
        return text

    def restore(self, text: str) -> str:
        """Reverse ``scrub``, so the operator sees real values locally."""
        if not self.enabled or not text:
            return text
        # Longest placeholder first: replacing USER_1 before USER_10 would leave
        # a stray "0" behind.
        for value, token in sorted(self._forward.items(), key=lambda kv: len(kv[1]), reverse=True):
            text = text.replace(token, value)
        return text

    def scrub_all(self, texts: Sequence[str]) -> list[str]:
        return [self.scrub(t) for t in texts]

    @property
    def mapping(self) -> dict[str, str]:
        """placeholder -> real value. In-memory only; never persisted."""
        return {token: value for value, token in self._forward.items()}

    @property
    def substitutions(self) -> int:
        return len(self._forward)

    def summary(self) -> dict[str, object]:
        by_kind: dict[str, int] = {}
        for token in self._forward.values():
            kind = token.rsplit("_", 1)[0]
            by_kind[kind] = by_kind.get(kind, 0) + 1
        return {
            "enabled": self.enabled,
            "public_ips_masked": self.anonymize_public_ips,
            "substitutions": len(self._forward),
            "by_kind": by_kind,
        }
