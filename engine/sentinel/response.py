"""Phase 4: automated active response via UFW.

Letting a language model change a firewall is the most dangerous thing in this
repository, so the guard rails are the design, and the firewall call is an
afterthought:

*   **Dry-run is the default.** ``SENTINEL_RESPONSE_MODE`` must be set to
    ``enforce`` explicitly. A fresh deployment cannot block anything by accident.
*   **The allowlist wins, always.** Loopback and all RFC1918 ranges are allowlisted
    out of the box. A false positive that firewalls the operator out of their own
    home server is a worse outcome than the attack it was defending against, and
    unlike the attack it is self-inflicted.
*   **A score threshold, checked here.** The caller passes the deterministic score
    from the Go ingestor — not the model's opinion — and it must clear
    ``SENTINEL_RESPONSE_MIN_SCORE`` (default 90). Only correlated incidents reach
    that number, so a single failed password can never trigger a block.
*   **Rate limiting.** At most ``max_blocks_per_hour`` rules are added. A
    misfiring detection loop cannot fill the ruleset with thousands of entries.
*   **Every decision is audited,** including the refusals. The audit log is
    append-only JSONL and records the reason, the mode, and the exact argv.
*   **No shell.** ``subprocess.run`` with an argument list and ``shell=False``, so
    an address string that somehow reached here unvalidated still cannot become a
    command.
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings
from .schemas import utcnow_iso

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class ResponseAction:
    """The record of one response decision, taken or refused."""

    action: str
    target: str
    allowed: bool
    executed: bool
    mode: str
    reason: str
    detail: str = ""
    # The deterministic ingestor score behind the decision. Recorded so the
    # host-side responder can re-check the threshold itself instead of trusting
    # that the engine already did.
    score: int = -1
    command: list[str] = field(default_factory=list)
    at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "allowed": self.allowed,
            "executed": self.executed,
            "mode": self.mode,
            "reason": self.reason,
            "detail": self.detail,
            "score": self.score,
            "command": list(self.command),
            "at": self.at,
        }


class Responder:
    """UFW-backed active response with layered safety checks."""

    def __init__(self, settings: Settings, max_blocks_per_hour: int = 20) -> None:
        self.settings = settings
        self.max_blocks_per_hour = max_blocks_per_hour
        self._lock = threading.Lock()
        self._recent: list[float] = []
        self._networks = self._parse_allowlist(settings.response_allowlist)

    # -- allowlist ---------------------------------------------------------

    @staticmethod
    def _parse_allowlist(entries: Sequence[str]) -> list[IPNetwork]:
        networks: list[IPNetwork] = []
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                # A malformed allowlist entry is a configuration bug. Skipping it
                # silently would quietly widen what can be blocked, so it is
                # surfaced in the action detail instead of being ignored.
                continue
        return networks

    def is_allowlisted(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in net for net in self._networks)

    # -- checks ------------------------------------------------------------

    def _rate_limited(self) -> bool:
        cutoff = time.time() - 3600
        self._recent = [t for t in self._recent if t > cutoff]
        return len(self._recent) >= self.max_blocks_per_hour

    def _ufw_available(self) -> str | None:
        return shutil.which(self.settings.ufw_binary)

    # -- actions -----------------------------------------------------------

    def block(self, ip: str, score: int, reason: str, dry_run: bool | None = None) -> ResponseAction:
        """Add a deny rule for ``ip``, subject to every safety check.

        ``score`` must be the deterministic ingestor score for the triggering
        event, not a model-derived number.
        """
        # dry_run=True forces a rehearsal even in enforce mode; None defers to
        # configuration. dry_run=False does not grant enforcement on its own —
        # only SENTINEL_RESPONSE_MODE=enforce can do that.
        mode = "dry-run" if dry_run is True else self.settings.response_mode

        def refuse(why: str, detail: str = "") -> ResponseAction:
            return self._audit(
                ResponseAction(
                    action="block", target=ip, allowed=False, executed=False,
                    mode=mode, reason=why, detail=detail, score=score,
                )
            )

        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return refuse("invalid IP address", f"{ip!r} is not a valid IPv4/IPv6 address")

        if self.settings.response_mode == "disabled":
            return refuse("active response is disabled", "SENTINEL_RESPONSE_MODE=disabled")
        if self.is_allowlisted(ip):
            return refuse(
                "target is allowlisted",
                f"{ip} falls inside SENTINEL_RESPONSE_ALLOWLIST; refusing to lock out a trusted range",
            )
        if address.is_multicast or address.is_unspecified:
            return refuse("target is not a unicast host address")
        if score < self.settings.response_min_score:
            return refuse(
                "score below threshold",
                f"score {score} < SENTINEL_RESPONSE_MIN_SCORE {self.settings.response_min_score}",
            )

        with self._lock:
            if self._rate_limited():
                return refuse(
                    "rate limit reached",
                    f"already at {self.max_blocks_per_hour} blocks in the last hour",
                )

            # `insert 1` puts the deny rule ahead of any earlier allow rule; a deny
            # appended after an allow for the same traffic would never match.
            command = [self.settings.ufw_binary, "insert", "1", "deny", "from", str(address), "to", "any"]

            if mode != "enforce":
                return self._audit(
                    ResponseAction(
                        action="block", target=ip, allowed=True, executed=False, mode=mode,
                        reason=reason, score=score,
                        detail="dry-run: the command below was not executed",
                        command=command,
                    )
                )

            binary = self._ufw_available()
            if binary is None:
                return refuse(
                    "ufw not found",
                    f"{self.settings.ufw_binary!r} is not on PATH; is this running inside a container?",
                )
            command[0] = binary

            try:
                completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                    command,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return refuse("ufw invocation failed", str(exc))

            if completed.returncode != 0:
                return self._audit(
                    ResponseAction(
                        action="block", target=ip, allowed=True, executed=False, mode=mode,
                        reason=reason, score=score,
                        detail=f"ufw exited {completed.returncode}: {(completed.stderr or completed.stdout).strip()[:400]}",
                        command=command,
                    )
                )

            self._recent.append(time.time())
            return self._audit(
                ResponseAction(
                    action="block", target=ip, allowed=True, executed=True, mode=mode,
                    reason=reason, score=score,
                    detail=(completed.stdout or "").strip()[:400],
                    command=command,
                )
            )

    def unblock(self, ip: str) -> ResponseAction:
        """Remove a deny rule. Always permitted: undoing a block is never the
        dangerous direction, so this is not gated behind enforce mode."""
        mode = self.settings.response_mode
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return self._audit(
                ResponseAction(
                    action="unblock", target=ip, allowed=False, executed=False, mode=mode,
                    reason="invalid IP address",
                )
            )

        command = [self.settings.ufw_binary, "delete", "deny", "from", str(address), "to", "any"]
        if mode != "enforce":
            return self._audit(
                ResponseAction(
                    action="unblock", target=ip, allowed=True, executed=False, mode=mode,
                    reason="dry-run", detail="command not executed", command=command,
                )
            )
        binary = self._ufw_available()
        if binary is None:
            return self._audit(
                ResponseAction(
                    action="unblock", target=ip, allowed=False, executed=False, mode=mode,
                    reason="ufw not found",
                )
            )
        command[0] = binary
        try:
            completed = subprocess.run(  # noqa: S603
                command, capture_output=True, text=True, timeout=15, check=False, shell=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._audit(
                ResponseAction(
                    action="unblock", target=ip, allowed=True, executed=False, mode=mode,
                    reason="ufw invocation failed", detail=str(exc), command=command,
                )
            )
        return self._audit(
            ResponseAction(
                action="unblock", target=ip, allowed=True,
                executed=completed.returncode == 0, mode=mode,
                reason="operator requested unblock",
                detail=(completed.stderr or completed.stdout or "").strip()[:400],
                command=command,
            )
        )

    def status(self) -> dict[str, Any]:
        cutoff = time.time() - 3600
        return {
            "mode": self.settings.response_mode,
            "min_score": self.settings.response_min_score,
            "allowlist": [str(n) for n in self._networks],
            "ufw_available": self._ufw_available() is not None,
            "blocks_last_hour": len([t for t in self._recent if t > cutoff]),
            "max_blocks_per_hour": self.max_blocks_per_hour,
        }

    def history(self, limit: int = 100) -> list[dict[str, Any]]:
        """Most recent audit entries, newest first."""
        path = Path(self.settings.audit_log)
        if not path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return rows[-limit:][::-1]

    # -- audit -------------------------------------------------------------

    def _audit(self, action: ResponseAction) -> ResponseAction:
        """Append-only audit trail, including refusals.

        Refusals are recorded because 'the system decided not to act' is exactly
        the thing you need evidence of during an incident review.
        """
        path = Path(self.settings.audit_log)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(action.to_dict(), ensure_ascii=False) + "\n")
        except OSError:
            # An unwritable audit log must not stop a block that is otherwise
            # authorised, but it is recorded in the returned detail.
            action.detail = (action.detail + " [audit log write failed]").strip()
        return action
