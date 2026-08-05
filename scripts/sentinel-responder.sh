#!/usr/bin/env bash
#
# sentinel-responder — apply Sentinel's blocking decisions on the host.
#
# WHY THIS EXISTS
#
# The AI engine runs in a container with no capabilities and no network access to
# the host. It cannot touch the firewall, by design: giving a process that talks
# to a language model the ability to rewrite your firewall is a straight line
# from prompt injection to being locked out of your own server.
#
# Instead the engine *records* decisions in an append-only audit log, and this
# script — running on the host, under systemd, as root, with its own independent
# allowlist — decides whether to act on them. The engine proposes; the host
# disposes. The two never share a trust boundary.
#
# Every safety check the engine already performed is repeated here. That is
# deliberate duplication: this script must be correct even if the engine is
# entirely compromised.
#
# INSTALL
#
#   sudo install -m 0755 scripts/sentinel-responder.sh /usr/local/bin/
#   sudo install -m 0644 scripts/systemd/sentinel-responder.service /etc/systemd/system/
#   sudo install -m 0644 scripts/systemd/sentinel-responder.timer   /etc/systemd/system/
#   sudo systemctl daemon-reload
#   sudo systemctl enable --now sentinel-responder.timer
#
#   # watch it in dry-run for a week before enabling enforcement
#   journalctl -u sentinel-responder -f

set -euo pipefail

AUDIT_LOG="${SENTINEL_AUDIT_LOG:-/var/lib/docker/volumes/sentinel-rag_sentinel-data/_data/audit.log}"
STATE_FILE="${SENTINEL_RESPONDER_STATE:-/var/lib/sentinel/responder.state}"

# The responder keeps its OWN audit trail, separate from the engine's audit.log
# and from the journal. Two reasons: the engine's log is written by a container
# the engine controls, so it is evidence produced by the thing under review; and
# journald rotates on its own schedule, so the record of what was done to the
# firewall would age out with unrelated noise. This file is append-only, one JSON
# object per line, and records refusals as well as actions.
RESPONDER_AUDIT="${SENTINEL_RESPONDER_AUDIT:-/var/lib/sentinel/responder-audit.jsonl}"
ENFORCE="${SENTINEL_RESPONDER_ENFORCE:-0}"
MIN_SCORE="${SENTINEL_RESPONDER_MIN_SCORE:-90}"
MAX_PER_RUN="${SENTINEL_RESPONDER_MAX_PER_RUN:-5}"

# Independent allowlist. Deliberately NOT read from the engine's configuration: a
# compromised engine must not be able to widen what this script will block. These
# prefixes can only ever be added to from this file or from
# SENTINEL_RESPONDER_EXTRA_ALLOW, never removed by anything the engine says.
ALLOWLIST=(
  "127."        "10."         "172.16."     "172.17."     "172.18."     "172.19."
  "172.2"       "172.30."     "172.31."     "192.168."    "169.254."    "::1"
)

# Site-specific ranges that must never be blocked — your office, your university,
# your ISP's gateway, the address you SSH in from. Set it; the defaults above
# only cover loopback and RFC1918, which will not save you if you administer this
# box from a public address.
#
#   SENTINEL_RESPONDER_EXTRA_ALLOW="203.0.113. 198.51.100.42"
#
# Left empty on purpose. Guessing an institution's range and shipping it as a
# default would be a fabricated safety guarantee — if the guess is wrong the
# operator believes they are protected and is not.
read -r -a EXTRA_ALLOW <<< "${SENTINEL_RESPONDER_EXTRA_ALLOW:-}"
ALLOWLIST+=("${EXTRA_ALLOW[@]}")

# The address this session came from, if any. Blocking the range you are
# currently connected from is the single most likely way to lock yourself out,
# and it is trivially detectable.
if [[ -n "${SSH_CLIENT:-}" ]]; then
  ALLOWLIST+=("$(awk '{print $1}' <<< "$SSH_CLIENT")")
fi

log() { printf '%s sentinel-responder: %s\n' "$(date -Is)" "$*"; }

# Structured, append-only, separate from the journal. Every decision including
# refusals: "the system declined to act" is exactly what an incident review needs.
audit() {
  local verdict="$1" ip="$2" reason="$3" score="${4:--1}"
  mkdir -p "$(dirname "$RESPONDER_AUDIT")" 2>/dev/null || true
  printf '{"at":"%s","verdict":"%s","target":"%s","score":%s,"reason":"%s","enforce":%s,"host":"%s"}\n' \
    "$(date -Is)" "$verdict" "$ip" "$score" "${reason//\"/\'}" "${ENFORCE:-0}" "$(hostname)" \
    >> "$RESPONDER_AUDIT" 2>/dev/null || log "WARNING: could not write $RESPONDER_AUDIT"
}
die() { log "ERROR: $*"; exit 1; }

command -v ufw >/dev/null 2>&1 || die "ufw is not installed"
command -v jq  >/dev/null 2>&1 || die "jq is not installed (sudo apt-get install jq)"
[[ $EUID -eq 0 ]] || die "must run as root"
[[ -r "$AUDIT_LOG" ]] || { log "no audit log at $AUDIT_LOG — nothing to do"; exit 0; }

mkdir -p "$(dirname "$STATE_FILE")"
touch "$STATE_FILE"

is_allowlisted() {
  local ip="$1" prefix
  for prefix in "${ALLOWLIST[@]}"; do
    [[ "$ip" == "$prefix"* ]] && return 0
  done
  return 1
}

already_blocked() {
  ufw status | grep -qF "$1"
}

applied=0
processed=0

# Read only entries the engine approved, that were not already executed, and
# that are block actions.
while IFS=$'\t' read -r ip score reason at; do
  [[ -z "${ip:-}" ]] && continue
  processed=$((processed + 1))

  grep -qxF "$ip" "$STATE_FILE" && continue

  if is_allowlisted "$ip"; then
    log "REFUSED $ip — allowlisted range (host-side allowlist)"
    audit refused "$ip" "allowlisted range" "$score"
    continue
  fi

  # The engine already checked this. We check it again because this script must
  # be correct even if the engine is entirely compromised.
  if [[ ! "$score" =~ ^[0-9]+$ ]] || (( score < MIN_SCORE )); then
    log "REFUSED $ip — score '${score}' below host-side threshold $MIN_SCORE"
    audit refused "$ip" "score below host-side threshold $MIN_SCORE" "$score"
    continue
  fi

  if ! [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ || "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
    log "REFUSED $ip — not a valid address"
    audit refused "$ip" "not a valid address" "$score"
    continue
  fi

  if already_blocked "$ip"; then
    log "SKIP $ip — already present in the ruleset"
    echo "$ip" >> "$STATE_FILE"
    continue
  fi

  if [[ "$applied" -ge "$MAX_PER_RUN" ]]; then
    log "STOP — reached MAX_PER_RUN=$MAX_PER_RUN, remaining entries deferred to the next run"
    break
  fi

  if [[ "$ENFORCE" != "1" ]]; then
    log "DRY-RUN would block $ip (score $score, recorded $at): $reason"
    audit dry-run "$ip" "$reason" "$score"
    continue
  fi

  # insert 1: a deny appended after an existing allow would never match.
  if ufw insert 1 deny from "$ip" to any; then
    log "BLOCKED $ip (score $score, recorded $at): $reason"
    audit blocked "$ip" "$reason" "$score"
    echo "$ip" >> "$STATE_FILE"
    applied=$((applied + 1))
  else
    log "FAILED to block $ip — ufw returned $?"
    audit failed "$ip" "ufw invocation failed" "$score"
  fi
done < <(
  jq -r 'select(.action == "block" and .allowed == true)
         | [.target, (.score // -1 | tostring), (.reason // ""), (.at // "")]
         | @tsv' "$AUDIT_LOG" 2>/dev/null | sort -u
)

log "done — $processed approved decision(s) considered, $applied rule(s) applied (enforce=$ENFORCE)"
log "allowlist has ${#ALLOWLIST[@]} prefix(es); audit trail: $RESPONDER_AUDIT"
