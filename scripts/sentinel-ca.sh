#!/usr/bin/env bash
#
# sentinel-ca.sh — a private Certificate Authority for the Sentinel fleet.
#
# Public CAs cannot issue certificates for internal hostnames, and you would not
# want them to: a Let's Encrypt certificate proves you control a DNS name, which
# is the wrong question. The question here is "is this machine one of mine", and
# only you can answer it. So you become the CA.
#
#   ./scripts/sentinel-ca.sh init                    # create the root CA (once)
#   ./scripts/sentinel-ca.sh server sentinel-hub.lan # cert for the Python hub
#   ./scripts/sentinel-ca.sh client probe-01         # cert for a Go ingestor
#   ./scripts/sentinel-ca.sh revoke probe-04         # stop trusting one probe
#   ./scripts/sentinel-ca.sh list
#
# WHY MUTUAL TLS AND NOT PLAIN TLS
#
# Plain TLS authenticates the *server*. That stops a probe from shipping logs to
# an impostor hub, which matters — logs are a map of your infrastructure and its
# weaknesses. But it leaves the hub accepting connections from anyone.
#
# For security telemetry that is the more dangerous gap. An unauthenticated hub
# can be fed fabricated events: an attacker who has compromised a host can drown
# the real signal in noise, or worse, inject quiet "nothing happened" traffic to
# make a genuinely-compromised probe look healthy. Detection tooling that accepts
# anonymous input can be *disabled by talking to it*.
#
# Mutual TLS closes that: the probe proves it holds a key this CA signed, on
# every connection, before a byte of application data is read.
#
# WHAT mTLS STILL DOES NOT GIVE YOU
#
# It proves a valid probe is connected. It does NOT prove which host the logs
# describe. Without binding the certificate identity to the log content, any
# valid probe can forge events for any other host — a compromised probe-04 could
# submit clean logs claiming to be probe-07. The hub therefore pins each event's
# `host` field to the client certificate's Common Name; see engine/sentinel/hub.py.
#
# Authentication is not authorisation, and on a log pipeline the difference is
# the whole attack.

set -euo pipefail

CA_DIR="${SENTINEL_CA_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/pki}"
DAYS_CA="${SENTINEL_CA_DAYS:-3650}"
DAYS_SERVER="${SENTINEL_SERVER_DAYS:-825}"
# Client certificates are deliberately short-lived. A stolen probe key is a
# problem that expires on its own; the revocation list only has to cover the
# window between theft and expiry, which keeps it small and keeps its staleness
# bounded. This is the same reasoning behind SPIFFE and Google's own short-lived
# workload credentials, scaled down to a home fleet.
DAYS_CLIENT="${SENTINEL_CLIENT_DAYS:-90}"
KEY_BITS="${SENTINEL_KEY_BITS:-4096}"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$*"; }
die()  { printf "  ${RED}✗${NC} %s\n" "$*" >&2; exit 1; }
note() { printf "    ${DIM}%s${NC}\n" "$*"; }

command -v openssl >/dev/null || die "openssl is not installed"

# One scratch directory for the whole run, cleaned on exit. A per-function RETURN
# trap looked tidier but fires again in the *calling* function's scope, where the
# variables it references do not exist — noisy under `set -u`.
_TMP="$(mktemp -d)"
trap 'rm -rf "$_TMP"' EXIT

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

ensure_ca() {
  [[ -f "$CA_DIR/ca.crt" ]] || die "no CA at $CA_DIR — run: $0 init"
}

cmd_init() {
  if [[ -f "$CA_DIR/ca.crt" ]]; then
    warn "CA already exists at $CA_DIR/ca.crt — refusing to overwrite"
    note "Re-initialising would invalidate every certificate already issued."
    note "To start over deliberately: rm -rf $CA_DIR"
    return 1
  fi
  mkdir -p "$CA_DIR"/{certs,private,revoked}
  # The CA key is the root of all trust here. 0700/0600 so a compromise of any
  # other account on the hub does not become a compromise of the fleet.
  chmod 700 "$CA_DIR/private"

  openssl genrsa -out "$CA_DIR/private/ca.key" "$KEY_BITS" 2>/dev/null
  chmod 600 "$CA_DIR/private/ca.key"

  openssl req -x509 -new -nodes -sha256 \
    -key "$CA_DIR/private/ca.key" \
    -days "$DAYS_CA" \
    -subj "/O=Sentinel RAG/OU=Fleet/CN=Sentinel Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$CA_DIR/ca.crt" 2>/dev/null

  echo "01" > "$CA_DIR/serial"
  : > "$CA_DIR/issued.txt"
  : > "$CA_DIR/revoked/revoked.json.tmp"
  echo '{"revoked": []}' > "$CA_DIR/revoked.json"

  ok "root CA created: $CA_DIR/ca.crt (valid ${DAYS_CA} days)"
  note "pathlen:0 — this CA can issue leaf certificates but no sub-CAs."
  note "Back up $CA_DIR/private/ca.key offline. Losing it means reissuing the fleet."
}

# issue <kind:server|client> <name> [san...]
issue() {
  local kind="$1" name="$2"; shift 2
  ensure_ca
  local key="$CA_DIR/private/${name}.key"
  local crt="$CA_DIR/certs/${name}.crt"
  local csr="$_TMP/${name}.csr"
  local ext="$_TMP/${name}.ext"

  [[ -f "$crt" ]] && die "$crt already exists — revoke it first, or pick another name"

  local days eku
  if [[ "$kind" == "server" ]]; then
    days="$DAYS_SERVER"; eku="serverAuth"
  else
    days="$DAYS_CLIENT"; eku="clientAuth"
  fi

  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature,keyEncipherment"
    echo "extendedKeyUsage=${eku}"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid,issuer"
    # A SAN is mandatory: every modern TLS stack ignores the Common Name for
    # hostname verification. A cert with only a CN silently fails to validate.
    printf "subjectAltName=DNS:%s" "$name"
    for extra in "$@"; do
      if [[ "$extra" =~ ^[0-9.]+$ || "$extra" == *:* ]]; then
        printf ",IP:%s" "$extra"
      else
        printf ",DNS:%s" "$extra"
      fi
    done
    echo
  } > "$ext"

  openssl genrsa -out "$key" "$KEY_BITS" 2>/dev/null
  chmod 600 "$key"
  openssl req -new -sha256 -key "$key" \
    -subj "/O=Sentinel RAG/OU=${kind}/CN=${name}" -out "$csr" 2>/dev/null
  openssl x509 -req -sha256 -in "$csr" \
    -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/private/ca.key" \
    -CAserial "$CA_DIR/serial" \
    -days "$days" -extfile "$ext" -out "$crt" 2>/dev/null

  local serial fingerprint
  serial="$(openssl x509 -in "$crt" -noout -serial | cut -d= -f2)"
  fingerprint="$(openssl x509 -in "$crt" -noout -fingerprint -sha256 | cut -d= -f2)"
  printf "%s\t%s\t%s\t%s\t%s\n" \
    "$name" "$kind" "$serial" "$fingerprint" "$(date -Is)" >> "$CA_DIR/issued.txt"

  ok "${kind} certificate for '${name}' (valid ${days} days)"
  note "cert: $crt"
  note "key : $key"
  note "SHA-256: $fingerprint"
}

cmd_server() {
  [[ $# -ge 1 ]] || die "usage: $0 server <hostname> [extra-san ...]"
  issue server "$@"
  note "Point the hub at it: SENTINEL_HUB_CERT / SENTINEL_HUB_KEY / SENTINEL_HUB_CA"
}

cmd_client() {
  [[ $# -ge 1 ]] || die "usage: $0 client <probe-name> [extra-san ...]"
  issue client "$@"
  note "The probe's CN is its identity. The hub pins each event's 'host' field"
  note "to it, so this certificate cannot submit logs claiming to be another machine."
  note "Ship with: sentinel-ingestor -remote https://hub:8443 -remote-cert ... -remote-key ..."
}

# The revocation list is a plain JSON file read by the hub. It is deliberately
# NOT a CA-signed CRL: the list lives on the machine that enforces it, so signing
# would protect it from an attacker who, by definition, already controls the
# enforcement point. A signature that guards nothing is ceremony.
cmd_revoke() {
  [[ $# -eq 1 ]] || die "usage: $0 revoke <name>"
  ensure_ca
  local name="$1"
  local line
  line="$(grep -P "^${name}\t" "$CA_DIR/issued.txt" || true)"
  [[ -n "$line" ]] || die "no certificate issued for '${name}' (see: $0 list)"

  local serial fingerprint
  serial="$(echo "$line" | cut -f3)"
  fingerprint="$(echo "$line" | cut -f4)"

  python3 - "$CA_DIR/revoked.json" "$name" "$serial" "$fingerprint" <<'PY'
import json, sys, datetime
path, name, serial, fingerprint = sys.argv[1:5]
try:
    data = json.load(open(path))
except (OSError, json.JSONDecodeError):
    data = {"revoked": []}
entries = data.setdefault("revoked", [])
if any(e.get("fingerprint") == fingerprint for e in entries):
    print("  already revoked")
    raise SystemExit(0)
entries.append({
    "name": name, "serial": serial, "fingerprint": fingerprint,
    "revoked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
})
with open(path, "w") as fh:
    json.dump(data, fh, indent=2)
PY

  ok "revoked '${name}' (serial ${serial})"
  note "The hub hot-reloads $CA_DIR/revoked.json — no restart, and no other"
  note "certificate in the fleet is affected."
  note "The key on that machine is still valid-looking; it is the hub that stops believing it."
}

cmd_unrevoke() {
  [[ $# -eq 1 ]] || die "usage: $0 unrevoke <name>"
  ensure_ca
  python3 - "$CA_DIR/revoked.json" "$1" <<'PY'
import json, sys
path, name = sys.argv[1:3]
data = json.load(open(path))
before = len(data.get("revoked", []))
data["revoked"] = [e for e in data.get("revoked", []) if e.get("name") != name]
json.dump(data, open(path, "w"), indent=2)
print(f"  removed {before - len(data['revoked'])} entry(ies)")
PY
  ok "unrevoked '$1'"
}

cmd_list() {
  ensure_ca
  printf "\n\033[1mIssued\033[0m  (%s)\n" "$CA_DIR/issued.txt"
  printf "  %-18s %-8s %-12s %s\n" NAME KIND EXPIRES STATUS
  local revoked_names
  revoked_names="$(python3 -c "
import json,sys
try: print(' '.join(e['name'] for e in json.load(open('$CA_DIR/revoked.json'))['revoked']))
except Exception: pass" 2>/dev/null || true)"

  while IFS=$'\t' read -r name kind serial fingerprint issued; do
    [[ -z "${name:-}" ]] && continue
    local expiry status
    if [[ -f "$CA_DIR/certs/${name}.crt" ]]; then
      expiry="$(openssl x509 -in "$CA_DIR/certs/${name}.crt" -noout -enddate | cut -d= -f2 | awk '{print $1, $2, $4}')"
      if openssl x509 -in "$CA_DIR/certs/${name}.crt" -noout -checkend 0 >/dev/null 2>&1; then
        status="valid"
      else
        status="EXPIRED"
      fi
    else
      expiry="-"; status="missing"
    fi
    [[ " $revoked_names " == *" $name "* ]] && status="REVOKED"
    printf "  %-18s %-8s %-12s %s\n" "$name" "$kind" "$expiry" "$status"
  done < "$CA_DIR/issued.txt"
  echo
}

cmd_verify() {
  ensure_ca
  [[ $# -eq 1 ]] || die "usage: $0 verify <name>"
  openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/certs/$1.crt"
  openssl x509 -in "$CA_DIR/certs/$1.crt" -noout -subject -issuer -dates -ext subjectAltName,extendedKeyUsage
}

case "${1:-}" in
  init)     shift; cmd_init "$@" ;;
  server)   shift; cmd_server "$@" ;;
  client)   shift; cmd_client "$@" ;;
  revoke)   shift; cmd_revoke "$@" ;;
  unrevoke) shift; cmd_unrevoke "$@" ;;
  list)     shift; cmd_list "$@" ;;
  verify)   shift; cmd_verify "$@" ;;
  -h|--help|help|"") usage 0 ;;
  *) die "unknown command '${1}' (try: $0 help)" ;;
esac
