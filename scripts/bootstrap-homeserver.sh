#!/usr/bin/env bash
#
# bootstrap-homeserver.sh — prepare an Ubuntu machine to run Sentinel RAG.
#
#   ./scripts/bootstrap-homeserver.sh            # check what is missing
#   ./scripts/bootstrap-homeserver.sh --install  # install it
#
# Idempotent: safe to re-run. Nothing is installed without --install, and the
# script prints every command it would run first.

set -euo pipefail

INSTALL=0
[[ "${1:-}" == "--install" ]] && INSTALL=1

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; DIM='\033[2m'; NC='\033[0m'
ok()   { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
warn() { printf "  ${YELLOW}!${NC} %s\n" "$*"; }
bad()  { printf "  ${RED}✗${NC} %s\n" "$*"; }
note() { printf "    ${DIM}%s${NC}\n" "$*"; }
head_() { printf "\n\033[1m%s\033[0m\n" "$*"; }

MISSING=()
run_or_show() {
  if [[ "$INSTALL" == "1" ]]; then
    printf "  ${DIM}\$ %s${NC}\n" "$*"
    "$@"
  else
    MISSING+=("$*")
  fi
}

head_ "Sentinel RAG — home server bootstrap"

# --------------------------------------------------------------------------
head_ "1. Operating system"

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  ok "$PRETTY_NAME"
  if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
    warn "not Ubuntu/Debian — package names below may differ"
  fi
else
  warn "cannot identify the distribution"
fi

KERNEL=$(uname -r)
ok "kernel $KERNEL"

# --------------------------------------------------------------------------
head_ "2. Hardware"

MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
MEM_GB=$(( MEM_KB / 1024 / 1024 ))
if (( MEM_GB >= 8 )); then
  ok "${MEM_GB} GB RAM"
elif (( MEM_GB >= 4 )); then
  warn "${MEM_GB} GB RAM — multilingual-e5-large needs ~2.5 GB resident"
  note "set SENTINEL_EMBEDDING_MODEL=intfloat/multilingual-e5-small in .env"
else
  bad "${MEM_GB} GB RAM — too little for the large embedding model"
  note "use intfloat/multilingual-e5-small, or SENTINEL_EMBEDDING_BACKEND=hashing"
fi

CORES=$(nproc)
ok "${CORES} CPU core(s) — the ingestor defaults to one worker per core"

AVAIL_GB=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
if (( AVAIL_GB >= 15 )); then
  ok "${AVAIL_GB} GB free"
else
  warn "${AVAIL_GB} GB free — model weights are ~2.2 GB and the images ~2 GB"
fi

# --------------------------------------------------------------------------
head_ "3. Toolchain"

if command -v go >/dev/null 2>&1; then
  ok "$(go version)"
else
  bad "Go is not installed (needed to build the ingestor outside Docker)"
  run_or_show sudo apt-get install -y golang-go
fi

if command -v python3 >/dev/null 2>&1; then
  PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
  if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)'; then
    ok "Python $PYV"
  else
    bad "Python $PYV — 3.10 or newer is required"
  fi
else
  bad "Python 3 is not installed"
  run_or_show sudo apt-get install -y python3 python3-pip python3-venv
fi

if command -v docker >/dev/null 2>&1; then
  ok "$(docker --version)"
  if docker compose version >/dev/null 2>&1; then
    ok "$(docker compose version | head -1)"
  else
    bad "the docker compose plugin is missing"
    run_or_show sudo apt-get install -y docker-compose-plugin
  fi
  if ! docker info >/dev/null 2>&1; then
    warn "cannot talk to the Docker daemon as $(whoami)"
    note "sudo usermod -aG docker $(whoami)   # then log out and back in"
  fi
else
  bad "Docker is not installed"
  note "curl -fsSL https://get.docker.com | sudo sh"
fi

for tool in jq git curl; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool"
  else
    bad "$tool is not installed"
    run_or_show sudo apt-get install -y "$tool"
  fi
done

# --------------------------------------------------------------------------
head_ "4. Log sources"

for logfile in /var/log/auth.log /var/log/syslog; do
  if [[ -r "$logfile" ]]; then
    ok "$logfile readable ($(du -h "$logfile" | cut -f1))"
  elif [[ -e "$logfile" ]]; then
    warn "$logfile exists but is not readable as $(whoami)"
    note "the ingestor container reads it as root; this only affects host-side runs"
  else
    warn "$logfile does not exist"
    note "on a journald-only system: journalctl -f -o short-iso | sentinel-ingestor -in -"
  fi
done

if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
  ok "sshd is running — auth.log will have something to say"
else
  warn "sshd is not running; the sample corpus is SSH-heavy"
fi

# --------------------------------------------------------------------------
head_ "5. Firewall (needed for Phase 4)"

if command -v ufw >/dev/null 2>&1; then
  ok "ufw installed"
  STATUS=$(sudo -n ufw status 2>/dev/null | head -1 || echo "status: unknown (needs sudo)")
  note "$STATUS"
else
  warn "ufw is not installed — active response will refuse to act"
  run_or_show sudo apt-get install -y ufw
fi

# --------------------------------------------------------------------------
head_ "6. Repository state"

cd "$(dirname "$0")/.."

if [[ -f .env ]]; then
  ok ".env exists"
  if grep -qE '^GEMINI_API_KEY=.+' .env; then
    ok "GEMINI_API_KEY is set"
  else
    warn "GEMINI_API_KEY is empty — alerts will be rule-based only"
    note "get a key at https://aistudio.google.com/app/apikey"
  fi
else
  warn ".env is missing"
  run_or_show cp .env.example .env
fi

ADVISORIES=$(find data/advisories -name '*.md' -not -name 'README.md' 2>/dev/null | wc -l)
if (( ADVISORIES >= 8 )); then
  ok "${ADVISORIES} advisories in the corpus"
else
  warn "only ${ADVISORIES} advisories found"
fi

# --------------------------------------------------------------------------
head_ "Summary"

if (( ${#MISSING[@]} > 0 )); then
  echo
  echo "  Re-run with --install to apply, or run these yourself:"
  echo
  printf "    %s\n" "sudo apt-get update"
  for cmd in "${MISSING[@]}"; do printf "    %s\n" "$cmd"; done
  echo
  exit 1
fi

cat <<'EOF'

  Ready. Next steps:

    make demo                   # end-to-end walkthrough, no API key needed
    make up                     # start the stack in Docker
    xdg-open http://127.0.0.1:8000/

  For active response, after a week of watching data/audit.log:

    sudo install -m 0755 scripts/sentinel-responder.sh /usr/local/bin/
    sudo install -m 0644 scripts/systemd/sentinel-responder.* /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-responder.timer

EOF
