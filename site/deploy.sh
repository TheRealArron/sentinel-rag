#!/usr/bin/env bash
#
# deploy.sh — publish the Sentinel RAG write-up to the local Ubuntu server.
#
# Copies one HTML file into the nginx document root. That is the whole job, and
# keeping it that way is deliberate: a static page with no build step, no
# generator and no runtime is a page that cannot be exploited and cannot rot.
#
#   sudo ./site/deploy.sh                 # install to /var/www/sentinel-site
#   sudo ./site/deploy.sh --check         # verify only, change nothing
#   DEST=/srv/www sudo ./site/deploy.sh   # somewhere else
#
# Run the nginx config install once, by hand, from site/nginx-sentinel-site.conf.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${DEST:-/var/www/sentinel-site}"
PAGE="$SRC_DIR/index.html"
CHECK_ONLY=0

[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

log()  { printf '%s deploy: %s\n' "$(date -Is)" "$*"; }
die()  { printf '%s deploy: ERROR %s\n' "$(date -Is)" "$*" >&2; exit 1; }

[[ -f "$PAGE" ]] || die "missing $PAGE"

# The page must stay self-contained. A CDN reference would both break the CSP in
# nginx-sentinel-site.conf and quietly add a third party to a page arguing for
# dependency discipline — so it is a hard failure, not a warning.
#
# Only *resource loads* count: src= on any element, and href= on <link>. A plain
# <a href="https://..."> is a hyperlink, not a fetch, and the page should have
# them — an earlier version of this check rejected the repository link.
external=$(grep -Eoi '(<link[^>]+href|src)="https?://[^"]*"' "$PAGE" | sort -u || true)
if [[ -n "$external" ]]; then
  sed 's/^/  /' <<< "$external"
  die "the page loads a resource from an external origin; inline it or drop it"
fi

# Catch a truncated write before it reaches the document root.
if ! grep -q '</html>' "$PAGE"; then
  die "$PAGE has no closing </html> — refusing to publish a truncated page"
fi

bytes=$(wc -c < "$PAGE")
(( bytes > 4096 )) || die "$PAGE is only ${bytes} bytes, which is not a finished page"

log "page verified: ${bytes} bytes, self-contained"

if (( CHECK_ONLY )); then
  log "--check given; nothing written"
  exit 0
fi

[[ $EUID -eq 0 ]] || die "must run as root to write $DEST (use sudo)"

install -d -m 0755 "$DEST"
# 0644 root:root — nginx reads it as an unprivileged worker and must never be
# able to write it back.
install -m 0644 -o root -g root "$PAGE" "$DEST/index.html"
log "installed $DEST/index.html"

if command -v nginx >/dev/null 2>&1; then
  if nginx -t 2>/dev/null; then
    systemctl reload nginx && log "nginx reloaded"
  else
    log "WARNING: nginx config test failed; the file is in place but nginx was NOT reloaded"
    log "         run 'sudo nginx -t' to see why"
  fi
else
  log "nginx not installed; the file is in place at $DEST/index.html"
fi

log "done"
