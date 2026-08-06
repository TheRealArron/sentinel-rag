# The write-up

`index.html` is a long-form postmortem: the five hardest defects in this project
and, more usefully, the mechanism that caught each one.

One file. No build step, no generator, no runtime, no external requests — the
CSS is inline and there is no JavaScript at all. That is not minimalism for its
own sake: a page with no moving parts cannot be exploited, cannot break when a
CDN changes, and will still render in five years. It seemed the right shape for
a page arguing that dependencies are a liability.

## Reading it locally

```bash
xdg-open site/index.html          # it is a file; there is nothing to serve
```

## Publishing it on the Ubuntu server

```bash
# one-time: install the nginx site and edit server_name
sudo cp site/nginx-sentinel-site.conf /etc/nginx/sites-available/sentinel-site
sudoedit /etc/nginx/sites-available/sentinel-site        # set server_name
sudo ln -sf /etc/nginx/sites-available/sentinel-site /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# TLS
sudo certbot --nginx -d sentinel.example.com

# every time the page changes
make site-check          # verify without writing anything
sudo ./site/deploy.sh    # install to /var/www/sentinel-site and reload nginx
```

`deploy.sh` refuses to publish if the page loads any external resource, if it
has no closing `</html>` (a truncated write), or if it is implausibly small. It
checks before it copies, so a bad page never reaches the document root.

## Keep this on a different hostname to the dashboard

The nginx config does not proxy to the Sentinel API, deliberately. This page is
public; the dashboard has an endpoint that a host-side responder turns into
`ufw` rules as root. Sharing a server name between them is how a public page
ends up one misconfigured `location` block away from a privileged action.

Defect 01 in the write-up is what happens when you assume a boundary exists
because it has a friendly name.

## If you edit it

Every number on the page was measured, not estimated. If you change a claim,
re-measure it:

| Claim | How to reproduce |
|---|---|
| 16 / 13 / 9 blast-radius entities | `scripts/generate-baseline-log.py --days 7 --seed 42`, concatenate `data/samples/sample_syslog.log`, ingest, then `blast_radius("source_ip:203.0.113.45", max_hops=3)` with each flag combination |
| 25 → 23 events | revert the `if ev.Outcome == ""` guard in `ingestor/internal/enrich/enrich.go` and run `make sample` with Sigma rules armed |
| The 403s | `python -m sentinel serve --port 8137`, then the `curl` commands quoted on the page |
| 12,518 / 5,638 lines | `find … -name '*.go' -o -name '*.py'` split by test/non-test |
| 496 Python tests | `make test-py` |

The page renders in the reader's light or dark theme; both are defined
explicitly, so check both after any change to the palette.
