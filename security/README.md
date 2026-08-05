# Container and supply-chain hardening

## Confinement profiles

| File | Enforces |
|---|---|
| `apparmor-sentinel-ingestor` | *what the ingestor may touch* — read `/var/log`, write only the event stream and spool |
| `seccomp-sentinel-ingestor.json` | *what syscalls it may make* — 41 denied |

They are complementary, not alternatives. Seccomp filters syscalls and cannot
express "`open()` is fine for `/var/log` but not for `/etc/shadow`"; AppArmor
does exactly that. The compose file already drops all capabilities and mounts the
filesystem read-only, so these are the third and fourth fences.

```bash
sudo apparmor_parser -r -W security/apparmor-sentinel-ingestor
docker compose up -d          # seccomp is wired in already; uncomment apparmor
```

**Neither profile has been tested on the machine they were written on** — no
Docker or AppArmor tooling was available. Load AppArmor in complain mode first
and read the denials before enforcing:

```bash
sudo aa-complain /etc/apparmor.d/sentinel-ingestor
sudo journalctl -f | grep apparmor
```

The seccomp profile is a **deny list layered on a permissive default**, not a
hand-written allow list. A Go binary's syscall surface includes the runtime's
scheduler, GC and netpoller, which varies by Go version and kernel; an allow list
built by guesswork breaks on the next toolchain bump in a way that looks like a
hang. The syscalls denied here are ones a log parser has no business making, so
blocking them costs nothing and cannot break on an upgrade.

## Dependency pinning

```bash
make lock            # regenerate engine/requirements.lock with hashes
make install-locked  # install with --require-hashes
```

`--require-hashes` means pip refuses any artifact whose SHA-256 does not match,
which closes dependency substitution: a compromised index or a typosquatted
mirror cannot serve a different wheel under the same version.

Two caveats worth stating rather than hiding:

* **The lock is platform-specific.** It is resolved for CPython 3.12 on
  x86-64 Linux. Installing it on a different platform will fail on a missing
  wheel — which is the correct behaviour for a lockfile, but is a surprise if
  you expected `requirements.txt` semantics.
* **Resolving it is slow.** The graph includes torch, chromadb and langchain;
  expect ten minutes or more. That is why `requirements.txt` remains the
  everyday file and the lock is a release artifact.

Hash pinning applies only to the *optional* Python dependencies. The Go ingestor
has none at all — its `go.mod` is empty and CI enforces that — so it has no
dependency-substitution surface to close.
