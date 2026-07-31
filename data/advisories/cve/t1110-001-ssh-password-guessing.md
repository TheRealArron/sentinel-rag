---
id: technique-t1110-001
title: "SSH credential brute forcing and password spraying against internet-facing hosts"
publisher: MITRE ATT&CK / technique note
published: 2025-04-14
lang: en
severity: high
mitre: [T1110.001, T1110.003, T1078.003, T1589.001]
keywords:
  - brute force
  - ブルートフォース
  - password spraying
  - パスワードスプレー
  - credential access
  - 認証情報の窃取
  - sshd
  - failed password
  - 認証失敗
  - fail2ban
---

## Summary

Automated credential guessing against `sshd` is the highest-volume attack any
internet-facing Linux host experiences. On a home server with port 22 exposed,
several thousand attempts per day is normal background radiation. The analytical
problem is therefore not detection but **triage**: separating opportunistic scanning
from a targeted campaign, and both of those from a campaign that succeeded.

## Log signatures

Ubuntu writes these to `/var/log/auth.log` (and the journal, unit `ssh`):

| Signature | Meaning |
|---|---|
| `Failed password for USER from IP port N ssh2` | Credential attempt against an existing account |
| `Failed password for invalid user USER from IP` | The account does not exist — enumeration |
| `Invalid user USER from IP port N` | Same, logged at connection time |
| `Connection closed by authenticating user USER IP port N [preauth]` | Client gave up mid-authentication |
| `error: maximum authentication attempts exceeded for USER from IP` | `MaxAuthTries` hit in one session |
| `Accepted password for USER from IP port N ssh2` | **Success** |
| `POSSIBLE BREAK-IN ATTEMPT!` | Reverse DNS does not match forward DNS |

## Triage rules that actually discriminate

1. **Volume within a window, not total volume.** Five failures from one address
   inside 60 seconds is a campaign; five failures spread over a day is noise.
   Opportunistic scanners typically try three or four credentials and move on.
2. **Distinct usernames from one source is spraying**, and is more serious than
   repeated attempts against one account: it indicates the attacker has no valid
   username yet and is enumerating, or has a credential list to spray. Targets like
   `admin`, `oracle`, `test`, `ubuntu`, `pi`, `git`, and `postgres` indicate a
   generic list rather than reconnaissance against this specific host.
3. **A success immediately following a failure burst from the same source is the
   critical case.** The guessing stopped because it worked. This is the transition
   from T1110.001 (Brute Force) to T1078.003 (Valid Accounts: Local Accounts), and
   it should be treated as a probable compromise, not a successful login.
4. **Public versus private source.** An internal address failing to authenticate is
   usually a misconfigured backup job or a stale credential in a script. Weight
   internet-facing sources higher.
5. **Root as the target account raises severity** regardless of outcome, because
   success grants immediate full control with no escalation step required.

## What to do after a success from a suspicious source

Treat the account as compromised and the host as suspect:

```bash
sudo last -F | head -40                      # who logged in, from where
sudo lastlog                                 # last login per account
sudo ss -tanp                                # current connections
sudo find /home /root -name authorized_keys -newermt '-2 days' -ls
sudo journalctl -u ssh --since '-24 hours' | grep -E 'Accepted|Failed'
```

Then rotate credentials, revoke SSH keys, and review for persistence before
declaring the incident closed.

## Prevention

1. **Disable password authentication entirely.** In `/etc/ssh/sshd_config`, set
   `PasswordAuthentication no` and `KbdInteractiveAuthentication no`, then
   `sudo systemctl reload ssh`. Key-only authentication eliminates this entire
   technique rather than rate-limiting it.
2. **Disable direct root login:** `PermitRootLogin no`.
3. **Rate-limit:** `sudo apt-get install fail2ban`, then enable the `sshd` jail. A
   default `bantime` of 10 minutes with `maxretry 5` removes most automated volume.
4. **Reduce exposure:** move SSH behind a VPN, or restrict source ranges with UFW:
   `sudo ufw limit from 203.0.113.0/24 to any port 22 proto tcp`.
5. **Lower `MaxAuthTries` to 3** so a single session cannot try six credentials.

Changing the SSH port is not on this list. It reduces log volume from
indiscriminate scanners but provides no security against anything that scans ports,
and it makes legitimate access harder to document.
