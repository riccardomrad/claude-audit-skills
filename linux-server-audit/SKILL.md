---
name: linux-server-audit
description: >-
  READ-ONLY security audit of a Linux server you own or administer, over SSH.
  In one command it collects the state of SSH access, firewall and listening
  ports, containers, accounts and privileges, file permissions and sensitive
  files, kernel parameters and process isolation, logging and pending updates,
  then judges the findings and writes a dated report split into "fix now" and
  "written debt with a trigger". Use this skill whenever the user says "server
  security audit", "audit the server", "is my server secure?", "how exposed are
  we", "check the open ports", "who can get into the server", "check SSH",
  "hardening", "check the containers", "is the server patched?", "monthly
  audit", or after an alert, a suspicious login, an intrusion attempt, or
  before putting a new customer on the machine. It also triggers on softer
  phrasings such as "let's take a look at the server from a security angle" or
  "I am afraid the server has been broken into". It changes nothing, restarts
  nothing, deletes nothing, and refuses to run against a host that is not
  declared in the local audit profile. It is NOT a disk-space cleanup and NOT a
  software update run. For websites and exposed web panels use web-security-audit.
---

# Linux server security audit

A photograph of the server's security state, taken by looking and nothing else.
The goal is not to produce as many findings as possible: it is to know **where
someone could get in today**, and what is worth closing first.

This skill does three things and then stops: it collects, it judges, it writes
the report. Fixing is separate work that the owner decides after reading.

## The three rules that do not bend

1. **Read only, always.** No command in this skill writes, deletes, restarts,
   installs or changes configuration. If a fix occurs to you while analysing,
   write it in the report, do not apply it. Practical reason: an audit that
   modifies is no longer a photograph, and if something stops working nobody
   can tell whether the audit or the original problem caused it.
2. **Secrets never leave the machine.** For sensitive files collect name, owner
   and permissions, never content. Never `cat` an `.env`, a private key, a
   certificate or the shadow file. If you need to know whether a secret is
   exposed, the evidence is the file mode, not the contents. Most `/etc`
   configuration files are world readable by default and application configs
   often carry plaintext database passwords (Tevault ch. 8), so the mode is the
   whole answer.
3. **What you did not look at is not "fine".** Every skipped check goes into the
   "what I could not check" section of the report. An audit that declares
   healthy what it never saw is worse than no audit.

## Phase 0: the profile decides the target

The collector never runs against an undeclared host. Before anything else:

```bash
bash scripts/run-audit.sh --check-profile
```

It reads `$AUDIT_PROFILE`, or `~/.config/audit-skills/profile.conf` when that
variable is unset, and stops with a non zero exit code when the file is missing
or when the profile is still a stub. Copy `profile.example.conf` to that path
and fill it in with your own host, port, user, domains and output directory.
The example file ships every value empty, and a profile still carrying the
placeholder names of the manuals (203.0.113.x, example.com, example.org,
example.net) is refused as never filled in: those names belong to nobody, so a
run aimed at them would look like it worked and audit nothing.

If the machine has no SSH client at all, that is worth knowing before anything
else, and it is one command:

```bash
bash scripts/run-audit.sh --check-ssh
```

Then, before collecting:

1. Look for the previous audit in `OUTPUT_DIR`. The comparison is the most
   valuable part of the work: one new SUID file or one new listening port is
   worth more than ten generic findings, and without a baseline there is
   nothing to compare against (Tevault ch. 8).
2. Tell the user in one line that you are about to open an SSH session and run
   a read-only collection that takes two or three minutes.

## Phase 1: collection (one command)

```bash
bash scripts/run-audit.sh
```

`scripts/collect.sh` is piped to `ssh` on standard input, so it is never copied
to the server and leaves nothing behind. It is readable: if the user wants to
check it first, open it together, it is a few hundred commented lines.

Practical notes, learned the hard way:

- The wrapper picks the right `ssh` binary for the platform. On Windows the Git
  Bash `ssh` does not work and the Windows OpenSSH binary is needed; on Linux
  that path does not exist and the system `ssh` is the right one. Written by
  hand on the wrong platform, the command fails and looks like a network fault
  (verified in the field). When there is no client at all the wrapper says so in
  those words and writes nothing: a missing client used to surface as "the
  collection was cut short, run it again", which you can obey all evening
  without ever learning what is actually missing.
- The bundle can carry a list followed by `(the command also reported an error:
  the result may be incomplete)`. Those lines are real: judge them, and treat the
  section as possibly partial. Only `NOT VERIFIED` means the check never ran.
- The collector always uses `sudo -n`, so a command never hangs waiting for a
  password prompt that will never be answered (verified in the field).
- If the connection fails, stop and report the exact error. Do not try other
  ports, other users or other hosts: an audit that finds its own way in is
  exactly the behaviour we are trying to deny everyone else.
- Check that the bundle ends with `##### END OF COLLECTION`. If it does not, the
  collection was cut short: run it again before analysing, or you will mistake a
  truncated output for a problem that does not exist (verified in the field).

## Phase 2: analysis

Read `references/checks.md` and walk the bundle sections in the order they
appear. That file gives, for every check, what is fine, what is a finding, at
what severity, why it matters, and the source it comes from.

Three things deserve extra attention, because they are the ones most likely to
do real damage:

1. **Listening ports against firewall rules.** Compare what is listening with
   what the firewall backend actually contains, including the NAT table: a
   front end summary is a rule generator's opinion, not the firewall, and
   `iptables -L` shows only the filter table (Tevault ch. 4, Tevault ch. 5).
2. **Who can become administrator**: members of the admin group, sudo rules
   without a password, and the container group, which is administrator power
   under another name (Tevault ch. 2, Tevault ch. 10).
3. **Containers that mount the host filesystem or the container daemon socket**:
   that is the shortest path from "code running in a container" to
   "administrator on the host" (Tevault ch. 10).

While analysing keep two separate lists and never mix them: **facts read in the
bundle** on one side, **hypotheses** on the other. Facts go into the report;
hypotheses become "to be verified", not findings.

## Phase 3: report

Follow `references/report-template.md`. Save:

- the report in `$OUTPUT_DIR/server-security-audit-<YYYY-MM-DD>.md`;
- the raw bundle in `$OUTPUT_DIR/raw/bundle-server-<YYYY-MM-DD-HHMM>.txt`, which the
  next audit compares against, above all for SUID files and listening ports.

Then write the deferred findings into your own security roadmap file, one per
line, each with the trigger that says when to pick it up again. A deferral
without a trigger is never reopened by anyone.

In chat report only the two line summary, the "fix now" table, and where you
saved the report. The rest is read in the file.

## Phase 4: the fixes (this skill does not make them)

Propose an order of work, then stop. Every change to the server is a production
change:

- Firewall, SSH, container engine, reverse proxy: take a provider snapshot
  first, and the person who owns the console takes it, not you.
- Before changing anything that touches SSH access, open a second session and
  keep it connected. If the change locks you out, that session is the only way
  back without the provider console (Tevault ch. 7 warns about exactly this
  class of lockout: disabling password authentication before key access works,
  or saving a deny list before the allow list).
- One change at a time, and after each one re-check the piece you touched. The
  rule is not "I wrote the right configuration", it is "I verified it now
  behaves the way I want". For the firewall the check is trying again from
  outside; for SSH it is opening a fresh connection.

## What this skill does not do

- It does not free disk space and does not update software: different jobs with
  different risks.
- It does not look at websites, published pages or exposed web panels: that is
  `web-security-audit`.
- It is not a certification and not a formal compliance check. It is the
  periodic look of whoever keeps the server running.
- It does not run exploits and does not force anything: it reads configuration,
  it does not attack the machine.
- It cannot see what a compromised host chooses to hide. A replaced system tool
  can hide its own connections, which is why an external scan is a second
  opinion the host cannot fake (Tevault ch. 16).
