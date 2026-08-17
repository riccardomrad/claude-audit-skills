# linux-server-audit

A read-only security audit of a Linux server you own or administer, packaged as
an agent skill. One command collects the state of the machine over SSH, a
reference file says how to read every section, and a template turns the result
into a dated report split into "fix now" and "written debt with a trigger".

## What it does

Collects and judges: SSH configuration in effect, accounts and privilege paths,
firewall rules and listening ports (IPv4 and IPv6, filter table and NAT table),
containers and what they mount, file permissions and SUID inventory, kernel
hardening parameters, mandatory access control, scheduled tasks, logging and
pending updates.

## The read-only promise

Every command in `scripts/collect.sh` reads. Nothing writes, deletes, restarts,
installs, or changes configuration. The collector is piped to `ssh` on standard
input, so it is never copied to the server and leaves nothing behind. Secrets
are never collected: for sensitive files it takes name, owner and mode, never
content; session IP addresses are masked; sudo rules, cron lines and fstab
entries are summarised rather than quoted, because a bundle travels through
chats and shared folders.

You can read the whole collector before running it. That is the point of
shipping it as a readable script instead of a binary.

## Setting up the profile

The skill never runs against an undeclared host.

```bash
mkdir -p ~/.config/audit-skills
cp profile.example.conf ~/.config/audit-skills/profile.conf
$EDITOR ~/.config/audit-skills/profile.conf
```

Keys: `SSH_HOST`, `SSH_PORT` (default 22), `SSH_USER`, `WEB_TARGETS` (space
separated, every host written in full, no implicit subdomains), `OUTPUT_DIR`
(default `./audit-output`).

The file is read as data, never executed: a line that is not one of those keys
stops the run and names the line. Any other key is refused rather than ignored,
so a typo cannot leave you auditing a default you did not choose.

Set `AUDIT_PROFILE` to use a different file, for example one profile per
machine:

```bash
AUDIT_PROFILE=~/.config/audit-skills/staging.conf bash scripts/run-audit.sh
```

The example file ships every value empty. If the profile is missing, if a
required value is empty, or if it still holds the placeholder names of the
manuals (203.0.113.x, example.com, example.org, example.net, which belong to
nobody), the skill stops with a non zero exit code and an explanation. It never
falls back to a default target.

Check the profile, and the ssh client, without connecting to anything:

```bash
bash scripts/run-audit.sh --check-profile
bash scripts/run-audit.sh --check-ssh
```

## Running it

```bash
bash scripts/run-audit.sh                 # collect into $OUTPUT_DIR/raw/
bash tests/test-linux-server-audit.sh     # the test suite, no network, no server
```

Then hand `references/checks.md` and the bundle to the agent, and write the
report with `references/report-template.md`.

## Credits

The judgement in `references/checks.md` is not invented. Every check is either
drawn from a named chapter of one of these two books, and says so in
parentheses, or is an operational fact we verified ourselves, and says that
instead.

- **Mastering Linux Security and Hardening**, 3rd edition, Donald A. Tevault,
  Packt Publishing. The source for accounts and sudo, SSH hardening, firewalls,
  discretionary access control and the SUID inventory, mandatory access control,
  kernel parameters and process isolation, auditing, logging, and the scanning
  chapters. If this skill is useful to you, buy the book: it is where the
  reasoning comes from, and it explains far more than an audit checklist can.
- **Bug Bounty Bootcamp**, Vickie Li, No Starch Press. The source for the
  version to CVE reasoning and the information disclosure material used here,
  and the whole basis of the companion skill `web-security-audit`. Worth buying
  for anyone who wants to understand why these checks exist.

Neither book is redistributed here, and neither publisher endorses this skill.

## Companion skill

`web-security-audit` covers the other half: published sites, exposed panels,
certificates, security headers, files that should not be reachable, and secrets
that ended up inside pages.
