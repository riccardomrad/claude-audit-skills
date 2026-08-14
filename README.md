# claude-audit-skills

Two read-only security audit skills for coding agents. One looks at a Linux
server you administer, the other at the websites and admin panels you own.

Each one collects evidence with a shell script you can read, judges it against a
reference file whose every check names the chapter it comes from, and writes a
dated report split into two lists: what to fix now, and what is written debt
with a trigger that says when it comes back.

## Use this only on systems you own

Both skills refuse any target that is not declared in your local profile, and
that refusal is the safety model, not a formality. Auditing a machine or a site
you neither own nor administer is unauthorised access in most places, whatever
a tool promises about being read-only. If you did not set it up, and nobody put
in writing that you may test it, do not point these at it.

## The two skills

**[`linux-server-audit`](linux-server-audit/)**, over SSH: the SSH configuration
actually in effect, accounts and privilege paths, firewall rules and listening
ports (IPv4 and IPv6, filter and NAT), containers and what they mount, file
permissions and the SUID inventory, kernel hardening parameters, mandatory
access control, scheduled tasks, logging, pending updates.

**[`web-security-audit`](web-security-audit/)**, over HTTPS: the certificate and
the names it covers, the move from cleartext to encrypted, security headers,
cookies and their attributes, allowed methods, cross-origin sharing, paths that
should not be reachable (source control directories, environment files,
backups, dumps, debug endpoints, build sources), open directory listings,
secrets and internal addresses that ended up inside served pages, forgotten
subdomains, redirect parameters, and whether an exposed panel sits behind a
barrier.

Each folder has its own README with the full detail.

## The read-only promise

Nothing here writes, deletes, restarts, installs, or changes configuration.

- The server collector is piped to `ssh` on standard input, so it is never
  copied onto the machine and leaves nothing behind.
- The web collector sends GET, HEAD and OPTIONS only. No payloads, no login
  attempts, no fuzzing, and a pause between requests, so an audit never looks
  like a scan. Third party scripts are listed, never fetched: fetching them
  would be a request to somebody else's site.
- Secrets are never collected whole. Sensitive files are reported by name,
  owner and mode, never content. A secret found inside a page is printed masked
  (first characters plus length), so the bundle tells you it exists without
  carrying it around. Addresses in session and login lists are masked.
- A command that fails is reported as NOT VERIFIED. Neither skill turns a
  missing answer into a clean bill of health.

Both collectors ship as readable shell scripts on purpose: read them before you
run them.

## Install

```bash
git clone https://github.com/riccardomrad/claude-audit-skills.git
cp -r claude-audit-skills/linux-server-audit  ~/.claude/skills/
cp -r claude-audit-skills/web-security-audit  ~/.claude/skills/
```

Any agent that reads `SKILL.md` files can use them. The collectors are plain
bash and run on their own too, agent or no agent.

Needed locally: `bash`, `ssh`, `curl`, `openssl`, `awk`, `sed`. Nothing gets
installed on the audited server: the collector uses commands that are already
there, and reports the ones that are missing instead of adding them.

## Fill in the profile first

Both skills read the same profile file, so you fill it in once. Without it they
stop.

```bash
mkdir -p ~/.config/audit-skills
cp claude-audit-skills/linux-server-audit/profile.example.conf ~/.config/audit-skills/profile.conf
$EDITOR ~/.config/audit-skills/profile.conf
```

| Key | Meaning |
|---|---|
| `SSH_HOST` | Hostname or IP of the machine you audit. |
| `SSH_PORT` | SSH port, 22 if left out. |
| `SSH_USER` | Login user. Passwordless sudo, or the privileged sections come back as NOT VERIFIED, which is the honest answer. |
| `ALLOWED_DOMAINS` | Space separated list of the domains you own. Any target outside it is refused. |
| `OUTPUT_DIR` | Where bundles and reports are written, `./audit-output` by default. |

The example file ships every value empty. An empty value, or one still holding
the placeholder names of the manuals (`203.0.113.x` from RFC 5737,
`example.com`, `example.org`, `example.net` from RFC 2606), makes the skill stop
with a non zero exit code and an explanation. There is no fallback target: a
run that audits nothing must never look like a run that worked.

Set `AUDIT_PROFILE` to point at a different file, one per machine if you like.

Check the profile without connecting to anything:

```bash
bash linux-server-audit/scripts/run-audit.sh --check-profile
bash linux-server-audit/scripts/run-audit.sh --check-ssh
bash web-security-audit/scripts/collect-site.sh --check-target www.yourdomain.com
```

## Tests

353 checks, no network and no server needed:

```bash
bash linux-server-audit/tests/test-linux-server-audit.sh   # 188
bash web-security-audit/tests/test-web-security-audit.sh   # 165
```

## Credits, and please buy the books

The judgement in these skills is not invented. Every check either names the
chapter of the book it comes from, in parentheses, or says instead that it is
an operational fact verified in the field.

- **Mastering Linux Security and Hardening**, 3rd edition, Donald A. Tevault,
  Packt Publishing. The source for accounts and sudo, SSH hardening, firewalls,
  discretionary access control and the SUID inventory, mandatory access
  control, kernel parameters and process isolation, auditing, logging, and the
  scanning chapters.
- **Bug Bounty Bootcamp**, Vickie Li, No Starch Press. The source for
  reconnaissance, cross-site scripting and content security policy, framing,
  cross-site request forgery and cookie attributes, broken object-level access
  control, server-side request forgery, same-origin policy and cross-origin
  sharing, information disclosure, code review and interface hacking.

If these skills are useful to you, buy both books. A checklist tells you what to
look at; the books tell you why it matters and what to do when the answer is
bad, which is the part no audit script can carry. Neither book is redistributed
here, in whole or in part, and neither publisher endorses this project.

## Licence

MIT, see [LICENSE](LICENSE).
