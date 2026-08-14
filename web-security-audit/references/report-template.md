# Report template (web audit)

Copy the structure, fill in only what you actually verified. Plain language, no
unexplained acronyms.

---

```markdown
# Web security audit, <date>

Properties checked: <list of hosts, one per line>
Collection: <bundle files used>
Compared with: <previous audit, or "first audit">
Every check was read only: nothing sent, no access attempted, nothing changed.

## In two lines

<General state in human words. Example: "The customer applications are clean and
protected. The automation panel sits behind a barrier and is fine. One thing has
to be closed today: an old subdomain pointing at nothing.">

## Fix now

| # | Where (host) | What | Severity | What happens if it stays | How to fix it |
|---|--------------|------|----------|--------------------------|---------------|
| 1 | <host> | <description> | CRITICAL | <concretely: who gets in, what they see, who pays for it> | <step> |

If it is empty, say so: "Nothing to fix right now."

**How each row is written.** A finding is only worth as much as the reader's
ability to act on it, so borrow the discipline of a vulnerability report
(Li ch. 2):

- **The title says what and where**, not how bad it feels. "Backup archive
  readable at `/backup.zip` on the customer site" beats "critical exposure".
- **Reproduction assumes no prior knowledge**: the exact address, and the
  prerequisites, so somebody else can see it for themselves.
- **Impact is a separate thing from severity.** Severity ranks the queue;
  impact describes what actually happens, escalated as far as is realistic and
  never hypothetical. A row that only carries a severity tells the owner
  nothing they can weigh.
- **Suggest a direction, not an implementation**, and skip the suggestion
  entirely when the root cause is not understood. A confident wrong fix costs
  more than an honest blank.
- **Validate before sending**: re-request every address in the table and
  re-read every quoted response. A finding that no longer reproduces, or a
  wrong address, burns the credibility of the whole report.

Severity is calibrated the same way: what the page holds, multiplied by how
many people it affects (Li ch. 2).

## Can wait (goes into the roadmap)

| # | Where | What | Severity | When to pick it up (trigger) |
|---|-------|------|----------|------------------------------|
| 1 | <host> | <description> | MEDIUM | <precise event> |

## Result per property

A summary table, so the state is visible at a glance:

| Host | Certificate | Cleartext to encrypted | Headers | Exposed files | Secrets in pages | Notes |
|------|-------------|------------------------|---------|---------------|------------------|-------|
| <host> | valid until <date> | ok | 3 of 5 present | none | none | |

## Manual checks

<Tenant isolation, customer written text that could become code, webhook
authentication, automations that fetch external addresses, raw endpoint
responses. For each one: what I tried, what I saw, verdict.>

## What I could NOT check

<Unreachable hosts, pages behind authentication, checks postponed. This section
is never skipped.>

## Compared with the previous audit

- Closed since then: <list>
- Still open: <list>
- New since then: <list, paying attention to new subdomains>

## Advice, not defects

<Things that would improve the situation without their absence being a hole: a
periodic subdomain review, tightening a policy that is currently permissive, and
similar.>
```

---

## File names

- Report: `$OUTPUT_DIR/web-security-audit-<YYYY-MM-DD>.md`
- Raw data: `$OUTPUT_DIR/raw/bundle-site-<host>-<YYYY-MM-DD>.txt`

Use the directories from the profile, the same ones in every phase. The raw data
is what next month's comparison uses: that is how you notice a new subdomain or
a header that disappeared after a release.

**Never put a secret found during the audit into a file.** The collector already
prints them masked; the report says where it is and what it is for, never the
value. If the secret is real and live, the first thing to do is not to write it
down, it is to rotate it.

## Roadmap lines

One line per deferred finding:

```
- [ ] <what> on <host> (web audit <date>, severity <level>). Comes back when: <trigger>.
```
