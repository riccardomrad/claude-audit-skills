# Report template (server audit)

Copy this structure and fill in only what you actually verified.
Plain language: somebody who does not do this for a living has to understand it.

---

```markdown
# Server security audit, <date>

Host: <host from the profile>
Collection: <bundle file used>, <time>
Compared with: <previous audit, or "first audit, no comparison">
Every check was read only: nothing was modified, restarted or deleted.

## In two lines

<General state in human words. Example: "The server is in good shape: the front
door is locked and updates are recent. Two things need fixing tonight, four can
wait.">

## Fix now

| # | What | Severity | Why it is a problem | How to fix it |
|---|------|----------|---------------------|---------------|
| 1 | <short description> | CRITICAL | <in plain words> | <command or step, with the risk of the change> |

If the table is empty, say so in words: "Nothing to fix right now."

**How each row is written.** Borrow the discipline of a vulnerability report,
because a finding is worth only what the reader can act on (Li ch. 2):

- **The title says what and where**, not how bad it feels. "PostgreSQL port
  reachable from any address" beats "critical database exposure".
- **Reproduction assumes no prior knowledge**: the command that shows it, and
  the line of the bundle it came from, so somebody else can see it too.
- **Impact is a separate thing from severity.** Severity ranks the queue;
  impact says what actually happens, as far as is realistic and never
  hypothetical.
- **Suggest a direction, not an implementation**, and skip the suggestion when
  the root cause is not understood. On a server a confident wrong fix takes the
  machine down.
- **Validate before sending**: re-read the bundle lines you quoted. A finding
  that turns out to be a truncated output makes the owner distrust the next
  nine that are real.

## Can wait (goes into the roadmap)

| # | What | Severity | When to pick it up (trigger) |
|---|------|----------|------------------------------|
| 1 | <description> | MEDIUM | <precise event, for example "before the second customer with a database of their own"> |

A deferral without a trigger is never reopened: either write when it comes back,
or drop it entirely.

## Checked and fine

Short, concrete list, so it is clear what was actually looked at:
- SSH access: <one line result>
- Firewall and exposed ports: <result>
- Containers: <result>
- Updates: <result>
- Permissions and sensitive files: <result>
- Logging and traceability: <result>

## What I could NOT check

<Commands unavailable, truncated output, permission denied. This section is
never skipped: it is the difference between "fine" and "not looked at".>

## Compared with the previous audit

- Findings closed since then: <list>
- Findings still open: <list>
- New since then: <list, paying attention to new SUID files and new listening
  services; a new root owned SUID file that nobody installed is the single most
  important line in this report>

## Advice, not defects

<Things that would improve the situation but whose absence is not a hole: a
periodic local hardening scan, shipping logs off the machine, and similar.>
```

---

## File names

- Report: `$OUTPUT_DIR/server-security-audit-<YYYY-MM-DD>.md`
- Raw data: `$OUTPUT_DIR/raw/bundle-server-<YYYY-MM-DD-HHMM>.txt`

Use the directories from the profile, the same ones in every phase (the wrapper
creates them before writing). Do not reuse a report name that another tool on
the same machine already writes: two different files with the same name end up
overwritten or swapped (verified in the field).

The raw data is kept because the next audit compares against it. The most
valuable comparison is SUID files and listening ports: that is how you find out
something changed without anybody changing it (Tevault ch. 8).

**Before saving the raw bundle, check that it contains no secrets.** The
collector gathers only names and permissions, but if a command is added later
the rule stays the same: no `.env` contents, no keys, no password hashes, no
tokens.

## Roadmap lines

One line per deferred finding:

```
- [ ] <what> (server audit <date>, severity <level>). Comes back when: <trigger>.
```
