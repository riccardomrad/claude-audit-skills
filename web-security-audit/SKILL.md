---
name: web-security-audit
description: >-
  READ-ONLY security audit of the websites, web applications and admin panels
  you own: customer facing pages, marketing sites, and any exposed management
  interface. It checks the certificate, the move from cleartext to encrypted,
  security headers, cookies, cross-origin sharing, files and directories that
  should not be reachable (source control directories, environment files,
  backups, dumps, build sources), secrets and internal addresses that ended up
  inside pages, forgotten subdomains, isolation between one tenant's data and
  another's, and whether an admin panel is reachable by anyone; then it writes a
  dated report. Use this skill whenever the user says "audit the site", "check
  the security of our sites", "are our pages safe?", "how exposed are we on the
  web", "check the panels", "is the admin panel protected?", "do we have data
  exposed", "is there a file that should not be visible", "check the
  certificate", "web audit", "pen test our own sites", or when they fear a page
  has been tampered with, an old domain is in somebody else's hands, or a new
  customer is about to go live. It makes read requests only: no payloads, no
  login attempts, no fuzzing, nothing that can break or dirty production, and it
  refuses any host that is not declared in the local audit profile. It is NOT
  the server audit (that is linux-server-audit) and NOT a pre-delivery content
  check.
---

# Web security audit

You look at what the world can see of your web properties, and decide what to
close first. Read only: you observe what the sites answer to anybody, without
sending anything and without trying to get into anywhere.

## The four rules that do not bend

1. **Your own property only.** The collector accepts a host only if it matches
   the domain list in the audit profile, and refuses everything else. If you
   need a new domain, add it to the profile after checking that it is yours or
   that the customer authorised it in writing. Never work around that refusal
   with another tool: it is the difference between an internal check and
   unauthorised access. Recon on out-of-scope hosts is treated as an attack, not
   as a formality (Li ch. 5).
2. **Read only, no attacks.** GET, HEAD and OPTIONS requests. No payloads, no
   password guessing, no bursts of requests, no writes, no real messages pushed
   into a customer's flow. The reason is not only prudence: these systems send
   real messages to real people, and a test that lands in production cannot be
   undone.
3. **Secrets are reported, never copied.** If a key ended up inside a page, the
   report says where it is and what it is for, never the value. And validate
   before you alarm anybody: an expired key is not a finding, a working one is
   (Li ch. 21). If it is live, the first move is not to write it down somewhere,
   it is to rotate it.
4. **What you did not look at is not "fine".** Every skipped check goes into its
   own section of the report.

## Phase 0: decide what to check

Read `references/targets.md`. It holds the allowed-target rule and, above all,
how to rebuild the real list of the day, which changes with every new customer
or service.

Two steps worth taking every time:

1. Ask the owner which properties are live today. Fastest and most reliable
   source.
2. Look for forgotten subdomains in the public certificate logs (the command is
   in `targets.md`). They are the most dangerous ones because nobody is watching
   them, and certificate transparency plus the alternative-name field of a
   certificate is the standard way to expand from one known domain to the whole
   estate (Li ch. 5).

Check that a target is in scope before doing anything with it:

```bash
bash scripts/collect-site.sh --check-target www.example.com
```

If time is short, the order is: admin panels first, then subdomains you cannot
explain, then customer-facing applications, then marketing sites.

## Phase 1: collection (one command per host)

```bash
bash scripts/collect-site.sh <host> > bundle.txt
```

The script reads the profile, refuses undeclared hosts (including a profile
still holding the placeholder names of the manuals, which belong to nobody), and
writes the bundle into `$OUTPUT_DIR/raw/` when you let it choose the
destination:

```bash
bash scripts/collect-site.sh --save <host>
```

In that mode the collection lands beside the bundle under a `.part` name and
takes its final name, with the hour and the minute in it, only once it ends with
the completion marker. So a second run never overwrites the morning's bundle,
and a file called `bundle-site-...` is always a complete one.

Extra paths can be listed after the host, which is useful for an application
with its own data endpoints:

```bash
bash scripts/collect-site.sh app.example.com /data.json /events/app /export.pdf
```

An extra path has to start with a single `/` and stay a path: no `@`, no `://`,
no `//` at the start, no spaces. Anything else is refused before a single
request goes out, because the path is glued onto the address and curl reads
everything before an `@` as a username: `@other.example/x` would quietly send
the request to somebody else's site.

Practical notes:

- It needs `curl` and, for the certificate, `openssl`.
- Do not use `-o /dev/null` if you write curl commands by hand on Windows: under
  the MSYS environment it returns a zero size and makes you conclude a page is
  empty when it is not. The script writes to real files on purpose (verified in
  the field).
- Every bundle must end with `##### END OF COLLECTION`. If it does not, the
  collection was cut short: run it again before analysing.
- If a host does not answer, stop on that one and note it. Do not try name
  variants at random: a name that does not resolve is already information, and
  guessing looks like a scan.

## Phase 2: analysing the bundle

Read `references/checks.md` and walk the sections in order. For every item that
file says what is fine, when it is a finding, at what severity, why it matters,
and which chapter it comes from.

The two traps that cause most mistakes, both explained in there:

- **A 200 is not enough.** Many sites answer 200 to files that do not exist,
  returning the home page in disguise. Always compare size and content type
  before declaring a file exposed (verified in the field).
- **The same missing header weighs differently** on a public page and on a
  management panel. Before assigning a severity, ask what that page guards.

## Phase 3: the manual checks

They are in the last part of `checks.md` and they are the most important,
because no script can do them for you: isolation between one tenant's data and
another's, text written by a customer that could become code in the page,
authentication on webhooks, automations that fetch addresses chosen by somebody
else, and the raw responses of the endpoints a page calls.

All of them are done by reading configuration and public pages. None requires
sending data, and none should be done by pushing real messages through a live
flow.

## Phase 4: report

Follow `references/report-template.md`. Save the report in `$OUTPUT_DIR` and the
bundles in `$OUTPUT_DIR/raw/`, which is what next month's comparison uses.

Then write the deferred findings into your security roadmap, each with its
trigger. In chat report only the summary, the "fix now" table, and where you
saved the report.

## Phase 5: the fixes (this skill does not make them)

Propose the order of work and stop. Three warnings that always apply here:

- **Touching security headers can break the site.** A content security policy
  written by eye blocks the page's own scripts: turn it on in report-only mode
  first, look at what would have been blocked, then enforce it.
- **Retiring a forgotten subdomain is urgent but not trivial**: first check
  nobody is using it, then remove the record.
- **Customer-facing applications get the same care as the server**: they are in
  production and people are looking at them right now.

## What this skill does not do

- It does not attack, does not try passwords, does not send payloads, does not
  run heavy scans. If a check would require sending something, it stops and
  writes that down.
- It does not look at the server behind the sites: that is `linux-server-audit`.
- It is not a pre-delivery content check, which looks at entirely different
  things (prices, wording, translations, printed codes).
- It is not a certification and does not replace a legal review or a
  professional test commissioned from a third party.
