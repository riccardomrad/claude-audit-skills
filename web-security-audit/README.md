# web-security-audit

A read-only security audit of the websites, applications and admin panels you
own, packaged as an agent skill. One command per host collects what the site
answers to anybody, a reference file says how to read every section, and a
template turns the result into a dated report split into "fix now" and "written
debt with a trigger".

## What it does

Collects and judges: DNS records and forgotten subdomains, the move from
cleartext to encrypted, security headers, cookies and their attributes, the TLS
certificate and the names it covers, allowed HTTP methods, cross-origin sharing,
paths that should not be reachable (source-control directories, environment
files, backups, dumps, debug endpoints, build sources), open directory listings,
secrets and internal addresses inside served pages and scripts, redirect
parameters, and whether an exposed panel sits behind a barrier.

## The read-only promise

GET, HEAD and OPTIONS only. No payloads, no login attempts, no bursts: there is
a pause between requests so an audit never looks like a scan. It does ask for a
fixed, short list of well known paths that should not answer (`/.git/HEAD`,
`/.env`, `/backup.zip`, `/admin`: about forty in all), plus eight directories
asked for a listing, with plain read requests: that is how a published source
control directory gets found. Both lists are written in
`scripts/collect-site.sh` for you to read.
Scripts hosted by third parties are listed, never fetched, because fetching them
would be a request to somebody else's site. Secrets found inside pages are
printed masked (first characters plus length), so the bundle tells you they
exist without carrying them around.

And the hard boundary: the collector refuses any host that is not in your
profile's domain list. The name is normalised first (scheme, credentials, path,
query, fragment, port, trailing dot, capitals) and only then compared, so the
usual tricks for smuggling a foreign host past a filter do not work. That
refusal is the difference between an internal check and unauthorised access.

One exception, stated here so the sentence above stays true as written: the DNS
lookups go to a public resolver over HTTPS, which is a host you did not declare.
No content of yours is sent there, only the name being looked up, exactly as any
DNS query does. If even that is more than your rules allow, point those two
lookups at your own resolver, or drop that section.

## Setting up the profile

```bash
mkdir -p ~/.config/audit-skills
cp profile.example.conf ~/.config/audit-skills/profile.conf
$EDITOR ~/.config/audit-skills/profile.conf
```

Keys: `WEB_TARGETS` (space separated, every host written in full, no implicit
subdomains: `radlab.it` does not cover `www.radlab.it`), `OUTPUT_DIR`
(default `./audit-output`), and optionally `SSH_HOST`, `SSH_PORT`, `SSH_USER`,
which the companion server skill uses and which let this one flag your origin
server's address if it shows up inside a page.

Set `AUDIT_PROFILE` to use a different file. The example file ships every value
empty. If the profile is missing, if the domain list is empty, or if it still
holds the placeholder names of the manuals (example.com, example.org,
example.net, 203.0.113.x, which belong to nobody), the skill stops with a non
zero exit code and an explanation. It never falls back to a default target.

With `--save` the bundle is written aside as a `.part` file and takes its final
name, `bundle-site-<host>-<date>-<hour><minute>.txt`, only once it ends with the
completion marker. Two runs on the same day therefore no longer share a name,
and a run that fails halfway leaves the earlier collection intact.

## Running it

```bash
bash scripts/collect-site.sh --check-target www.example.com   # in scope or not
bash scripts/collect-site.sh www.example.com > bundle.txt     # to stdout
bash scripts/collect-site.sh --save www.example.com           # into $OUTPUT_DIR/raw/
bash scripts/collect-site.sh app.example.com /data.json /export.pdf
bash tests/test-web-security-audit.sh                         # tests, no network
```

Then hand `references/checks.md` and the bundle to the agent, and write the
report with `references/report-template.md`.

## Credits

The judgement in `references/checks.md` is not invented. Every check is either
drawn from a named chapter of one of these two books, and says so in
parentheses, or is an operational fact we verified ourselves, and says that
instead.

- **Bug Bounty Bootcamp**, Vickie Li, No Starch Press. The source for
  reconnaissance, cross-site scripting and content security policy, framing,
  cross-site request forgery and cookie attributes, broken object-level access
  control, server-side request forgery, same-origin policy and cross-origin
  sharing, information disclosure, code review and interface hacking. If this
  skill is useful to you, buy the book: it explains why each of these checks
  exists, which a checklist never can.
- **Mastering Linux Security and Hardening**, 3rd edition, Donald A. Tevault,
  Packt Publishing. The source for the risky HTTP methods reported by remote
  scanners here, and the whole basis of the companion skill
  `linux-server-audit`. Worth buying for anyone who runs the machine underneath
  the site.

Neither book is redistributed here, and neither publisher endorses this skill.

## Companion skill

`linux-server-audit` covers the other half: the machine behind the sites, its
SSH access, firewall, containers, permissions, kernel parameters and logs.
