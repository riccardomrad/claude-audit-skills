# Checks: how to read a site bundle

Same order as the sections of `scripts/collect-site.sh`, plus a final part with
the checks no script can do on its own.

For each item: **what I look at**, **when it is a finding** and at what severity,
and **why it matters**, in words the owner can repeat to a customer.

Every check carries its source in parentheses. `(Li ch. N)` is a chapter of *Bug
Bounty Bootcamp*, Vickie Li; `(Tevault ch. N)` is a chapter of *Mastering Linux
Security and Hardening*, 3rd ed., Donald A. Tevault; `(verified in the field)` is
an operational fact we established ourselves while building and running this
collector. If a claim is neither in the books nor something we tested, it is not
a check and it does not belong here.

A citation covers the idea and the reasoning, not every string on the line. The
concrete probe lists, file names and example values are ours unless the book
names them: the books teach that build artefacts and configuration files get
left in the web root, they do not hand you the list of filenames to request.
`(our scale)` marks the severity levels, which are this skill's convention.

Two rules before starting.

**First rule: context decides severity.** The same defect weighs differently
depending on what it guards. A public catalogue page contains information that
is public by definition, so a datum that is visible there is not a leak. A panel
that commands every customer's automation is the opposite. Before writing a
finding, always ask: **what does this page guard, and who pays if somebody gets
in?** Severity is what the page holds multiplied by who the victims are (Li
ch. 6).

**Second rule: a 200 is not enough.** Many sites answer 200 to pages that do not
exist, returning the home page in disguise. Before shouting "exposed file",
compare the size of the response with the size of the home page (the collector
prints it for exactly this reason) and look at the content type: a real
environment file is a few hundred bytes of plain text, not forty kilobytes of
HTML (verified in the field).

---

## 1. Names and addresses (DNS)

**What I look at:** the A, AAAA and CNAME records of the host, and the target of
the CNAME when there is one.

- **A subdomain you cannot explain** (a test copy, an old staging name, a
  service you stopped using): **HIGH until explained**. Every subdomain is
  another way into the estate, and breadth of surface is exactly what an
  attacker maps first (Li ch. 5). Note where the name points and who runs that
  target; a name pointing at a service you no longer control is the first thing
  to sort out.
- **A CNAME pointing at a third-party service that no longer answers for that
  name, a dangling CNAME**: **CRITICAL**. This is subdomain takeover. Several
  hosting and object-storage products let anybody claim a name nobody is using,
  so whoever claims yours next serves their own content on your subdomain (some
  providers are takeable this way and some are not, which is why the target has
  to be identified before the severity is settled). The damage is not
  defacement: if any cookie of yours is scoped to the parent domain, a script
  hosted on the taken subdomain reads that shared session cookie and walks into
  every service which trusts it (Li ch. 20). The tell is usually the target's
  own error page, the "there is no site here" wording of the hosting provider,
  and the hunt starts from the full list of subdomains rather than from the site
  you already know about (Li ch. 5).
  The collector resolves the CNAME target and reports its DNS status on purpose,
  so the bundle shows the state instead of a guess (verified in the field).

## 2. From cleartext to encrypted

- **The cleartext version answers 200 and does not redirect**: **HIGH** when the
  site has any session or login, **MEDIUM** otherwise. Why it matters: the
  cleartext and the encrypted version are two different origins as far as the
  browser is concerned (Li ch. 3), and a session cookie without the `Secure`
  attribute travels over the cleartext one, where anybody on the same network
  can read it. The recommended cookie form is `Secure; HttpOnly; SameSite`
  together (Li ch. 8).
- **A redirect that lands on a host other than the expected one**: **MEDIUM**,
  and worth understanding before anything else, because a redirect whose
  destination is decided elsewhere is the raw material of the next check
  (Li ch. 7).

## 3. Security headers

These are instructions the site gives the browser. They cost nothing and remove
whole families of attacks.

| Header | If it is missing | Severity |
|---|---|---|
| `content-security-policy` | if somebody manages to get a script into the page, the browser runs it with no objection (Li ch. 6) | MEDIUM, HIGH if the page shows text written by customers |
| `x-frame-options` or CSP `frame-ancestors` | the page can be framed inside another site and clicks can be hijacked (Li ch. 8) | MEDIUM on panels, LOW on a public page |
| `referrer-policy` | the destination site sees the exact address the user came from, and that address may carry a token (Li ch. 7) | LOW, MEDIUM where authentication tokens travel in URLs |

Note on user-generated content, and it is the most important line in this table:
where the text on the page is written by a customer (through a form, a chat, an
import), that text enters the page. If it is inserted without contextual
escaping, a carefully built string becomes code running in every visitor's
browser (Li ch. 6). The real defence is escaping the text when the page is
built; the content security policy is the second net, the one that saves you
when the first one fails (Li ch. 6). That is why its absence weighs more here
than on a site whose content only you write.

Framing protection is only worth as much as the action behind the button: a
frameable page that changes a theme colour is not a vulnerability, a frameable
page that moves money or deactivates an account is (Li ch. 8). Note also that
`x-frame-options: ALLOW-FROM` is obsolete and unsupported by modern browsers, so
a page carrying only that is unprotected (Li ch. 8).

## 4. What the server reveals about itself

- **`server` or `x-powered-by` carrying a version number**: **LOW**. It is not a
  hole, it is a favour to whoever is looking for targets: the exact version maps
  straight to the published vulnerabilities of that version (Li ch. 5, Li
  ch. 21).
- **A generator header or meta tag naming the software**: **LOW**, same reason
  (Li ch. 5).

## 5. Cookies

Look at every cookie the page sets:

- **`HttpOnly` missing on a session cookie**: **HIGH**. Without it, a script
  injected into the page can read the cookie and walk away with the session of
  whoever was logged in (Li ch. 6).
- **`Secure` missing**: **HIGH** on anything that identifies a user, because the
  browser would also send it over the cleartext version (Li ch. 8).
- **`SameSite` missing, or `SameSite=None` with no reason**: **MEDIUM**. It is
  the attribute that stops another site making the browser act in your name
  using a session that is still open, and it is also what makes an authenticated
  framing attack fail (Li ch. 9, Li ch. 8). Note that browsers differ in their
  default, so "it is fine in my browser" proves nothing (Li ch. 9).

## 6. TLS certificate

**What I look at:** subject, issuer, validity dates and the alternative-name
list, which is the field that says which hostnames the certificate actually
covers (Li ch. 5).

- **Expired, or expiring within fifteen days**: **HIGH**. Report the date the
  collector read, do not guess it (verified in the field: checking certificate
  validity is part of our own routine before a site is handed over, because the
  expiry lands on a live page and nobody sees it coming).
- **The host does not appear among the covered names**: **HIGH**. Careful with
  internationalised domains: they must be checked in their punycode form, or
  they look wrong when they are not (verified in the field).

## 7. HTTP methods

- **The allowed-methods list includes `PUT`, `DELETE` or `TRACE`/`TRACK`**:
  **MEDIUM**, and worth understanding who answers. A remote scan reports
  precisely these: `PUT` lets somebody write by manipulating a URL, and an
  active `TRACK` method is reported as a cross-site tracing exposure
  (Tevault ch. 16, Tevault ch. 14). On a site of pages only, nothing beyond GET, HEAD and
  OPTIONS is needed.

## 8. Cross-origin sharing

The browser normally stops a script on one site from reading another site's
data. Sites relax that on purpose, and the relaxation is where it breaks (Li
ch. 19).

- **The site echoes back exactly the foreign origin used in the probe**, or
  allows the `null` origin, together with credentials: **CRITICAL**. It means
  any site, opened in another tab by the same logged-in user, can read the
  responses meant for yours (Li ch. 19).
- **An origin allowlist matched with a loose pattern** (anything ending in your
  domain, so `yourdomain.com.attacker.example` passes): **CRITICAL**, same
  effect (Li ch. 19).
- **`access-control-allow-origin: *`**: not exploitable for private data,
  because credentials are not sent with a wildcard. On public data it is
  deliberate; note it and move on (Li ch. 19).
- **No cross-origin headers at all**: fine, nothing is granted (Li ch. 19).

## 9. Paths that should not exist

Ordered by severity, all to be confirmed by comparing size and content type.

- **A source-control directory answering with real content** (`/.git/HEAD`,
  `/.git/config`): **CRITICAL**. With it, the entire source tree can be
  reconstructed, history included, and the history almost always contains the
  credentials somebody removed later believing they were gone (Li ch. 21). Note
  the three possible answers: not found means not public, forbidden means
  present but not listable and still reconstructible object by object, and a
  directory listing means help yourself (Li ch. 21).
- **Environment files** (`/.env` and variants): **CRITICAL**. Database keys and
  tokens live there, and an unprotected environment file is the textbook
  disclosure finding (Li ch. 21).
- **Archives and database dumps** (`/backup.zip`, `/dump.sql`): **CRITICAL**,
  same class of leak (Li ch. 21).
- **Container and package manager files** (`/docker-compose.yml`, `/Dockerfile`,
  `/.npmrc`): **HIGH**, they routinely carry credentials (Li ch. 21, Li ch. 22).
- **Status and debug endpoints** (`/server-status`, `/phpinfo.php`, `/debug`):
  **HIGH**. They describe the internal configuration, paths and private
  addresses, and debug endpoints left in production are a known developer
  mistake (Li ch. 22, Li ch. 21).
- **Dependency manifests and lock files** (`/package.json`, `/composer.json`):
  **LOW to MEDIUM**. They reveal the exact library list and versions, which is
  the same version-to-vulnerability lead as a version header (Li ch. 5).
- **An open directory listing** (a page that lists the files of a directory):
  **MEDIUM**. It shows files nobody meant to be found, including working copies
  and sources; it is a standard search-engine recon target (Li ch. 5).
- **Build sources and working directories reachable** (a sources directory, an
  extracted-files directory): **HIGH**. Published source is a source disclosure,
  and once somebody has the source they can review it for further bugs the way
  you would (Li ch. 21, Li ch. 22).
- **A path answering "forbidden" rather than "not found"**: not a finding by
  itself, but do not stop there. It means the resource exists and is protected,
  which is a signpost, not a wall (Li ch. 3, Li ch. 5).
- **Old versions of an application programming interface still answering**
  (`/api/v1/...` while `/api/v2/...` is current): **MEDIUM**. Old versions rarely
  die and often still carry the bug the new one fixed (Li ch. 24).

## 10. Secrets and internal addresses inside pages

- **A key, token or signed token found in the page source or in the scripts it
  loads**: **CRITICAL** if it is a credential that can read or write data;
  **LOW** if it is a public key meant to live in the browser. The difference is
  what it lets somebody do, not where it sits, so establish what the key is for
  before alarming anybody, and validate it: a dead key is not a finding (Li
  ch. 21). Served scripts are a goldmine for this, which is why the collector
  reads them (Li ch. 21).
- **A signed token in the page**: remember that its signature protects integrity,
  not confidentiality: the payload is only encoded and can be read by anybody,
  so anything sensitive inside it is already disclosed (Li ch. 3).
- **The server's real address, or internal network addresses, in the code**:
  **MEDIUM**. Leaked internal addresses are the map for the next step inwards
  (Li ch. 21, Li ch. 13), and when the site sits behind a proxy or a content
  network, knowing the real address lets somebody bypass it and knock on the
  machine directly.
- **Comments, paths or endpoints left in the served code**: **LOW to MEDIUM**.
  Developers document their own weak spots in comments, and the served code is
  the first place to grep for them (Li ch. 22).

## 11. Redirect parameters

- **A parameter that decides where the user is sent** (`?url=`, `?next=`,
  `?redirect=`, `?return=`, `?dest=`) that accepts an arbitrary external
  address: **MEDIUM** on its own, and always worth reporting. Why it matters: by
  itself it lands the user on a fake page that looks as if it started from your
  site; chained, it is how an allowlist gets bypassed and how a token is
  smuggled out of an authentication flow, which is exactly why it is treated as
  a trivial bug standalone and a critical link inside a chain (Li ch. 7, Li
  ch. 13). The root cause is that URL validators and browsers disagree about
  which part of a string is the hostname, so hand written validators are almost
  always bypassable (Li ch. 7). Final verification is done by hand, by looking at
  whether an external address is accepted, without building any attack.

## 12. Is the panel protected

For any exposed management interface the question is not whether the password is
strong, it is whether the login screen is reachable by anybody.

- **The application login page answers 200 directly**: **HIGH**. From that moment
  every automated attempt in the world reaches the application, and any flaw in
  it is reachable without credentials. Exposed dashboards are a standard recon
  target, found with a single search query (Li ch. 5).
- **A redirect to an external access barrier before the application**: that is
  the right behaviour, note it as healthy (verified in the field: this is the
  shape we treat as sound, an access check that answers before the application
  does).
- **A barrier that a second path walks around** (an interface or an old version
  answering 200 without passing the check): **HIGH**. Access control applied to
  the web application but not to its programming interface, or not to every
  method and version, is a documented and common mistake (Li ch. 24).
- **A page behind the login answering 200 to a request with no session at all**
  (`/dashboard`, `/account`, `/settings`, `/admin/index.php`): **HIGH**. This is
  forced browsing: the check is enforced on the login page, and the page it
  redirects to after login is left unprotected, so asking for it directly walks
  past the whole thing (Li ch. 17). Read the answer carefully before calling it,
  because this is where a soft "not found" fools you: a real leak returns the
  actual page, with data on it, not the site's generic page wearing a 200.
  Note the family this belongs to, so the manual pass in section 13 knows what
  to look for: hidden-by-obscurity addresses, an access check that is skipped
  when the request seems to come from inside, and a value the application
  trusts because the client sent it (Li ch. 17).

## 13. Checks the script cannot do (by hand, still read only)

These are the most important and they need judgement.

1. **Isolation between tenants.** Open one customer's page and change the
   identifier in the address to another customer's, everywhere it appears (page,
   data file, live-update channel, generated documents, images). Expected: you
   only ever see things that are already public. If anything operational appears
   (a management field, the owner's phone number, a working file), it is
   **CRITICAL**: that is the missing ownership check, the most common access
   control bug there is, and randomising the identifiers is only defence in
   depth, never the control itself (Li ch. 10).
2. **Customer written text that becomes code.** Look at how text somebody else
   wrote is inserted into the page: it must appear as text, with the special
   characters already neutralised. Check the same thing in generated documents
   and in translated versions. If the text lands raw in the page it is **HIGH**,
   and **CRITICAL** where the page also has an authenticated area, because then
   it reaches the session (Li ch. 6).
3. **Channels that accept commands.** Webhooks that receive events must verify
   who is calling (a signature or a shared secret) and have a rate limit. A
   webhook without authentication is a public remote control for the system.
   Verify it from the configuration, not by sending real events: **HIGH** if the
   authentication is missing, and missing rate limits on an authentication or
   data endpoint are a finding of their own (Li ch. 24).
4. **Automations that fetch addresses chosen by somebody else.** If a flow
   downloads a URL supplied from outside, that flow can be talked into knocking
   on internal services that should be unreachable, including the cloud metadata
   address that hands out credentials by default. Read it in the flow
   configuration: **HIGH** if the address is not restricted to an allowlist, and
   note that an allowlist alone is bypassable through an open redirect on an
   allowed host, so internal ranges and the metadata address have to be blocked
   as well (Li ch. 13, Li ch. 7).
5. **The raw response behind the page.** Fetch the endpoint the page itself
   calls and read the raw response, not the rendered page: an interface commonly
   returns more fields than the page shows, and private identifiers or tokens in
   that response are the whole exploit (Li ch. 24). This is a plain read
   request, so it stays inside the read-only rule.

---

## How severity is assigned

The four levels are this skill's own convention, not a quotation from either
book.

- **CRITICAL**: private data readable right now, or control of the system
  reachable by anybody. (our scale)
- **HIGH**: an important barrier is missing, or one more step gets somebody
  there. (our scale)
- **MEDIUM**: missing defence in depth, or information that helps an attacker.
  (our scale)
- **LOW**: hygiene, tidiness, good practice. (our scale)

Then the question that decides **what gets done now**: can it lose or miscount
money, make the system tell a customer something false, cross or lose one
customer's data, break privacy, open an access path, or fire something outward
that cannot be undone? If yes, fix it now. If no, it goes into the roadmap with
the trigger that says when it comes back.

## What is never reported as a defect

- That public content is publicly visible: that is the product working.
- The absence of optional niceties on pages that guard nothing: those belong in
  the advice section.
- Unverified suspicions: if the evidence is not in the bundle, write "to be
  verified", do not count it as a finding. A list of generic alarms burns trust
  in the audit, and next time nobody reads it.
- A leaked credential that no longer works: validate before reporting, an
  expired key is not a finding (Li ch. 21).
