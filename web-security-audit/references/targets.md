# What gets checked, and how you know what actually exists

## The allowed-target rule

The collector accepts only hosts that match a domain in `ALLOWED_DOMAINS` in the
audit profile, or a subdomain of one. It refuses everything else, and that is
not a formality: a tool that poked around somebody else's site, even by accident
and even only reading, is a legal problem, not a technical mistake. Recon
against a host you have no permission for counts as an attack on it (Li ch. 5).

To check a new domain (a customer with a domain of their own), add it to
`ALLOWED_DOMAINS` after verifying it is yours or that the customer authorised it
in writing. Do not work around the refusal with another tool.

The name is normalised before the check (scheme, credentials, path, query,
fragment, port, trailing dot, capitals) and only then compared with the list, so
neither `evil.example/?x=.yourdomain.com` nor `yourdomain.com@evil.example`
sneaks through, and `YOURDOMAIN.COM` is not refused for being uppercase
(verified in the field: every one of those forms is a test case in
`tests/test-web-security-audit.sh`).

## How the list of the day is built

**This page does not contain the target list, and must not.** A hand written
list ages at the first new customer, and an audit run against an old list is
worse than no audit: it carefully checks things that no longer exist and misses
what went live last week. Rebuild it every time, in this order:

1. Ask the owner which properties are live today. Fastest and most reliable
   source.
2. Derive the tenants from the source repository rather than from memory: an
   application that serves one site per customer has one directory, one
   configuration entry or one database row per customer, and that identifier is
   the public name of the site. Check the deployment state as well: a prepared
   tenant is not necessarily a live one.
3. Add the fixed pieces that are not customers: the management panels, the
   marketing sites, and any mirror or failover copy. They are always the same,
   but they are worth more than everything else, because whoever gets into a
   panel does not steal one page, they take control of the whole estate.
4. Look for forgotten subdomains, which are the most dangerous precisely because
   nobody remembers them. A read-only way to find them is the public
   certificate transparency logs, which list every name a certificate was issued
   for, and the alternative-name field of the certificate itself (Li ch. 5):

   ```bash
   curl -sS 'https://crt.sh/?q=%25.example.com&output=json' \
     | tr ',' '\n' | grep -i name_value | sort -u | head -40
   ```

   Run it once per domain in `ALLOWED_DOMAINS`. Every name you cannot explain is
   worth looking at: this is how you find leftover test copies and subdomains
   pointed at services you stopped using.

## Priority of what you found

Priority does not come from the host name, it comes from what the host guards.
Put every target of the day into one of these categories:

| Category | What it guards | Priority |
|---|---|---|
| Management panels (automation, infrastructure, CMS admin) | control of the servers and of every customer's automation | **highest** |
| Paying customers' applications | their data and the service they pay for | **high** |
| Mirrors and failover copies | keeps the service up when the main one is down | medium |
| Marketing sites | the shop window and the contact form | medium |
| Subdomains you cannot explain | unknown, and that is exactly the problem | **high until explained** |

Order when checking everything: panels, then unexplained subdomains, then
customer applications, then the rest. If time is short, stop after the first two
groups and write that in the report.

## A note on internationalised domains

A domain with accented or non-Latin characters travels on the network in its
punycode form (`xn--...`). Requests and the certificate check must be made
against that form, otherwise everything looks broken while it is working
perfectly. It is worth checking the plain-ASCII alias too, because the two
addresses often have different configurations and one of them falls behind
(verified in the field).
