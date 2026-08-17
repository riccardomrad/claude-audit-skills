# Checks: how to read the server bundle

One check at a time, in the same order as the sections of `scripts/collect.sh`.
For each one: **what I look at**, **when it is a finding** and at what severity,
**why it matters** (that part is for explaining it to the owner, not for you).

Every check below carries its source in parentheses. `(Tevault ch. N)` is a
chapter of *Mastering Linux Security and Hardening*, 3rd ed., Donald A. Tevault;
`(Li ch. N)` is a chapter of *Bug Bounty Bootcamp*, Vickie Li; `(verified in the
field)` is an operational fact we established ourselves while building and
running this collector. Nothing else belongs in this file: if a claim is neither
in the books nor something we tested, it does not get to be a check.

A citation covers the idea and the reasoning, not every string on the line. The
exact command spellings, container configuration keys and example values are
ours unless the book writes them that way: the book teaches which capabilities
are dangerous to hand a process, it does not name the key your container runtime
spells them with. `(our scale)` marks the severity levels, which are this
skill's own convention.

Rule before all the others: **a finding is written only if you can see it in the
bundle.** If the data is missing (command unavailable, permission denied,
truncated output) the verdict is "not verified", not "fine" and not "broken". An
audit that invents holes wastes hours; one that declares healthy what it never
looked at does worse damage.

Its other half, which decides how to read half of these sections: **what a
command printed and how it ended are two separate facts, and the bundle carries
both.** `NOT VERIFIED` means the command printed nothing and failed, so that
check never happened. A list followed by `(the command also reported an error:
the result may be incomplete)` means the opposite: those lines are real findings
that must be judged, and something else in the same command failed, so there may
be more. It is the ordinary shape of a filesystem search, which exits non zero
as soon as one of the directories it was given does not exist, while having
found everything the other directories held (verified in the field).

Note on containers: most checks (accounts, SSH, permissions, kernel) are about
the **host**. What lives inside containers is judged from the CONTAINERS
section. Do not confuse the two planes: a user inside an image is not a user of
the server.

---

## 1. Identity and versions

**What I look at:** distribution and kernel version, uptime, disk and memory,
whether `sudo` works without a password.

- **`sudo` without a password**: it is a convenience choice, not a defect by
  itself, and it is what lets this collector run unattended. It becomes a
  **HIGH** finding when it is combined with password based SSH access or with
  other accounts that also have sudo, because then whoever gets in as an
  ordinary user is already administrator with nothing left to guess.
  Password-less sudo is called out as a no-no for business use precisely
  because it removes the last checkpoint (Tevault ch. 2).
- Distribution and kernel are recorded as context for the version-to-CVE work in
  section 2, not judged on their own.

## 2. Pending updates

**What I look at:** upgradable packages, how many of them are security updates,
whether a reboot is pending, when the last upgrade ran.

- **Security updates pending on a service reachable from the internet** (SSH
  daemon, web server, kernel): **HIGH**. Why it matters: an exact version is a
  direct attack lead, because it maps straight to the published vulnerabilities
  of that version (Li ch. 5, Li ch. 21), and a remote scanner reports exactly
  this class of finding against an unpatched service (Tevault ch. 14).
- **Reboot pending for a while**: **MEDIUM**. A patched kernel that has not been
  rebooted into is still the old kernel running. Note that the reboot flag can
  exist as either of two files and checking only one of them reports "no reboot
  needed" exactly when a reboot is needed (verified in the field: this is why
  the collector checks both).
- **Old kernels never cleaned up**: **LOW**. They fill the boot partition and
  can block future kernel installs, which quietly turns into "cannot patch"
  (Tevault ch. 16).
- **Automatic security updates switched off**: **MEDIUM**. On a Debian family
  system this is the `unattended-upgrades` service plus the two
  `APT::Periodic` lines in `/etc/apt/apt.conf.d/20auto-upgrades`, and the book
  treats having them on as the normal state of a fresh install (Tevault ch. 1).
  On a machine looked after by one person, automatic security updates are the
  difference between "fixed within hours" and "fixed the next time somebody
  remembers". Read the collected values rather than assuming: the service can be
  running while the periodic settings are 0, which looks enabled and updates
  nothing.
  The same chapter raises the other half of it: updates that need a reboot do
  nothing until the machine reboots, and these systems do not reboot themselves
  unless `Unattended-Upgrade::Automatic-Reboot` is turned on. So "automatic
  updates are on" and "the patched kernel is actually running" are two separate
  questions, and the reboot check above answers the second one.

## 3. Accounts and privileges

**What I look at:** who is in the administrator group, sudo rules, the container
group, whether the root account is locked, password ageing, recent successful
and failed logins.

- **Members of the administrator group** (`sudo` on Debian and Ubuntu, `wheel`
  on the RHEL family): every member is a full administrator. The list should
  contain exactly the people who are supposed to be there, and no service
  account (Tevault ch. 2).
- **`NOPASSWD` rules for anyone other than the intended automation**: **HIGH**.
  Password-less sudo is explicitly a no-no in a business setting (Tevault ch. 2).
- **A sudo rule that lists a command without its subcommand**: **HIGH** when the
  command bundles several powers. The listing granularity *is* the security
  boundary: a command listed alone allows any subcommand, so delegating a
  service manager bare also delegates shutdown and reboot (Tevault ch. 2).
- **Root account not locked**: **HIGH** on an internet facing machine. Create
  your own sudo user and lock root, because botnets brute force exposed root
  logins constantly (Tevault ch. 2, Tevault ch. 3). In the bundle a locked
  account shows a `!` or `!!` in front of the password field (Tevault ch. 3).
- **A user in the container group**: **HIGH** unless that user is trusted and
  the choice is deliberate. Why it matters: a member of that group can start a
  container that mounts the whole host filesystem and edit the host's own
  account file to give themselves administrator rights, with no sudo at all
  (Tevault ch. 10). Adding users there as a convenience is a root grant
  (Tevault ch. 11).
- **Temporary or contractor accounts with no expiry**: **LOW**. Password expiry
  and account expiry are different things, and temporary accounts should carry
  the second one (Tevault ch. 3).
- **Floods of failed logins**: normal internet background noise, and worth
  saying so out loud, otherwise the owner is frightened every month for nothing.
  It becomes **MEDIUM** only when password authentication is still enabled,
  because that is when guessing can actually succeed; with keys only there is
  nothing for the bots to brute force (Tevault ch. 7). Failed logins are read
  from the failed-login file with `last -f /var/log/btmp` (Tevault ch. 13). If
  the machine does need password logins, automatic lockout after repeated
  failures is the countermeasure, tuned around a hundred attempts rather than
  three, so you keep the forensic trail instead of locking users out at the
  first typo (Tevault ch. 3).

## 4. SSH

This is the front door: findings here count double.

**What I look at:** the daemon's effective configuration, not the file. Commented
lines in the configuration file are live defaults, so reading `#PermitRootLogin
yes` as "not configured" is exactly how root stays reachable (Tevault ch. 7).

- **Root login permitted**: **HIGH**. Root is the one account name an attacker
  knows exists on every Linux server. `no` is the target; key-only is the
  compromise (Tevault ch. 7).
- **Password authentication enabled**: **HIGH**. Botnets scan the internet
  continuously for SSH servers that accept passwords, and that combination is
  what has handed over entire fleets. With keys only, that whole attack surface
  disappears, which is also why a non standard port and automatic banning become
  optional extras rather than necessities (Tevault ch. 7).
- **Non standard SSH port presented as a security control**: not a finding, and
  not a merit either. Internet-wide scanners index services on any port; a moved
  port is marginal cover, nothing more (Tevault ch. 7).
- **No `AllowUsers` or `AllowGroups`**: **LOW to MEDIUM**. Listing who may log in
  is finite and auditable; a deny list is never finished. Note the evaluation
  order: deny directives are checked before allow directives (Tevault ch. 7).
- **Weak algorithms** in the cipher, MAC and key exchange lists: **MEDIUM**.
  Compare against the current recommendation of AES-256 for confidentiality,
  SHA-384 for integrity and P-384 key exchange, and prune what falls short;
  SHA-1 based MACs and 64 bit UMAC are the usual leftovers (Tevault ch. 7). A
  remote scanner reports the same thing as "weak SSH encryption algorithms"
  (Tevault ch. 14).
- **Forwarding left enabled** (X11, TCP, stream local, gateway ports, tunnels):
  **MEDIUM**. X11 has remotely exploitable weaknesses, and forwarding lets a
  user tunnel back through the perimeter firewall (Tevault ch. 7).
- **Log level below verbose**: **LOW**. Verbose logging records the fingerprint
  of the key used for each login, which is what makes key management real
  (Tevault ch. 7).
- **Authorized keys file writable by its own user, or a loose `.ssh`
  directory**: **MEDIUM**. Anything a user can edit, a user can extend, so keys
  in user-writable places are user-controlled and revocation is not real. The
  hardened form is a root-owned central file plus a read-only ACL for the user
  (Tevault ch. 7, Tevault ch. 9).
- **More authorized keys than expected**: **HIGH** until each one is explained.
  Every key in that file is a person or a machine that can log in, and the only
  way revocation means anything is knowing whose each key is (Tevault ch. 7).
- **A key file for the root account**: **HIGH** if it contains keys and direct
  root access is not needed (Tevault ch. 2, Tevault ch. 7).
- **No automatic ban service installed**: not a finding when password
  authentication is off, for the reason above (Tevault ch. 7).

## 5. Firewall and listening ports

The most important check in the whole audit is not reading rules: it is
**comparing two lists**. On one side what is listening, on the other what the
firewall actually contains.

- **No default deny**: **HIGH**. The sane build order is loopback, then
  established traffic, then the services you run, then the necessary ICMP types,
  then drop everything else. Leaving the policy at accept with no final drop is
  wide open (Tevault ch. 4).
- **A service listening on every interface that is not one of your published
  services**: **HIGH** until it is shown to be needed. The question for an open
  port is not "is it vulnerable" but "why is it running at all"
  (Tevault ch. 16). Databases, caches, metrics exporters and management panels are the
  usual finds, and a database reachable from the internet is the fastest way to
  lose everyone's data at once.
- **A service listening only on the loopback address**: fine, that is the right
  way to expose an internal service (Tevault ch. 16, reading the local address
  column of the listening list).
- **The firewall front end not enforcing**: **HIGH**. The service being enabled
  is not the same as the firewall being active: check the status output, not the
  unit (Tevault ch. 5).
- **IPv4 filtered, IPv6 not**: **HIGH**. They are two separate firewalls. Rules
  written only for IPv4 leave the same port open on the other protocol, and most
  distributions enable IPv6 by default (Tevault ch. 4). The same mistake happens
  inside front ends, where the IPv6 rule file is edited less often than the IPv4
  one (Tevault ch. 5).
- **NAT table entries that publish a port you did not mean to publish**:
  **HIGH**, and **CRITICAL** when the destination is a database or an admin
  interface. Why it matters: a front end status summary is not the firewall, it
  is a rule generator's view, and the standard listing command shows only the
  filter table, so a redirection living in the NAT table is invisible to both
  (Tevault ch. 4, Tevault ch. 5). Read the NAT table explicitly and compare its
  destinations against the container port list. The fix is to publish the
  service on the loopback address rather than to add another front end rule.
- **A local firewall does not replace an external opinion**: a compromised host
  can hide its own sockets from local tools, so an external port scan is the
  second opinion the machine cannot fake (Tevault ch. 16).

Each listening socket now carries what its address means. The label states which
address the service is bound to, which is a fact the collector reads; whether a
packet from the internet actually arrives depends on the firewall, which is
section 4. Read the two together, and settle the question with an external scan
(Tevault ch. 4, ch. 16, verified in the field):

- `REACHABLE FROM OUTSIDE (wildcard address)`: the service answers on every
  address of the machine. Fine for the reverse proxy and for SSH, a finding for
  anything else, and **CRITICAL** for a database, a queue or an admin interface
  once the firewall is confirmed not to be stopping it.
- `REACHABLE FROM OUTSIDE (routable address)`: the service is bound straight to
  a public address of the host. Same judgement as above, and worth reading twice
  for one reason: a published container port is written into the NAT table and
  does not pass through the front end whose status you just read, so a ruleset
  that looks correct can still be letting this through (section 6).
- `TO VERIFY (private address: reachable from that network)`: usually a container
  bridge or a mesh VPN. Not a finding on its own, but it is not "safe" either: it
  says the service answers to whoever sits on that network, containers included.
  Compare it with the published container ports in section 6.
- `TO VERIFY (multicast or reserved address: not an ordinary service)`: a
  discovery responder (mDNS, SSDP) answering the local network. Not a finding.
  Worth one look only if you did not expect that service to exist at all.
- `LOCAL ONLY`: bound to loopback, reachable only from the machine itself.
- `UNRECOGNISED ADDRESS SHAPE (check it on the server)`: the collector could not
  read the address. It belongs to no count: go and look, and list it under what
  could not be checked. Never round it down to "fine".

An unprivileged listing is still a complete list of sockets: what it loses is the
process attribution, the name of the program behind sockets the account does not
own. So a line whose process column says the listing was read without privileges
is a socket you know about and a program you do not: chase the program, do not
discount the socket. And never read a missing line as a closed port.

## 6. Containers

- **A container that mounts the host root, or the host configuration directory,
  writable**: **CRITICAL**. Mounting the host filesystem into a container and
  editing the host account file from inside is the documented escape to
  administrator on the host (Tevault ch. 10).
- **The container daemon socket mounted inside a container**: **HIGH**. It is
  the same power that membership of the container group carries, granted to a
  process instead of to a person (Tevault ch. 10). If a socket proxy sits in
  front of it, that proxy is the mitigation: identify which container holds the
  socket and why before classifying it.
- **Extra capabilities granted** (`cap_add`) **or a container run in privileged
  mode**: **MEDIUM to HIGH** depending on which ones. Capabilities exist to hand
  out one administrator power at a time instead of all of them, so the finding
  is "which powers were granted, and why" (Tevault ch. 11).
- **The container shares the host network namespace**: **MEDIUM**. The network
  namespace is what gives a process its own interfaces, routing table and
  firewall view; sharing the host's means the container has none of its own
  (Tevault ch. 11).
- **No mandatory access control profile on the container**: **MEDIUM**.
  Mandatory access control is the layer that decides what a process may touch
  regardless of file ownership, and it is what actually blocked the container
  escape above; a path-based profile protects only what has a profile (Tevault
  ch. 10). Where the platform offers it, the daemonless container engine blocks
  that same escape even without a profile (Tevault ch. 11, Tevault ch. 14).
- **Images that have not been rebuilt for months** on an exposed service:
  **MEDIUM**. The version inside the image is the version an attacker looks up
  in the vulnerability registry (Li ch. 5, Li ch. 21).

## 7. Permissions and sensitive files

- **SUID or SGID files outside the expected set**: **HIGH** until explained. The
  normal set is a handful of system binaries (`su`, `sudo`, `passwd`, `chsh`,
  `chfn`, `gpasswd`, `newgrp`, `mount`, `umount`). Why it matters: a SUID file
  owned by root runs as root even when an ordinary user launches it, so a
  planted SUID binary is a way back in as administrator whenever the intruder
  wants, and it survives fixing the original hole (Tevault ch. 8). The real
  value of this list is the **comparison with the previous audit**: nothing
  warns you that a new SUID file appeared, the inventory-and-diff routine is the
  detection mechanism, and without last month's snapshot there is nothing to
  compare (Tevault ch. 8). Note the search must match "any of these bits"
  (`-perm /6000`), not "all of them" (`-perm -6000`), or it finds nothing
  (Tevault ch. 8).
- **World writable files**: **HIGH** when they are scripts, service units or
  configuration, because write permission on a file is permission to change what
  the server runs (Tevault ch. 8); **LOW** for data files in temporary
  directories.
- **World writable directories without the sticky bit**: **MEDIUM**. In a
  writable directory, write permission normally implies the right to delete
  anybody's file; the sticky bit is what restricts deletion to the file's owner,
  and it is why the shared temporary directory has had it forever
  (Tevault ch. 9).
- **Environment files readable by everyone** (anything wider than owner and
  group): **HIGH**. That is where database passwords and tokens live.
  Application configuration left world readable routinely carries plaintext
  database passwords (Tevault ch. 8), and an unprotected environment file is a
  textbook disclosure finding (Li ch. 21). Look at the mode, never the content.
- **Private keys outside the SSH directory, or not owner-only**: **HIGH**. A
  private key file is read-write for its owner and nobody else, and whoever
  takes the file becomes that identity (Tevault ch. 7).
- **Mount options** (`nosuid`, `nodev`, `noexec`) missing on data and temporary
  filesystems: **LOW**. Mounting a non system partition `nosuid` is the
  structural way to stop users setting the SUID bit at all, and the root
  filesystem must never carry it or the system breaks (Tevault ch. 8). On a
  single-partition machine this cannot be retrofitted: partition layout is an
  install-time decision that no remediation tool can apply afterwards (Tevault
  ch. 16), so write it as a note for a future rebuild, not as work for today.
  The same three options are the distro-independent half of "only approved
  programs run here": `noexec` on the partitions that should never execute
  anything, an allow-list daemon on the ones that legitimately hold executables
  (Tevault ch. 15). Note the limit the book itself gives: `noexec` does not stop
  a shell script invoked as an argument to the interpreter, so it raises the
  cost of running something, it does not close the door.
- **No application allow-listing at all** (no `fapolicyd`, nothing equivalent):
  **LOW** on a Debian-family machine, where the daemon is not available anyway,
  and worth a line in the advice section rather than the findings. The reason to
  keep it in view: the defence against a miner or ransomware landing on the box
  is inverted compared to antivirus, allow what you actually run and block the
  rest, because the list of what you run is finite and the list of what is
  malicious is not (Tevault ch. 15).

## 8. Encryption at rest

**What I look at:** whether any block device is encrypted, whether anything is
unlocked at boot, whether swap is encrypted, whether any home directory is.

Permissions and access control protect a running system from the people using
it. They protect nothing once somebody holds the storage itself: a stolen disk,
a snapshot, a decommissioned volume, an old backup image. Only encryption does
(Tevault ch. 6).

- **Nothing encrypted on a machine holding customer data**: **MEDIUM**, and read
  it with the threat model rather than as a rule, which is how the book frames
  the whole subject: how much of this is worth doing depends on who might get
  their hands on the storage (Tevault ch. 6). On rented infrastructure a
  passphrase-unlocked volume means somebody has to be at a console to type it at
  every boot, which is often not workable; the honest finding is then "the
  provider can read the volume and so can anyone who obtains a copy of it", and
  the answer is usually to encrypt the backups and the sensitive data rather
  than the root filesystem (verified in the field).
- **An encrypted directory or home while swap is unencrypted**: **MEDIUM**.
  Anything the machine pages out lands on that swap in clear, which quietly
  undoes the encryption above it (Tevault ch. 6).
- **`/etc/crypttab` present with entries but no matching unlocked mapping**:
  worth understanding, not automatically a finding. Persistent unlocking needs
  both the entry that unlocks and the mount that follows (Tevault ch. 6).

## 9. Kernel parameters and process isolation

These cost almost nothing: they are written in a file and apply immediately.
None of them stops an attack on its own; together they remove rungs from the
ladder an intruder climbs from ordinary user to administrator (Tevault ch. 11).

Expected values, all from the hardening table in Tevault ch. 11:

| Parameter | Expected | What it is for |
|---|---|---|
| `kernel.dmesg_restrict` | 1 | kernel messages leak information |
| `kernel.kptr_restrict` | 2 | hides kernel memory addresses |
| `kernel.randomize_va_space` | 2 | shuffles where things sit in memory, so an exploit cannot count on a fixed address |
| `kernel.yama.ptrace_scope` | 1, 2 or 3 | restricts the debugger from reading another process |
| `kernel.sysrq` | 0 | key combinations that act on the kernel, on exposed hardware |
| `fs.protected_hardlinks` / `protected_symlinks` | 1 | link-following attacks |
| `fs.suid_dumpable` | 0 | stops a crashing privileged program from writing a memory dump that holds secrets |
| `net.ipv4.tcp_syncookies` | 1 | survives connection floods |
| `net.ipv4.conf.all.rp_filter` | 1 | rejects spoofed source addresses |
| `net.ipv4.conf.all.accept_redirects` | 0 | ICMP redirects enable interception |
| `net.ipv4.conf.all.send_redirects` | 0 | this machine is not a router |
| `net.ipv4.conf.all.log_martians` | 1 | logs impossible source addresses |
| `net.ipv4.ip_forward` | 0 | unless the machine routes or runs a VPN |

One deviation is **LOW**; many together are **MEDIUM**, because that means the
subject was never addressed. Two cautions from the same chapter: a commented out
line in the configuration does not mean the feature is off, since many values
are set elsewhere or compiled in, so the live parameter dump is the only ground
truth; and hiding other users' processes with `hidepid` is unsupported and
dangerous on RHEL 9 type distributions (Tevault ch. 11).

The productive way to work this section is the scan-fix-rescan loop: a local
hardening scanner prints each parameter as matching or differing with its
expected value, you turn the differing lines into a drop-in configuration file,
reboot and rescan (Tevault ch. 11, Tevault ch. 14).

- **Mandatory access control disabled or without profiles**: **MEDIUM**. It is
  the shell that contains a compromised service: without it, a broken daemon can
  touch everything ordinary permissions allow it to. A path-based system
  protects only applications that have a profile, and shipped profiles have
  historically been buggy or intentionally empty (Tevault ch. 10).
- **Profiles in complain mode**: **LOW**. They observe and do not block, which is
  right while tuning and wrong as a final state; a machine left permissive has no
  mandatory access control at all (Tevault ch. 10).
- **File capabilities on unexpected binaries**: **MEDIUM**. Capabilities are
  administrator power sliced up and handed to a single program, and a package
  update silently drops them, so both their presence and their disappearance are
  worth knowing (Tevault ch. 11).

## 10. Services and scheduled tasks

- **Listening services nobody needs** (mail, printing, file sharing, an unused
  database): **MEDIUM**. Every one of them is reachable code, and the question
  is why it is running at all (Tevault ch. 16).
- **Scheduled jobs you cannot account for**: **HIGH** until each is recognised.
  Every entry runs code on a schedule as some user. Treat this list the way you
  treat the SUID list: take the inventory, compare it with the previous audit,
  and investigate what appeared (Tevault ch. 8, applying the same
  inventory-and-diff routine).

## 11. Logging and traceability

- **Logs kept only on the machine that produced them**: **MEDIUM**. Plaintext
  files, a text editor and administrator access is the whole attack: an intruder
  edits themselves out. Shipping logs to another machine is the countermeasure,
  and encrypting the transport keeps them confidential on the way
  (Tevault ch. 13).
- **Short journal retention, or a volatile journal**: **MEDIUM**. On the RHEL
  family the journal is volatile by default and does not survive a reboot
  (Tevault ch. 13). Intrusions are usually discovered weeks later; if the logs
  cover three days there is nothing left to read.
- **Administrators working from a root shell instead of sudo**: **MEDIUM**. Sudo
  is a logging control as much as an access control: it records every privileged
  command and who ran it, while a root login records only the login
  (Tevault ch. 13).
- **Kernel level auditing absent**: **LOW** on a small machine. It is the tool
  that records who touched which file and it is hard to subvert, but it is also
  noisy, and auditing everything produces an unreadable log and a measurable
  cost (Tevault ch. 12). Note it, do not call it a hole.

## 12. Security tooling present

The absence of scanners is **not a finding**. Put them in the advice section:

- A local hardening scanner run monthly gives warnings, suggestions with control
  identifiers, and a hardening index, but it reports and never fixes; chasing
  the index as a score wastes effort (Tevault ch. 14).
- Antivirus on a Linux server exists to avoid passing infected files to Windows
  machines, so it belongs on file, mail and download servers and not on a
  machine that serves neither (Tevault ch. 12). Its absence elsewhere is not a
  defect.
- Rootkit scanners are table stakes, not defence: a rootkit requires the
  attacker to already have administrator rights, and many are simply not
  detected, so keeping them out is the real control (Tevault ch. 12).

## 13. Network and exposure

- **Established connections to addresses you cannot explain**: **MEDIUM**, and
  usually legitimate (updates, offsite backup, webhooks). Look up unfamiliar
  ports in the services file before deciding anything, and report only what you
  cannot explain (Tevault ch. 16).
- **Connection states worth recognising** while reading that list: established,
  outbound attempt in progress, and half-closed sockets (Tevault ch. 16).

---

## How severity is assigned, and what actually blocks

Four levels, plus one question that decides what gets done now. The scale
itself is this skill's own convention, not a quotation from either book: it
exists so two audits months apart rank the same finding the same way.

- **CRITICAL**: somebody can get in or take control today, with nothing left to
  guess. (our scale)
- **HIGH**: an important barrier is missing, or an attacker needs one more step.
  (our scale)
- **MEDIUM**: missing defence in depth, or something that makes a problem much
  harder to notice. (our scale)
- **LOW**: hygiene, tidiness, good habits. (our scale)

Then the question that really decides: **can this finding lose or miscount
money, make the system tell somebody something false, cross or lose one
customer's data, break privacy, open an access path, or fire something outward
that cannot be undone?**

- Yes to any of those: **fix it now**, whatever the level says.
- No to all of them: it becomes written debt in the roadmap, with the trigger
  that says when to pick it up again.

There is no such thing as an audit without minor findings. If every line found
becomes urgent work, nobody runs the audit again next month.
