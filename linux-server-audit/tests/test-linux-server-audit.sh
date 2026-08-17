#!/usr/bin/env bash
# =============================================================================
# Tests for linux-server-audit.
#
# Touches NO network and NO server: it loads the collector functions only
# (AUDIT_FUNCTIONS_ONLY=1) and exercises them against fake data written here,
# plus the wrapper in profile-check mode, which never connects to anything.
#
#   bash tests/test-linux-server-audit.sh
#
# Exits 0 when every test passes, 1 when at least one fails.
# =============================================================================
set -u
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
COLLECT="$SKILL/scripts/collect.sh"
RUNNER="$SKILL/scripts/run-audit.sh"
SKILL_MD="$SKILL/SKILL.md"
CHECKS="$SKILL/references/checks.md"
TEMPLATE="$SKILL/references/report-template.md"
EXAMPLE="$SKILL/profile.example.conf"

ok=0; ko=0

expect() {   # expect <description> <expected> <actual>
  if [ "$2" = "$3" ]; then
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  else
    ko=$((ko+1)); printf 'KO    %s\n        expected: [%s]\n        actual:   [%s]\n' "$1" "$2" "$3"
  fi
}

expect_nonzero() {   # expect_nonzero <description> <exit code>
  if [ "$2" -ne 0 ] 2>/dev/null; then
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  else
    ko=$((ko+1)); printf 'KO    %s\n        expected a non zero exit code, got [%s]\n' "$1" "$2"
  fi
}

contains() {   # contains <description> <needle> <haystack>
  case "$3" in
    *"$2"*) ok=$((ok+1)); printf 'ok    %s\n' "$1" ;;
    *) ko=$((ko+1)); printf 'KO    %s\n        missing [%s] in [%s]\n' "$1" "$2" "$3" ;;
  esac
}

lacks() {   # lacks <description> <forbidden> <haystack>
  case "$3" in
    *"$2"*) ko=$((ko+1)); printf 'KO    %s\n        found the forbidden fragment [%s] in [%s]\n' "$1" "$2" "$3" ;;
    *) ok=$((ok+1)); printf 'ok    %s\n' "$1" ;;
  esac
}

file_has() {   # file_has <description> <regex> <file>
  if grep -qE "$2" "$3" 2>/dev/null; then
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  else
    ko=$((ko+1)); printf 'KO    %s\n        %s does not contain /%s/\n' "$1" "$3" "$2"
  fi
}

file_lacks() {   # file_lacks <description> <regex> <file>
  if grep -qE "$2" "$3" 2>/dev/null; then
    ko=$((ko+1)); printf 'KO    %s\n        %s still contains /%s/\n' "$1" "$3" "$2"
  else
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  fi
}

expect_lt() {   # expect_lt <description> <line that must come first> <line that must come after>
  if [ "${2:-0}" -gt 0 ] 2>/dev/null && [ "${3:-0}" -gt 0 ] 2>/dev/null && [ "$2" -lt "$3" ]; then
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  else
    ko=$((ko+1)); printf 'KO    %s\n        line %s does not come before line %s\n' "$1" "${2:-none}" "${3:-none}"
  fi
}

matches() {   # matches <description> <regex> <string>
  if printf '%s' "$3" | grep -qE "$2"; then
    ok=$((ok+1)); printf 'ok    %s\n' "$1"
  else
    ko=$((ko+1)); printf 'KO    %s\n        [%s] does not match /%s/\n' "$1" "$3" "$2"
  fi
}

# --- loading the functions ---------------------------------------------------
# The guard has to exist BEFORE sourcing: without it, sourcing the collector
# would start a real collection on this machine.
if ! grep -q 'AUDIT_FUNCTIONS_ONLY' "$COLLECT" 2>/dev/null; then
  printf 'KO    guard AUDIT_FUNCTIONS_ONLY missing in %s: sourcing nothing.\n' "$COLLECT"
  exit 1
fi
# shellcheck disable=SC1090
AUDIT_FUNCTIONS_ONLY=1 . "$COLLECT" || { echo "KO    cannot load $COLLECT"; exit 1; }

t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT

# The wrapper is always called in profile-check mode and with a clean
# environment, so a test can never open a connection to anything.
profile_check() {   # profile_check <profile path>
  env -u SSH_HOST -u SSH_USER -u SSH_PORT -u OUTPUT_DIR -u ALLOWED_DOMAINS \
      AUDIT_PROFILE="$1" bash "$RUNNER" --check-profile 2>&1
}
profile_rc() {   # profile_rc <profile path>
  profile_check "$1" >/dev/null 2>&1; printf '%s' "$?"
}

echo
echo '=== PROFILE: nothing runs against an undeclared target ==='
out="$(profile_check "$t/does-not-exist.conf")"
expect_nonzero 'missing profile: exit code is not zero' "$(profile_rc "$t/does-not-exist.conf")"
contains 'missing profile: the message names the profile' 'no audit profile found' "$out"

printf 'SSH_HOST="203.0.113.10"\nSSH_USER="auditor"\nALLOWED_DOMAINS=""\n' > "$t/empty-domains.conf"
out="$(profile_check "$t/empty-domains.conf")"
expect_nonzero 'empty domain list: exit code is not zero' "$(profile_rc "$t/empty-domains.conf")"
contains 'empty domain list: the message names ALLOWED_DOMAINS' 'ALLOWED_DOMAINS' "$out"

printf 'SSH_USER="auditor"\nALLOWED_DOMAINS="example.com"\n' > "$t/no-host.conf"
expect_nonzero 'profile without SSH_HOST: exit code is not zero' "$(profile_rc "$t/no-host.conf")"

# A profile that is really filled in: no documentation address, no reserved
# example domain. Those are what the example file carries, and a profile still
# carrying them is a profile nobody ever filled in (see the section below).
printf 'SSH_HOST="10.9.8.7"\nSSH_PORT="2222"\nSSH_USER="auditor"\nALLOWED_DOMAINS="ourshop.test ourblog.test"\nOUTPUT_DIR="%s/out"\n' "$t" > "$t/good.conf"
out="$(profile_check "$t/good.conf")"
expect  'complete profile: exit code is zero'         0 "$(profile_rc "$t/good.conf")"
contains 'complete profile: the target host is shown' '10.9.8.7' "$out"
contains 'complete profile: the port is shown'        '2222' "$out"
contains 'complete profile: the output directory is shown' "$t/out" "$out"
contains 'complete profile: the allowed domains are shown' 'ourblog.test' "$out"
file_has 'the default profile path is the shared one' 'config/audit-skills/profile.conf' "$RUNNER"

echo
echo '=== COLLECTOR: reboot pending ==='
: > "$t/reboot-required"
expect 'reboot required even when the .pkgs file is missing' 'REBOOT_REQUIRED' \
  "$(verdict_reboot "$t/reboot-required" "$t/reboot-required.pkgs")"
expect 'neither file: no reboot pending' 'no reboot pending' \
  "$(verdict_reboot "$t/missing-1" "$t/missing-2")"

echo
echo '=== COLLECTOR: masking ==='
masked="$(printf 'Aug 14 13:45:22 srv sshd[1]: Accepted publickey for auditor from 203.0.113.7 port 51334 ssh2\n' | mask_ip)"
lacks   'session IP masked'                '203.0.113.7' "$masked"
contains 'a marker is left where the IP was' 'IP-MASKED'  "$masked"
contains 'the timestamp survives masking'    '13:45:22'   "$masked"
masked6="$(printf 'from 2001:db8:1c1c::2 port 2222\n' | mask_ip)"
lacks   'IPv6 masked too'                    '2001:db8'   "$masked6"

# A Defaults line sets an option, it grants nothing to nobody: counting it as a
# rule inflates the count and puts the word "Defaults" in the list of who can
# become administrator. Two real rules here, not four.
sudoers="$(printf '# comment\nDefaults\tenv_reset\nDefaults:auditor !requiretty\nauditor ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app\n%%sudo ALL=(ALL:ALL) ALL\n' | summarize_sudoers)"
lacks   'sudo rule text not quoted'          '/usr/bin/systemctl' "$sudoers"
contains 'sudo: only real rules are counted' 'sudo rules: 2'      "$sudoers"
lacks   'sudo: Defaults is not a principal'  'Defaults'           "$sudoers"
contains 'sudo: the real principals are listed' '%sudo'           "$sudoers"
contains 'sudo: NOPASSWD reported'           'NOPASSWD present: yes' "$sudoers"

# A user crontab: schedule then command, with no user column in between.
cron="$(printf '# backup\n0 3 * * * /opt/app/backup.sh --token=abc123XYZ\n' | summarize_cron)"
lacks   'cron: arguments (and tokens) not quoted' 'abc123XYZ' "$cron"
contains 'cron: schedule reported'                '0 3 * * *' "$cron"
contains 'cron: command name reported'            'backup.sh' "$cron"

fstab="$(printf '# /etc/fstab\nUUID=1234-abcd-5678 / ext4 defaults 0 1\n' | summarize_fstab)"
lacks   'fstab: device identifier masked'   '1234-abcd-5678' "$fstab"
contains 'fstab: mount options reported'    'defaults'       "$fstab"

echo
echo '=== COLLECTOR: listening ports ==='
fake_ss='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      4096   127.0.0.1:5432      0.0.0.0:*         users:(("postgres",pid=1,fd=7))
tcp   LISTEN 0      511    0.0.0.0:80          0.0.0.0:*         users:(("nginx",pid=2,fd=6))
tcp   LISTEN 0      511    *:8080              *:*               users:(("java",pid=3,fd=9))
tcp   LISTEN 0      128    [::]:443            [::]:*            users:(("proxy",pid=4,fd=3))
tcp   LISTEN 0      128    [::1]:9000          [::]:*            users:(("php",pid=5,fd=4))
udp   UNCONN 0      0      127.0.0.53%lo:53    0.0.0.0:*         users:(("resolved",pid=6,fd=12))'
ports="$(printf '%s\n' "$fake_ss" | public_ports)"
# A loopback socket is listed, and the thing that must never happen is calling
# it reachable. Checking that the line is absent was the old shape of this
# check, back when the listing dropped everything but wildcard binds: a socket
# nobody prints is a socket nobody judges.
contains 'a port on loopback is listed as local only' \
  'port 5432  users:(("postgres",pid=1,fd=7))  LOCAL ONLY' "$ports"
contains 'a port on IPv6 loopback is listed as local only' \
  'port 9000  users:(("php",pid=5,fd=4))  LOCAL ONLY' "$ports"
contains 'the local resolver port is listed as local only' \
  'port 53  users:(("resolved",pid=6,fd=12))  LOCAL ONLY' "$ports"
lacks   'no loopback socket is called reachable from outside' \
  'port 5432  users:(("postgres",pid=1,fd=7))  REACHABLE' "$ports"
# Full lines, not bare port numbers: matching '80' alone also matches the 8080
# line, so the assertion stayed green even with the port 80 socket gone.
contains 'port 80 on the wildcard is public' \
  'port 80  users:(("nginx",pid=2,fd=6))  REACHABLE FROM OUTSIDE (wildcard address)' "$ports"
contains 'port 8080 in *:port form is public' \
  'port 8080  users:(("java",pid=3,fd=9))  REACHABLE FROM OUTSIDE (wildcard address)' "$ports"
contains 'port 443 on the IPv6 wildcard is public' \
  'port 443  users:(("proxy",pid=4,fd=3))  REACHABLE FROM OUTSIDE (wildcard address)' "$ports"

echo
echo '=== PORTS: every listening address is classified ==='
# The addresses here are documentation addresses (RFC 5737 and RFC 1918), not
# the address of any real host: this file is public.
fake_ss='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*  users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      128    203.0.113.10:5432   0.0.0.0:*  users:(("postgres",pid=2,fd=4))
tcp   LISTEN 0      128    127.0.0.1:6379      0.0.0.0:*  users:(("redis",pid=3,fd=5))
tcp   LISTEN 0      128    172.17.0.1:9000     0.0.0.0:*  users:(("dockerd",pid=4,fd=6))'

out="$(printf '%s\n' "$fake_ss" | public_ports)"
contains 'ports: a wildcard bind is reachable from outside' \
  'port 22  users:(("sshd",pid=1,fd=3))  REACHABLE FROM OUTSIDE (wildcard address)' "$out"
contains 'ports: a bind to a routable address of the host is reachable from outside' \
  'port 5432  users:(("postgres",pid=2,fd=4))  REACHABLE FROM OUTSIDE (routable address)' "$out"
contains 'ports: a loopback bind is local only' \
  'port 6379  users:(("redis",pid=3,fd=5))  LOCAL ONLY' "$out"
contains 'ports: a private address is not silently called safe' \
  'port 9000  users:(("dockerd",pid=4,fd=6))  TO VERIFY (private address: reachable from that network)' "$out"
expect 'ports: no listening socket disappears from the listing' \
  '4' "$(printf '%s\n' "$out" | grep -c 'port ')"

# Carrier grade NAT (RFC 6598) is the address family a mesh VPN hands out, and
# on the first real run it was the one address shape that came back wrong: a
# socket reachable only from the VPN was reported as reachable from the
# internet. A false alarm is cheaper than a miss, but it is still the report
# saying something that is not true (verified in the field).
cgnat='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    100.64.0.1:50049    0.0.0.0:*  users:(("tailscaled",pid=7,fd=1))
tcp   LISTEN 0      128    100.127.255.254:993 0.0.0.0:*  users:(("mesh",pid=8,fd=2))
tcp   LISTEN 0      128    100.63.0.1:993      0.0.0.0:*  users:(("real",pid=9,fd=3))
tcp   LISTEN 0      128    100.128.0.1:993     0.0.0.0:*  users:(("real",pid=10,fd=4))'
out="$(printf '%s\n' "$cgnat" | public_ports)"
contains 'ports: the bottom of the CGNAT range is not called internet reachable' \
  'port 50049  users:(("tailscaled",pid=7,fd=1))  TO VERIFY (private address: reachable from that network)' "$out"
contains 'ports: the top of the CGNAT range is not called internet reachable' \
  'port 993  users:(("mesh",pid=8,fd=2))  TO VERIFY (private address: reachable from that network)' "$out"
contains 'ports: the address just below the CGNAT range is still routable' \
  'port 993  users:(("real",pid=9,fd=3))  REACHABLE FROM OUTSIDE (routable address)' "$out"
contains 'ports: the address just above the CGNAT range is still routable' \
  'port 993  users:(("real",pid=10,fd=4))  REACHABLE FROM OUTSIDE (routable address)' "$out"

# A dual stack service binds an IPv4 address through an IPv6 socket, and the
# address arrives wrapped. Judged on the wrapper it looks public, so a service
# listening on loopback only gets reported as an exposure.
# The scope id (%lo, %eth0) is part of the same problem: it decorates the
# address without changing which address it is.
odd='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    [::ffff:127.0.0.1]:8180  0.0.0.0:*  users:(("crowdsec",pid=11,fd=1))
tcp   LISTEN 0      128    [::ffff:10.0.0.5]:9090   0.0.0.0:*  users:(("exporter",pid=12,fd=2))
udp   UNCONN 0      0      *%eth0:546               0.0.0.0:*  users:(("dhcp6",pid=13,fd=3))
tcp   LISTEN 0      128    weird                    0.0.0.0:*  users:(("mystery",pid=14,fd=4))'
out="$(printf '%s\n' "$odd" | public_ports)"
contains 'ports: an IPv4 loopback wrapped in an IPv6 socket stays local only' \
  'port 8180  users:(("crowdsec",pid=11,fd=1))  LOCAL ONLY' "$out"
contains 'ports: a private IPv4 wrapped in an IPv6 socket stays to verify' \
  'port 9090  users:(("exporter",pid=12,fd=2))  TO VERIFY (private address: reachable from that network)' "$out"
contains 'ports: a wildcard carrying a scope id is still a wildcard' \
  'port 546  users:(("dhcp6",pid=13,fd=3))  REACHABLE FROM OUTSIDE (wildcard address)' "$out"
contains 'ports: an address we cannot read is not quietly called public' \
  'users:(("mystery",pid=14,fd=4))  UNRECOGNISED ADDRESS SHAPE (check it on the server)' "$out"

# A multicast responder answers the local network, not the internet. Called
# reachable from outside it becomes an unexplained public service, which the
# criteria then rate HIGH: a loud alarm about a printer discovery daemon.
mcast='Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0      224.0.0.251:5353    0.0.0.0:*  users:(("avahi",pid=15,fd=1))
udp   UNCONN 0      0      239.255.255.250:1900 0.0.0.0:* users:(("ssdp",pid=16,fd=2))
udp   UNCONN 0      0      [ff02::fb]:5353     0.0.0.0:*  users:(("avahi",pid=17,fd=3))
tcp   LISTEN 0      128    223.0.0.1:443       0.0.0.0:*  users:(("real",pid=18,fd=4))'
out="$(printf '%s\n' "$mcast" | public_ports)"
contains 'ports: an IPv4 multicast responder is not called internet reachable' \
  'port 5353  users:(("avahi",pid=15,fd=1))  TO VERIFY (multicast or reserved address: not an ordinary service)' "$out"
contains 'ports: an SSDP responder is not called internet reachable' \
  'port 1900  users:(("ssdp",pid=16,fd=2))  TO VERIFY (multicast or reserved address: not an ordinary service)' "$out"
contains 'ports: an IPv6 multicast responder is not called internet reachable' \
  'port 5353  users:(("avahi",pid=17,fd=3))  TO VERIFY (multicast or reserved address: not an ordinary service)' "$out"
contains 'ports: the address just below the multicast range is still routable' \
  'port 443  users:(("real",pid=18,fd=4))  REACHABLE FROM OUTSIDE (routable address)' "$out"

# The raw listing sits one line above the classified one and reads the same
# sockets. Without the same fallback the bundle carries two answers to one
# question in one section: "NOT VERIFIED" above, a full list below.
file_has 'ports: the raw listing is retried without privileges too' \
  "run 'sudo -n ss -tulpn 2>/dev/null \|\| ss -tulpn'" "$COLLECT"

# The documents that turn these labels into a verdict have to describe the
# labels that exist, and stop asserting what the collector cannot know.
file_lacks 'checks: the firewall is not declared powerless against a public bind' \
  'does not undo this bind' "$CHECKS"
file_has 'checks: reachability is stated as depending on the firewall' \
  'depends on the firewall' "$CHECKS"
file_lacks 'checks: an unprivileged listing is not called a partial socket list' \
  'the section is partial and says so' "$CHECKS"
file_has 'checks: what an unprivileged listing loses is named exactly' \
  'process attribution' "$CHECKS"
file_has 'checks: the unrecognised label has a rule of its own' \
  'UNRECOGNISED ADDRESS SHAPE' "$CHECKS"
file_has 'checks: the multicast label has a rule of its own' \
  'multicast or reserved address' "$CHECKS"
file_has 'template: a cut socket list is reported as a floor, not as a count' \
  'at least' "$TEMPLATE"

# The classified list may never be shorter than the raw listing printed just
# above it: it now prints one line per socket instead of one per wildcard bind,
# and the report is told to count the categories. Counting a cut list and
# stating the result as a fact is the defect this whole phase exists to close.
# Read as "the last field of the last line of the call", not as "the line after
# the call": the second form measures whatever happens to follow if the call is
# ever reflowed onto one line, and this is the guard protecting the central
# claim of the whole change.
raw_cap="$(awk "/^run 'sudo -n ss -tulpn/ {print \$NF}" "$COLLECT")"
classified_cap="$(awk '/run_summary public_ports/ {f=1} f && NF {last=$NF} f && !NF {exit} END {print last}' "$COLLECT")"
if [ "${classified_cap:-0}" -ge "${raw_cap:-0}" ] 2>/dev/null && [ "${classified_cap:-0}" -ge 60 ]; then
  ok=$((ok+1)); printf 'ok    ports: the classified list is not cut shorter than the raw one\n'
else
  ko=$((ko+1)); printf 'KO    ports: the classified list is cut shorter than the raw one\n        raw cap [%s], classified cap [%s]\n' "${raw_cap:-none}" "${classified_cap:-none}"
fi

# Without passwordless sudo the whole section comes back NOT VERIFIED, while any
# account can read the same sockets unprivileged and lose only the process
# names. The collector already retries this way for the log counts and the login
# history, and the "process not visible" branch cannot fire without it.
file_has 'ports: the listing is retried without privileges' \
  'run_summary public_ports .sudo -n ss -tulpn 2>/dev/null \|\| ss -tulpn' "$COLLECT"
# The heading and the empty-case phrase describe the filter that used to be
# there. A heading that lies about what you are looking at is the same defect in
# a smaller format, so they may not survive the filter they described.
file_lacks 'ports: the heading no longer claims the listing is filtered' \
  'local column only' "$COLLECT"
file_lacks 'ports: the empty case no longer claims nothing is bound to a public address' \
  'nothing is bound to a public address' "$COLLECT"

echo
echo '=== COLLECTOR: SSH keys and honest verdicts ==='
printf '# old key\n\nssh-ed25519 AAAAC3NzaC1lZDI1 admin@laptop\nfrom="203.0.113.4",no-pty ssh-rsa AAAAB3Nza old@laptop\nsk-ssh-ed25519@openssh.com AAAAGnNr token@key\n' > "$t/authorized_keys"
expect  'keys with options in front are counted too' 3 "$(count_ssh_keys "$t/authorized_keys")"
expect  'missing file: zero keys'                    0 "$(count_ssh_keys "$t/missing")"
contains 'a failed command does not say all is well' 'NOT VERIFIED' \
  "$(verdict_empty 1 '' 'no SSH directory for root (good)')"
expect  'command succeeded and empty: reassuring phrase' 'no SSH directory for root (good)' \
  "$(verdict_empty 0 '' 'no SSH directory for root (good)')"
expect  'command succeeded with output: output shown' 'drwx------ root root' \
  "$(verdict_empty 0 'drwx------ root root' 'no SSH directory for root (good)')"
printf 'audit: apparmor="DENIED" operation="open"\nother\naudit: apparmor="DENIED" operation="exec"\n' > "$t/syslog"
expect  'mandatory access control denials counted' 2 "$(count_mac_denied "$t/syslog")"
# A log nobody could read and a log with nothing in it print the same "0" if you
# only look at grep's exit code. One of the two means the check never happened.
printf 'nothing interesting here\n' > "$t/quiet-syslog"
expect   'a readable log with no denial counts a real zero' 0 "$(count_mac_denied "$t/quiet-syslog")"
contains 'a log that could not be read is not zero denials' 'NOT VERIFIED' \
  "$(count_mac_denied "$t/missing")"
file_has 'the denial count is read with privileges' 'sudo -n grep -c' "$COLLECT"
printf 'Aug 14 10:00:00 srv sshd[1]: Failed password for root\nAug 14 10:00:01 srv sshd[1]: Failed password for admin\n' > "$t/auth.log"
expect   'failed logins counted from a readable log'   2 "$(count_matches 'Failed password' "$t/auth.log")"
expect   'a readable log with no failure counts zero'  0 "$(count_matches 'Failed password' "$t/quiet-syslog")"
contains 'an unreadable log is not zero failed logins' 'NOT VERIFIED' \
  "$(count_matches 'Failed password' "$t/missing-auth.log")"
file_has 'the failed login count goes through that counter' 'count_matches .Failed password' "$COLLECT"

echo
echo '=== COLLECTOR: updates and firewall ==='
upgrade="$(printf '2026-01-02 10:00:00 upgrade old:amd64 1 2\n2026-08-01 09:00:00 upgrade recent:amd64 3 4\n2026-03-03 11:00:00 upgrade middle:amd64 5 6\n' | latest_upgrades | tail -1)"
contains 'last upgrade is the most recent, not the oldest' '2026-08-01' "$upgrade"
file_has 'the IPv6 firewall is collected'      'ip6tables' "$COLLECT"
file_has 'the NAT table is collected'          'iptables -t nat' "$COLLECT"
file_has 'login history falls back to the journal' 'journalctl.*(ssh|sshd)' "$COLLECT"
file_has 'the bundle ends with a completion marker' 'END OF COLLECTION' "$COLLECT"

echo
echo '=== DOCUMENTS: paths, sources, no local branding ==='
file_has 'SKILL.md points at the profile check'   'check-profile' "$SKILL_MD"
file_has 'SKILL.md uses the output directory from the profile' 'OUTPUT_DIR' "$SKILL_MD"
file_has 'SKILL.md names the companion skill'     'web-security-audit' "$SKILL_MD"
file_has 'the template names the report file'     'server-security-audit-' "$TEMPLATE"
file_has 'checks.md cites the hardening book'     '\(Tevault ch\. [0-9]+' "$CHECKS"
file_has 'checks.md cites the web security book'  '\(Li ch\. [0-9]+' "$CHECKS"
file_has 'checks.md marks its own field facts'    'verified in the' "$CHECKS"
file_has 'the example profile explains which values are refused' '203\.0\.113\.' "$EXAMPLE"


echo
echo '=== COLLECTOR: an empty answer is not a clean answer ==='
# A summariser reads a stream. "sudo said no" and "there is nothing to report"
# reach it as the very same empty stream, and the summary then swears it looked.
out="$(run_summary summarize_sudoers 'exit 1' 'no sudo rule on this machine' 2>&1)"
contains 'sudoers: a denied command does not report zero rules'  'NOT VERIFIED' "$out"
lacks    'sudoers: nor does it swear NOPASSWD is absent' 'NOPASSWD present: no' "$out"
out="$(run_summary summarize_sudoers 'printf "auditor ALL=(ALL) NOPASSWD: /usr/bin/systemctl\n"' 'no sudo rule on this machine' 2>&1)"
contains 'sudoers: a command that did run is still summarised'   'sudo rules: 1' "$out"
out="$(run_summary public_ports 'exit 1' 'nothing listening on a public address' 2>&1)"
contains 'public ports: a denied listing is not an empty port list' 'NOT VERIFIED' "$out"
out="$(run_summary "summarize_cron system" 'exit 1' 'no system scheduled job' 2>&1)"
contains 'system cron: a denied read is not "no scheduled jobs"'    'NOT VERIFIED' "$out"
file_has 'the SUID search cannot come back silently clean'  'check "set -o pipefail; sudo -n find .*-perm /6000' "$COLLECT"
file_has 'the world writable file search cannot either'     'check "sudo -n find .*-type f -perm -0002' "$COLLECT"
file_has 'the world writable directory search cannot either' 'check "sudo -n find .*-type d -perm -0002' "$COLLECT"
file_has 'the environment file search cannot either'        "check \"sudo -n find .*-name '\.env'"  "$COLLECT"
file_has 'the private key search cannot either'             "check \"sudo -n find .*-name 'id_rsa'" "$COLLECT"
file_has 'the container inspection cannot either'           'check .sudo -n docker inspect'         "$COLLECT"
file_has 'the public port listing goes through the honest path' 'run_summary public_ports'          "$COLLECT"
file_has 'the sudo rule summary goes through it too'        'run_summary summarize_sudoers'         "$COLLECT"
file_has 'the system cron summary knows it is a system one' 'run_summary "summarize_cron system"'   "$COLLECT"

echo
echo '=== COLLECTOR: a cut list never looks complete ==='
# head closes the pipe and the shell reports 141 for the broken pipe, not 124
# for the clock: the timeout disappears exactly on the long lists where being
# cut short matters, a SUID listing above all.
out="$(run 'for i in 1 2 3 4 5 6 7 8 9 10; do echo line$i; done; sleep 5' 3 1 2>&1)"
contains 'run: the reader is told the list was cut'   'the list is cut'              "$out"
contains 'run: and that the clock ran out'            'exceeded the 1 second limit'  "$out"
out="$(run 'echo only-one-line' 3 5 2>&1)"
lacks    'run: a complete short list is not called cut' 'the list is cut'            "$out"
lacks    'run: nor is it called interrupted'            'exceeded'                   "$out"

# A command that fails while printing nothing used to leave the section blank,
# and a blank section reads as "there is nothing there" rather than "I was not
# allowed to look". Where it hurts most is the firewall: sudo denied on the
# rule listing, stderr discarded, and the most important section of the whole
# bundle becomes a clean bill of health for a machine nobody checked.
out="$(run 'exit 3' 5 5 2>&1)"
contains 'run: a silent failure is NOT VERIFIED'          'NOT VERIFIED'           "$out"
out="$(run 'echo evidence-line; exit 3' 5 5 2>&1)"
contains 'run: output that arrived anyway is kept'        'evidence-line'          "$out"
contains 'run: with the note that something failed'       'also reported an error' "$out"
lacks    'run: and is not thrown away as NOT VERIFIED'    'NOT VERIFIED'           "$out"
out="$(run 'echo all-good' 5 5 2>&1)"
lacks    'run: a command that succeeds is untouched'      'NOT VERIFIED'           "$out"
# The address is assembled inside the command so that the echoed command line,
# which is printed as written and not through the filter, cannot be what the
# masking assertion below is reading.
out="$(run_filtered mask_ip 'echo 203.0.113.$((4+5)); sleep 5' 3 1 2>&1)"
contains 'run_filtered: the clock is checked there too' 'exceeded the 1 second limit' "$out"
lacks    'run_filtered: and the filter still masks'     '203.0.113.9'                 "$out"
contains 'run_filtered: leaving the marker behind'      'IP-MASKED'                   "$out"

echo
echo '=== COLLECTOR: the process column of the port listing ==='
# Without privileges the listing has no Process column at all, so the last field
# is the peer address. Printing it as the process names a service that does not
# exist, which is worse than printing nothing.
ports_np="$(printf 'tcp   LISTEN 0      511    0.0.0.0:80          0.0.0.0:*\n' | public_ports)"
contains 'the public port is still reported without privileges' 'port 80' "$ports_np"
lacks    'the peer column is not printed as the process'  '0.0.0.0:*'   "$ports_np"
contains 'and the line says the process could not be seen' 'process not visible' "$ports_np"
contains 'with privileges the real process name is printed' 'nginx' "$ports"

echo
echo '=== COLLECTOR: system crontabs have a user column ==='
# /etc/crontab and /etc/cron.d put the user in sixth position: reading the sixth
# field as the command reports "root" as the scheduled job.
sys_cron="$(printf '# backup\nSHELL=/bin/sh\nPATH=/usr/bin:/bin\n0 3 * * * root /opt/app/backup.sh --token=abc123XYZ\n' | summarize_cron system)"
contains 'system cron: the command is reported'                 'backup.sh' "$sys_cron"
lacks    'system cron: the user is not mistaken for the command' 'root'     "$sys_cron"
lacks    'system cron: environment lines are not jobs'           'SHELL'    "$sys_cron"
lacks    'system cron: the token still stays out'                'abc123XYZ' "$sys_cron"
sys_cd="$(printf '*/5 * * * * deploy cd /opt/app && ./sync.sh --key=SECRETVALUE\n' | summarize_cron system)"
contains 'system cron: a job starting with cd still names its command' 'sync.sh' "$sys_cd"
lacks    'system cron: and its key stays out'                          'SECRETVALUE' "$sys_cd"
sys_noslash="$(printf '0 4 * * * root logger audit-heartbeat\n' | summarize_cron system)"
contains 'system cron: a command with no slash is still the command' 'logger' "$sys_noslash"
lacks    'system cron: and the user still is not it'                 'root'   "$sys_noslash"
at_reboot="$(printf '@reboot root /opt/app/warm-cache.sh\n' | summarize_cron system)"
contains 'system cron: @reboot skips the user column too' 'warm-cache.sh' "$at_reboot"
lacks    'system cron: @reboot does not report the user' 'root'          "$at_reboot"
user_env="$(printf 'MAILTO=admin@example.com\n0 6 * * * /home/app/report.sh\n' | summarize_cron user)"
contains 'user cron: the command is still reported' 'report.sh' "$user_env"
lacks    'user cron: environment lines are not jobs' 'MAILTO'   "$user_env"

echo
echo '=== COLLECTOR: session addresses arrive numeric ==='
# last and lastb print the host NAME when they have one, and a name is not an IP
# address: the mask has nothing to bite on and the address leaves in the bundle
# in words. Asking for the numeric form is what makes the masking promise true.
file_has 'the login history is collected numerically'   'last -i'  "$COLLECT"
file_has 'the failed login history too'                 'lastb -i' "$COLLECT"

echo
echo '=== RUNNER: yesterday bundle survives ==='
# The old name held the day only, and the redirection truncated it before ssh
# had said a word: a failed connection destroyed the previous collection.
out="$(profile_check "$t/good.conf")"
# Minute resolution is not enough: two runs inside the same minute build the
# same name and the second one overwrites the collection you would have wanted
# to compare against, which is the very loss the .part rename was added to stop.
matches  'the bundle name carries the hour, the minute and the second' \
         'bundle-server-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6}\.txt' "$out"
file_has 'the bundle is written aside and moved only when the collection finished' \
         'mv .*part' "$RUNNER"
file_lacks 'no bundle name is built from the day alone' \
         'bundle-server-\$\(date \+%Y-%m-%d\)' "$RUNNER"

echo
echo '=== COLLECTOR: what was printed and how it ended are two separate facts ==='
# The round before this one overcorrected: any non zero exit code threw the
# output away. These searches fail routinely for a reason that has nothing to do
# with what they found, because find exits 1 as soon as one of the directories
# it was handed does not exist, and /data does not exist on a plain Ubuntu. The
# search for exposed environment files was therefore finding them, holding the
# list, and printing NOT VERIFIED.
#
# The file found is named differently from the pattern searched for on purpose:
# the command line is echoed above its output, as written, so a name shared by
# both would let this pass while the output is being thrown away, which is the
# very bug it is here to catch.
mkdir -p "$t/site"
: > "$t/site/.env.production"
out="$(check "find '$t/site' '$t/no-such-dir' -name '.env*' 2>/dev/null" 'the search ran and found no environment file' 2>&1)"
contains 'a search that found files and then failed still shows the files' '.env.production' "$out"
lacks    'and that result is not called unverified'          'NOT VERIFIED'          "$out"
contains 'the failure is reported next to the result'        'also reported an error' "$out"
out="$(check 'exit 1' 'the search ran and found no environment file' 2>&1)"
contains 'nothing printed plus a failure is still unverified' 'NOT VERIFIED'         "$out"
lacks    'and does not get the reassuring phrase'             'found no environment file' "$out"
out="$(check 'printf "clean\n"' 'the search ran and found nothing' 2>&1)"
lacks    'a command that succeeded carries no error note'     'also reported an error' "$out"
contains 'verdict: output survives a failure'                 'line one' "$(verdict_empty 1 'line one' 'phrase')"
contains 'verdict: silence plus failure stays unverified'     'NOT VERIFIED' "$(verdict_empty 1 '' 'phrase')"
expect   'note: nothing to note when the command succeeded'   '' "$(note_partial 0 'out')"
expect   'note: nothing to note when there was no output'     '' "$(note_partial 1 '')"
contains 'note: an error next to real output is reported'     'may be incomplete' "$(note_partial 1 'out')"
lacks    'note: the clock is left to the line that words it better' 'also reported' "$(note_partial 124 'out')"
# The note is printed after the cut, so a list too long to show in full keeps it.
out="$(check 'for i in 1 2 3 4 5; do echo line$i; done; exit 1' 'nothing to report' 2 2>&1)"
contains 'a cut list still carries the error note' 'also reported an error' "$out"
contains 'and still says it was cut'               'the list is cut'        "$out"

echo
echo '=== COLLECTOR: a summary keeps what the command managed to read ==='
# cat /etc/crontab /etc/cron.d/* exits 1 when the directory is empty and the
# pattern stays a literal name, and the jobs of /etc/crontab have already been
# read by then: losing them means an audit that never saw the scheduled tasks.
# The token is assembled inside the command on purpose: the command line itself
# is echoed above the output, as written, so a literal token there would be what
# the assertion below reads instead of the summary.
out="$(run_summary "summarize_cron system" 'printf "0 3 * * * root /opt/app/backup.sh --token=tok$((6*7))\n"; exit 1' 'the system crontabs were read and hold no job' 2>&1)"
# The needle is the summarised shape, not the command name alone: the command
# name is in the echoed command line too, so on its own it would pass even with
# the summary thrown away.
contains 'system cron: the jobs already read survive the failure' \
  'backup.sh  (arguments not reported)' "$out"
lacks    'system cron: which is not an unverified section'        'NOT VERIFIED' "$out"
contains 'system cron: and the failure is reported next to them'  'also reported an error' "$out"
lacks    'system cron: the token still stays out of the bundle'   'tok42'      "$out"
out="$(run_summary public_ports 'printf "tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=2,fd=6))\n"; exit 1' 'nothing listening on a public address' 2>&1)"
contains 'public ports: a partial listing is still summarised' 'port 80'      "$out"
lacks    'public ports: and is not thrown away'                'NOT VERIFIED' "$out"

echo
echo '=== COLLECTOR: an include line is not a sudo rule ==='
# sudo 1.9, the default from Ubuntu 22.04 on, writes @includedir /etc/sudoers.d
# in the shipped file. Counted as a rule it inflates the count, and the word
# @includedir turns up in the list of who can become administrator, which is
# the one line of that summary people actually read.
inc="$(printf '@includedir /etc/sudoers.d\n@include /etc/sudoers.local\nroot ALL=(ALL:ALL) ALL\n' | summarize_sudoers)"
contains 'only the real rule is counted'            'sudo rules: 1' "$inc"
lacks    'the include directive is not a principal' '@includedir'   "$inc"
lacks    'nor is the single file include'           '@include'      "$inc"
contains 'and the real principal is still listed'   'root'          "$inc"

echo
echo '=== COLLECTOR: three ways for the container list to come back empty ==='
# docker inspect with no running container receives no argument at all, prints
# its usage and exits 1. Read as a failure it is NOT VERIFIED, read as an empty
# answer it is "the containers are confined": no engine, no permission and no
# container are three different answers and each deserves its own line.
expect 'no container engine on the machine'    ABSENT  "$(docker_state no 0 '')"
expect 'the engine did not answer'             DENIED  "$(docker_state yes 1 '')"
expect 'the engine answered, nothing running'  NONE    "$(docker_state yes 0 '')"
expect 'whitespace only is still no container' NONE    "$(docker_state yes 0 '   ')"
expect 'the engine answered with containers'   RUNNING "$(docker_state yes 0 'a1b2c3')"
file_has 'the container checks go through that decision' 'docker_check' "$COLLECT"
file_lacks 'and no longer feed inspect from a substitution that can be empty' \
  'docker inspect \$\(sudo -n docker ps -q\)' "$COLLECT"

echo
echo '=== COLLECTOR: the log file is not in the same place on every distribution ==='
# The skill says it supports the RHEL family too. With the Debian path written
# by hand, on those machines the failed logins and the access control denials
# came back NOT VERIFIED every single time, which reads as a broken audit.
printf 'Aug 14 10:00:00 srv sshd[1]: Failed password for root\nAug 14 10:00:01 srv sshd[1]: Failed password for admin\n' > "$t/secure"
expect 'failed logins are counted from the RHEL path too' 2 \
  "$(count_matches 'Failed password' "$t/no-auth.log" "$t/secure")"
printf 'audit: apparmor="DENIED" op="open"\naudit: apparmor="DENIED" op="exec"\n' > "$t/messages"
expect 'denials are counted from the RHEL system log too' 2 \
  "$(count_mac_denied "$t/no-syslog" "$t/messages")"
contains 'with no candidate at all the answer stays unverified' 'NOT VERIFIED' \
  "$(count_matches 'Failed password' "$t/no-auth.log" "$t/no-secure")"
expect 'the first candidate wins when it is there' "$t/auth.log" "$(first_existing "$t/auth.log" "$t/secure")"
expect 'and the second one is used when it is not'  "$t/secure"   "$(first_existing "$t/no-auth.log" "$t/secure")"
file_has 'the collector hands both candidates to the counter' 'auth\.log /var/log/secure' "$COLLECT"
file_has 'and both of them for the system log too'            'syslog /var/log/messages' "$COLLECT"

echo
echo '=== COLLECTOR: the keys of every account, not only of whoever connected ==='
# The account that matters is rarely the one running the audit: root, a deploy
# account, a service account left behind by an installer. Counting only the
# keys of the connected user is an audit of one account out of ten.
passwd_sample='root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
app:x:1001:1001::/home/app:/bin/sh
deploy:x:1002:1002::/home/deploy:/bin/bash
nobody:x:65534:65534::/nonexistent:/bin/false'
accounts="$(printf '%s\n' "$passwd_sample" | login_accounts)"
contains 'root is an account that can be logged into' 'root /root'         "$accounts"
contains 'so is an ordinary account'                  'app /home/app'      "$accounts"
contains 'and a deploy account'                       'deploy /home/deploy' "$accounts"
lacks    'an account with nologin as its shell is not' 'daemon'  "$accounts"
lacks    'nor is the sync account'                     'sync'    "$accounts"
lacks    'nor an account with false as its shell'      'nobody'  "$accounts"
file_has 'the collector walks every one of them'       'login_accounts' "$COLLECT"
file_has 'and reports the mode and the owner of each key file' 'stat -c "%a %U:%G" "\$kf"' "$COLLECT"
file_has 'the key count is attempted with privileges too'      'sudo -n grep -cvE' "$COLLECT"
printf 'not a directory\n' > "$t/afile"
contains 'a key file we cannot even reach is not zero keys' 'NOT VERIFIED' \
  "$(count_ssh_keys "$t/afile/.ssh/authorized_keys")"
expect 'a key file missing from a directory we can read is a real zero' 0 \
  "$(count_ssh_keys "$t/nothing-here")"

echo
echo '=== PROFILE: the example file is a form, not a profile ==='
# The example file says in writing that the skills refuse to run while it is a
# stub. That sentence has to be true, or it is the worst kind of documentation:
# the kind that stops people from checking.
printf 'SSH_HOST="203.0.113.10"\nSSH_USER="auditor"\nALLOWED_DOMAINS="example.com example.org"\n' > "$t/still-example.conf"
expect_nonzero 'a profile still holding the example values does not run' "$(profile_rc "$t/still-example.conf")"
contains 'and the message says the profile was never filled in' 'never filled in' "$(profile_check "$t/still-example.conf")"
printf 'SSH_HOST="10.9.8.7"\nSSH_USER="auditor"\nALLOWED_DOMAINS="ourshop.test example.com"\n' > "$t/half-example.conf"
expect_nonzero 'one reserved domain left in the list is enough to stop' "$(profile_rc "$t/half-example.conf")"
file_has 'the example profile ships an empty host'        'SSH_HOST=""' "$EXAMPLE"
file_has 'the example profile ships an empty user'        'SSH_USER=""' "$EXAMPLE"
file_has 'the example profile ships an empty domain list' 'ALLOWED_DOMAINS=""' "$EXAMPLE"
file_lacks 'and carries no value that looks already filled in' 'SSH_HOST="[0-9]' "$EXAMPLE"

echo
echo '=== RUNNER: a machine with no ssh client is told so ==='
# The profile below does not exist on purpose: whatever the runner decides to do
# with these arguments, it cannot open a connection to anything.
noprofile="$t/does-not-exist.conf"
out="$(env -u SSH_HOST -u SSH_USER AUDIT_PROFILE="$noprofile" bash "$RUNNER" --check-ssh "$t/no-such-ssh" 2>&1)"; rc=$?
contains 'a missing ssh client is named as such'  'no ssh client' "$out"
lacks    'and is not sold as a collection cut short' 'completion marker' "$out"
expect_nonzero 'and the run does not pretend it worked' "$rc"
printf '#!/bin/sh\nexit 0\n' > "$t/fake-ssh"; chmod +x "$t/fake-ssh"
out="$(env AUDIT_PROFILE="$noprofile" bash "$RUNNER" --check-ssh "$t/fake-ssh" 2>&1)"
contains 'a client that is there is reported with its path' "$t/fake-ssh" "$out"
contains 'and the check says it connected to nothing'       'connected'   "$out"
ln_ssh="$(grep -n 'no ssh client' "$RUNNER" | head -1 | cut -d: -f1)"
ln_write="$(grep -n '^mkdir -p' "$RUNNER" | head -1 | cut -d: -f1)"
expect_lt 'the run stops for a missing client before it writes anything' "${ln_ssh:-0}" "${ln_write:-0}"

# --- the mount options column is where a network share keeps its password -----
# The options field is the one field of the mount table that routinely carries
# credentials: a network share is mounted with username= and password= written
# in the clear. The bundle is the document this tool tells the operator it is
# safe to share, and the header of the collector promises the mount table does
# not come out of it, so printing that column whole breaks both at once.
out="$(printf '//198.51.100.5/backup /mnt/nas cifs username=svc,password=Str0ngP4ss,vers=3.0 0 0\n' | summarize_fstab)"
lacks    'fstab: a share password does not reach the bundle'  'Str0ngP4ss'  "$out"
lacks    'fstab: nor does the key that carries it'            'password='   "$out"
contains 'fstab: the mount point is still reported'           '/mnt/nas'    "$out"
contains 'fstab: and so is the filesystem type'               'cifs'        "$out"
out="$(printf '/dev/sda1 / ext4 defaults,nodev,nosuid,noexec 0 1\n' | summarize_fstab)"
contains 'fstab: the options the audit judges are kept (nodev)'  'nodev'  "$out"
contains 'fstab: and nosuid'                                     'nosuid' "$out"
contains 'fstab: and noexec'                                     'noexec' "$out"

# --- a tool that answers "nothing here" is not a tool that failed -------------
# Several commands report an empty result with exit code 1: no personal crontab,
# no matching line. Read as failures they print NOT VERIFIED on a perfectly
# healthy machine, and a warning that fires when all is well is a warning nobody
# reads when it matters.
collector="$(dirname "$0")/../scripts/collect.sh"
file_has 'crontab: an empty crontab is not read as a failure' \
         "crontab -l[^']*\|\| \[ \\\$\? = 1 \]" "$collector"
file_has 'security count: counting zero is not read as a failure' \
         "grep -ci security[^']*\|\| \[ \\\$\? = 1 \]" "$collector"

# --- the same file read two different ways ------------------------------------
# count_matches falls back to an unprivileged read when sudo is refused, so on a
# host where the audit user can read the log without sudo the bundle prints a
# real count and, two lines below, NOT VERIFIED for the history of that same
# file. One of the two is wrong, and it is the one that gave up.
fake_log="$(mktemp)"
printf 'Jan  1 00:00:01 host sshd[1]: Accepted publickey for someone from 203.0.113.9\n' > "$fake_log"
out="$(AUDIT_AUTH_LOGS="$fake_log" login_history 'Accepted' 5 2>&1)"
contains 'login history: it reads the log even with no privileges' 'Accepted publickey' "$out"
lacks    'login history: so it does not claim it could not look'   'NOT VERIFIED'       "$out"
contains 'login history: and the address is still masked'          'IP-MASKED'          "$out"
rm -f "$fake_log"

# --- the family guard ---------------------------------------------------------
# Three times now the same defect has been fixed in the wrapper the reviewer
# named and left standing in its siblings: a command that fails while printing
# nothing must never produce a silent section, because a silent section reads
# as "there is nothing there" rather than "I was not allowed to look". The
# behavioural test below covers the wrapper that was missed; the structural one
# below it covers the wrappers nobody has thought of yet.
out="$(run_filtered mask_ip 'exit 1' 15 5 2>&1)"
contains 'run_filtered: a silent failure is NOT VERIFIED too' 'NOT VERIFIED' "$out"
out="$(run_filtered mask_ip 'echo 203.0.113.7; exit 1' 15 5 2>&1)"
contains 'run_filtered: output that arrived is kept'     'IP-MASKED'              "$out"
contains 'run_filtered: with the note that it also failed' 'also reported an error' "$out"

collector="$(dirname "$0")/../scripts/collect.sh"
for fn in run run_filtered check run_summary docker_check; do
  body="$(awk -v f="^$fn\\\\(\\\\)" '$0 ~ f {on=1} on {print; if (/^}/) exit}' "$collector")"
  case "$body" in
    *verdict_empty*|*'NOT VERIFIED'*)
      ok=$((ok+1)); printf 'ok    family: %s applies the not-verified rule\n' "$fn" ;;
    *)
      ko=$((ko+1)); printf 'KO    family: %s can print a silent section on failure\n' "$fn" ;;
  esac
done

echo
echo '=== COVERAGE: the count reads the bundle, so it cannot contradict it ==='
# Counting calls to emit was the first attempt and it was wrong: five other
# places in this collector print NOT VERIFIED without going through emit
# (docker_check, login_history, the failed login count, the MAC denial count,
# the per account key read), so the number denied gaps the bundle was showing
# on the same page. Counting the text the reader sees cannot drift from it.
fake_bundle='##### SECTION: FIREWALL

$ sudo -n nft list ruleset
table inet filter { }

$ sudo -n ufw status
NOT VERIFIED: the command printed nothing and did not succeed


##### SECTION: CONTAINERS

$ sudo -n docker inspect
NOT VERIFIED: the container engine did not answer (permission denied)

$ sudo -n docker ps
NOT VERIFIED: the container engine did not answer (permission denied)


##### SECTION: SSH

$ sshd -T
port 4422
'
out="$(printf '%s\n' "$fake_bundle" | coverage_tee)"
contains 'coverage: the three numbers are stated' \
  'Coverage: 2 verified, 3 not verified, 6 excluded by contract.' "$out"
contains 'coverage: a NOT VERIFIED printed outside emit is counted' \
  'CONTAINERS (0/2)' "$out"
contains 'coverage: a section that lost one check of two is scored' \
  'FIREWALL (1/2)' "$out"
lacks 'coverage: a section that lost nothing is not named' 'SSH (' "$out"
contains 'coverage: the bundle text is passed through unchanged' \
  'table inet filter { }' "$out"

# One command can print several NOT VERIFIED lines (the per account key loop
# does), and that is still one check that did not happen, not five.
many='##### SECTION: ACCOUNTS

$ read every authorized_keys
root             NOT VERIFIED: could not be reached
ricca            NOT VERIFIED: could not be reached
deploy           NOT VERIFIED: could not be reached
'
out="$(printf '%s\n' "$many" | coverage_tee)"
contains 'coverage: several failures under one command count as one gap' \
  'Coverage: 0 verified, 1 not verified, 6 excluded by contract.' "$out"

# A command that answered is verified even if its exit code was not zero:
# "systemctl is-active" exits 3 to say "inactive", which is a real answer, and
# "no reboot pending" is the healthy case. Counting those as gaps would report
# a healthy server as a partial audit.
answered='##### SECTION: PENDING UPDATES

$ systemctl is-active unattended-upgrades
inactive

$ cat /var/run/reboot-required.pkgs
no reboot pending
'
out="$(printf '%s\n' "$answered" | coverage_tee)"
contains 'coverage: a command that answered is verified whatever its exit code' \
  'Coverage: 2 verified, 0 not verified, 6 excluded by contract.' "$out"
lacks 'coverage: with nothing missing the gaps line does not appear' 'Sections with gaps' "$out"

expect 'coverage: the excluded list is as long as the number it states' \
  "${AUDIT_EXCLUDED:-unset}" "$(excluded_by_contract </dev/null 2>/dev/null | grep -c .)"
# The exclusions belong to this collector: a read-only server audit is not in a
# position to fuzz anything or fire a webhook, and listing what it was never
# near reads as coverage it chose not to take.
file_lacks 'coverage: the exclusions are not the ones of the web collector' \
  'broad fuzzing and wide port scanning' "$COLLECT"

# A cut hidden inside the command hides the exit code with it: "dnf | head" on a
# machine with no dnf leaves head exiting zero and no output, which this count
# would read as a check that was made.
file_lacks 'coverage: no list cut is hidden inside a command in the body' \
  "^(run|run_filtered|check|run_summary).*\| *head " "$COLLECT"
file_has 'coverage: the pipeline that keeps its head guards its exit code' \
  "set -o pipefail; apt list --upgradable" "$COLLECT"
file_lacks 'coverage: the second apt pipeline guards its exit code too' \
  "^run 'apt list --upgradable 2>/dev/null \| grep" "$COLLECT"

# A heading is not a command. Written with the "$ " prefix it becomes a second
# command line for a check that ran once, and every one of them inflates the
# verified count on every single run.
file_lacks 'coverage: no heading is written as a command line' \
  "^printf '.n[$] [a-z].*[^n]'$" "$COLLECT"
titles='##### SECTION: ACCOUNTS

-- summary of sudo rules (contents not reported)

$ cat /etc/sudoers
NOT VERIFIED: the command printed nothing and did not succeed
'
out="$(printf '%s\n' "$titles" | coverage_tee)"
contains 'coverage: a title line is not counted as a command' \
  'Coverage: 0 verified, 1 not verified, 6 excluded by contract.' "$out"
contains 'coverage: the section score counts the check once' 'ACCOUNTS (0/1)' "$out"

# A tool that is not installed is not a check that failed. Ubuntu has no dnf and
# RHEL has no apt: calling either one a gap puts a permanent hole in every
# report on the majority platform, and a permanent hole is one nobody reads.
absent='##### SECTION: PENDING UPDATES

$ dnf -q check-update --security
NOT APPLICABLE: dnf is not installed on this machine

$ apt list --upgradable
libssl3/jammy-updates 3.0.2-0ubuntu1.15 amd64 [upgradable from: 3.0.2-0ubuntu1.12]
'
out="$(printf '%s\n' "$absent" | coverage_tee)"
contains 'coverage: an absent tool is answered, not counted as a gap' \
  'Coverage: 2 verified, 0 not verified, 6 excluded by contract.' "$out"
lacks 'coverage: an absent tool does not open a permanent gap' 'Sections with gaps' "$out"

if command -v sh >/dev/null 2>&1; then
  out="$(run_if sh 'echo reached' 5 5 2>&1)"
  contains 'run_if: a tool that is there runs its command' 'reached' "$out"
fi
# The marker has to differ from the text of the command, because the heading
# prints the command itself: looking for the command text would find the
# heading and call it an execution.
out="$(run_if definitely-not-a-real-tool 'printf "X%s\n" EXECUTED' 5 5 2>&1)"
contains 'run_if: a tool that is missing says so plainly' 'NOT APPLICABLE' "$out"
lacks 'run_if: a tool that is missing does not run its command' 'XEXECUTED' "$out"
lacks 'run_if: a missing tool is not reported as a failed check' 'NOT VERIFIED' "$out"

# These two used to run outside the run/check family, so an absent zgrep, a
# missing package log or an unreadable fstab printed nothing and was counted as
# a check that was made. They cannot go through run: they call shell functions,
# and run executes its command in a fresh bash that never saw them.
file_has 'coverage: the package log goes through the honest path' \
  'run_summary latest_upgrades' "$COLLECT"
file_has 'coverage: the fstab summary goes through the honest path' \
  'run_summary summarize_fstab' "$COLLECT"
file_lacks 'coverage: the fstab summary no longer cuts silently' \
  'summarize_fstab < /etc/fstab' "$COLLECT"

file_has 'the skill explains where the coverage line is' 'COVERAGE' "$SKILL_MD"

echo
echo '=== FAMILY: no report template may offer a clean bill of health ==='
for forbidden in 'in good shape' 'Nothing to fix right now' 'nothing sent' \
                 'is clean' 'is protected' 'all clear'; do
  if grep -qiF "$forbidden" "$TEMPLATE"; then
    ko=$((ko+1)); printf 'KO    template must not suggest [%s]\n' "$forbidden"
  else
    ok=$((ok+1)); printf 'ok    template does not suggest [%s]\n' "$forbidden"
  fi
done
file_has 'the template opens with the coverage line' \
  'Coverage: .* verified, .* not verified' "$TEMPLATE"
expect_lt 'the coverage line comes before the two line summary' \
  "$(grep -n 'Coverage: .* verified' "$TEMPLATE" | head -1 | cut -d: -f1)" \
  "$(grep -n '^## In two lines' "$TEMPLATE" | head -1 | cut -d: -f1)"

echo
printf 'TESTS: %d passed, %d failed (%d total)\n' "$ok" "$ko" "$((ok+ko))"
[ "$ko" -eq 0 ] || exit 1
exit 0
