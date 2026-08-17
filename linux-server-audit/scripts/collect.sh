#!/usr/bin/env bash
# =============================================================================
# linux-server-audit: READ-ONLY collection of the server state.
#
# Every command in here reads and nothing else: no writes, no deletions, no
# restarts, no installs, no configuration changes. You can read the whole file
# before running it, it takes a couple of minutes.
#
# The file is not copied to the server: it is piped to ssh on standard input,
# so it leaves nothing behind.
#
# SECRETS NEVER COME OUT. For sensitive files (environment files, keys,
# certificates) it collects name, owner and mode only, never content. For
# passwords it collects the hashing algorithm marker only, never the hash.
#
# THE CONTENTS OF THE AUTH LOG, SUDO RULES, CRON AND FSTAB DO NOT COME OUT
# EITHER: those are summarised (how many rules, which options), and the IP
# addresses of real sessions are masked. An audit bundle travels through chats,
# shared folders and attachments: neither the exact command a scheduled job runs
# with its token, nor the home address of whoever logged in, belongs in it.
#
# Usage (see SKILL.md, or run scripts/run-audit.sh which wraps this):
#   ssh -p <port> <user>@<host> 'bash -s' < collect.sh > bundle-server-DATE.txt
#
# Environment variables:
#   AUDIT_FUNCTIONS_ONLY=1  load the functions only (used by the test suite);
#                           collects nothing
# =============================================================================
set -u
export LC_ALL=C

# =============================================================================
# FUNCTIONS
# Kept separate from the body so they can be tested without a server:
#   AUDIT_FUNCTIONS_ONLY=1 . collect.sh
# The tests live in ../tests/test-linux-server-audit.sh
# =============================================================================

# The reboot flag can be either of two files, and the second one only shows up
# sometimes. Asking `ls` for both at once reports "no reboot needed" exactly
# when a reboot is needed.
verdict_reboot() {   # <file1> <file2>
  if [ -e "$1" ] || [ -e "$2" ]; then
    printf 'REBOOT_REQUIRED'
  else
    printf 'no reboot pending'
  fi
}

# Removes IP addresses (v4 and v6) and leaves the rest of the line readable.
# The IPv6 criterion demands at least four groups or a double colon, so it does
# not eat timestamps such as 13:45:22.
mask_ip() {
  sed -E \
    -e 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<IP-MASKED>/g' \
    -e 's/([0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}/<IP-MASKED>/g' \
    -e 's/([0-9a-fA-F]{1,4}:)+:[0-9a-fA-F]{0,4}/<IP-MASKED>/g'
}

# What matters about sudo rules is how many there are, who they apply to and
# whether any of them skips the password. The exact command each rule allows
# does not go into the bundle: read that on the server when you need it.
#
# A Defaults line (Defaults, Defaults:user, Defaults@host, Defaults>runas,
# Defaults!command) sets an option: it grants nothing to nobody. Counting it as
# a rule inflates the count, and puts the word "Defaults" in the list of who can
# become administrator, which is the one line of that summary people read.
#
# The same goes for the include directives. sudo 1.9, the default from Ubuntu
# 22.04 on, ships "@includedir /etc/sudoers.d" in the file it installs, so every
# ordinary machine would report one rule too many and would list "@includedir"
# among the principals. The rules those files hold are read anyway: the command
# that feeds this summary reads /etc/sudoers.d as well.
summarize_sudoers() {
  awk '
    /^[[:space:]]*(#|$)/ { next }
    /^[[:space:]]*Defaults([[:space:]:@>!]|$)/ { next }
    /^[[:space:]]*@include(dir)?([[:space:]]|$)/ { next }
    {
      n++
      if ($0 ~ /NOPASSWD/) nopass = 1
      who = $1
      if (!(who in seen)) { seen[who] = 1; list = list (list == "" ? "" : ", ") who }
    }
    END {
      printf "sudo rules: %d (who: %s)\n", n, (list == "" ? "nobody" : list)
      printf "NOPASSWD present: %s\n", (nopass ? "yes" : "no")
      print "(rule text stays out of the bundle: read it on the server)"
    }'
}

# What matters about scheduled jobs is when they run and what they launch. The
# arguments do not: that is where API tokens and connection passwords live.
#
# The two crontab shapes differ by one column and nothing warns you: the user
# crontab goes "schedule command", while /etc/crontab and /etc/cron.d slot the
# user in between, "schedule user command". Read with the wrong shape, a system
# crontab reports "root" as the scheduled job, over and over, and the section
# becomes noise nobody reads. Hence the mode argument: system or user.
#
# Two more shapes hide in those files. A crontab may set the environment first
# (SHELL=, PATH=, MAILTO=): those lines schedule nothing and must not be listed
# as jobs. And a job often starts by moving somewhere, "cd /opt/app && ./run.sh":
# the interesting name is run.sh, so the leading cd, its directory and the shell
# operators get stepped over rather than reported as the command.
summarize_cron() {   # [system|user]
  awk -v mode="${1:-user}" '
    /^[[:space:]]*(#|$)/ { next }
    /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ { next }
    {
      if ($1 ~ /^@/) { sched = $1; first = 2 }
      else { sched = $1" "$2" "$3" "$4" "$5; first = 6 }
      if (mode == "system") first++
      if (first > NF) next
      i = first
      while (i <= NF) {
        if ($i == "cd") { i += 2; continue }
        if ($i == "&&" || $i == "||" || $i == ";" || $i == "&") { i++; continue }
        if ($i ~ /^[A-Za-z_][A-Za-z0-9_]*=/) { i++; continue }
        break
      }
      cmd = (i <= NF ? $i : $first)
      sub(/.*\//, "", cmd)
      sub(/[;&|].*$/, "", cmd)
      if (cmd == "") next
      printf "%s  %s  (arguments not reported)\n", sched, cmd
    }'
}

# What matters about fstab is the mount point, the type and the options
# (nodev, nosuid, noexec). The device identifier is masked: it decides nothing
# and in a bundle that travels it is one datum too many.
# The options column is kept by allow-list, not by blocking the dangerous keys.
# It is the one column of this file that routinely carries a credential: a
# network share is mounted with username= and password= written in the clear,
# and a bundle is a document made to be shared. Blocking the keys we can think
# of would leave the ones we cannot (every filesystem type invents its own), so
# only the handful of options the audit actually reasons about survive, and the
# rest is reported as a count. If an option ever needs judging, add it here.
summarize_fstab() {
  awk '
    /^[[:space:]]*(#|$)/ { next }
    {
      n = split($4, o, ",")
      kept = ""; dropped = 0
      for (i = 1; i <= n; i++) {
        if (o[i] ~ /^(nodev|nosuid|noexec|ro|rw|defaults|relatime|noatime|nofail|bind|sync|user|nouser|auto|noauto)$/)
          kept = kept (kept == "" ? "" : ",") o[i]
        else
          dropped++
      }
      if (kept == "") kept = "-"
      if (dropped > 0) kept = kept sprintf("  (+%d option(s) not reported: they can carry credentials)", dropped)
      printf "<device>  %s  %s  %s\n", $2, $3, kept
    }'
}

# The listening-socket listing prints TWO address columns: the local one and the
# peer one (which for a listening socket is always the wildcard). Grepping for
# 0.0.0.0 makes every line look public, including services bound to loopback
# only. This looks at the local column alone, and accepts the *:port form too.
#
# The process column is the seventh, and it is there only when the listing was
# read with privileges: without them the line simply ends after the peer address.
# Taking the last field regardless prints "0.0.0.0:*" in the process slot, which
# reads as a service by that name. Better to say the process was not visible: a
# missing name sends you back to the server, an invented one does not.
#
# Every listening socket is printed, with the address it is bound to and what
# that address means. The previous version printed wildcard binds only, so a
# service bound straight to the public address of the host was missing from the
# list of public ports: the single worst blind spot this collector could have,
# since it is exactly the accident the audit exists to catch (verified in the
# field).
#
# The classification reads the shape of the address and nothing else. It does
# not need to know which address belongs to this host, which keeps the function
# a pure filter the tests can feed by hand.
# ponytail: shape based classification, revisit if a host uses addresses that do
# not fall into these families.
public_ports() {
  awk '
    function classify(a,   b) {
      # An address we cannot read gets its own label rather than the loudest
      # one. Falling through to "reachable from outside" would invent a public
      # port with an empty address column, and the rule in this file is that a
      # missing name sends you back to the server while an invented one does not.
      if (a == "") return "UNRECOGNISED ADDRESS SHAPE (check it on the server)"
      # Two decorations change how an address looks without changing which
      # address it is: the scope id (127.0.0.53%lo, *%eth0) and the IPv6 wrapper
      # a dual stack service gets when it binds an IPv4 address
      # ([::ffff:127.0.0.1]). Judged on the wrapper, a service listening on
      # loopback only is reported as an exposure.
      b = a
      sub(/%[A-Za-z0-9._-]+/, "", b)
      if (b ~ /^\[?::ffff:/) { sub(/^\[?::ffff:/, "", b); sub(/\]$/, "", b) }
      if (b == "0.0.0.0" || b == "*" || b == "[::]" || b == "::")
        return "REACHABLE FROM OUTSIDE (wildcard address)"
      if (b ~ /^127\./ || b == "[::1]" || b == "::1")
        return "LOCAL ONLY"
      # Multicast and the reserved space are not addresses anyone dials from the
      # internet: a printer discovery daemon or an SSDP responder answers the
      # local network. Left in the routable branch it becomes an unexplained
      # public service, and the criteria rate those HIGH.
      if (b ~ /^(22[4-9]|2[345][0-9])\./ || b ~ /^\[?ff/)
        return "TO VERIFY (multicast or reserved address: not an ordinary service)"
      if (b ~ /^10\./ || b ~ /^192\.168\./ || b ~ /^169\.254\./ ||
          b ~ /^172\.(1[6-9]|2[0-9]|3[01])\./ ||
          b ~ /^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./ ||
          b ~ /^\[?f[cde]/)
        return "TO VERIFY (private address: reachable from that network)"
      return "REACHABLE FROM OUTSIDE (routable address)"
    }
    $1 ~ /^(tcp|udp)$/ {
      loc = $5
      n = split(loc, p, ":")
      port = p[n]
      address = substr(loc, 1, length(loc) - length(port) - 1)
      process = (NF >= 7 ? $7 : "(process not visible: the listing was read without privileges)")
      printf "%s  %s  port %s  %s  %s\n", $1, address, port, process, classify(address)
    }'
}

# Log files do not live in the same place on every distribution: Debian and
# Ubuntu write /var/log/auth.log and /var/log/syslog, the RHEL family writes
# /var/log/secure and /var/log/messages. A path written by hand makes every
# count on the other half of the platforms this skill claims to support come
# back NOT VERIFIED, every single time, which reads as a broken audit rather
# than as a finding. So the candidates are listed and the first one that is
# there is the one read, exactly as the login history already does.
first_existing() {   # <file...>
  local f
  for f in "$@"; do
    [ -e "$f" ] && { printf '%s' "$f"; return 0; }
  done
  printf '%s' "${1:-}"   # nothing there: name the first, so the message names a path
}

# grep -c is honest about the count and ambiguous about the failure: it exits 1
# when it counted zero, and 2 when it could not read the file at all. Reading
# only the exit code turns "the log is unreadable" into "no such event ever
# happened", which is the most comfortable lie an audit can tell. Reading only
# the number has the same problem from the other side, because on a failure the
# number is simply absent. Both are needed, and the log usually needs privileges.
count_matches() {   # <pattern> <file...>
  local pat="$1" file out rc
  shift
  file="$(first_existing "$@")"
  out="$(sudo -n grep -c -e "$pat" -- "$file" 2>/dev/null)"; rc=$?
  if [ "$rc" -gt 1 ] || [ -z "$out" ]; then
    out="$(grep -c -e "$pat" -- "$file" 2>/dev/null)"; rc=$?
  fi
  if [ "$rc" -gt 1 ] || [ -z "$out" ]; then
    printf 'NOT VERIFIED: %s is absent or could not be read (privileges needed)' "$file"
  else
    printf '%s' "$out"
  fi
}

# "There is no key file here" can only be said by somebody who was able to look.
# Under a home directory nobody may enter, root's above all, the same empty
# answer means "I could not look", and printing 0 there is the audit declaring
# that root has no keys having never seen the directory.
absence_provable() {   # <path>
  local d="${1%/*}"
  while [ -n "$d" ] && [ ! -e "$d" ]; do d="${d%/*}"; done
  [ -n "$d" ] || d=/
  [ -r "$d" ] && [ -x "$d" ]
}

# An authorized key can carry options in front of it (from="...", restrict,
# command="..."): counting only the lines that start with ssh- skips some of
# them, which are precisely the ones placed by somebody who knew what they were
# doing. A file that exists but cannot be read is not a file with no keys, and
# the file that matters most, root's, needs privileges to be read at all.
count_ssh_keys() {   # <file>
  local out rc
  out="$(sudo -n grep -cvE '^[[:space:]]*(#|$)' -- "$1" 2>/dev/null)"; rc=$?
  if [ "$rc" -gt 1 ] || [ -z "$out" ]; then
    out="$(grep -cvE '^[[:space:]]*(#|$)' -- "$1" 2>/dev/null)"; rc=$?
  fi
  if [ "$rc" -le 1 ] && [ -n "$out" ]; then
    printf '%s' "$out"
  elif [ -e "$1" ]; then
    printf 'NOT VERIFIED: %s exists but could not be read' "$1"
  elif absence_provable "$1"; then
    printf '0'
  else
    printf 'NOT VERIFIED: %s could not be reached (privileges are needed to look inside %s)' "$1" "${1%/*}"
  fi
}

# Every account with a real shell is an account somebody can log into, and its
# authorized_keys file is a list of who can. The account that matters is rarely
# the one running the audit: root, a deploy account, a service account left
# behind by an installer. Accounts whose shell is nologin, false or sync are
# left out: nobody gets a session through them.
login_accounts() {   # reads a passwd stream, prints "<user> <home>"
  awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ { print $1, $6 }'
}

# What a command printed and how it ended are two separate facts, and the report
# needs both. A command that printed nothing and failed was never allowed to
# run: that is NOT VERIFIED. A command that printed results and then failed did
# find those results, and throwing them away because of the exit code is how a
# search for exposed environment files reports nothing while holding the list of
# them: find exits 1 as soon as one of the directories it was handed does not
# exist, and /data does not exist on a plain Ubuntu.
verdict_empty() {   # <rc> <output> <phrase if it succeeded but printed nothing>
  if [ -n "$2" ]; then
    printf '%s' "$2"
  elif [ "$1" -ne 0 ]; then
    printf 'NOT VERIFIED: the command printed nothing and did not succeed (permission denied, tool missing or timed out)'
  else
    printf '%s' "$3"
  fi
}

# The note that goes with output which arrived anyway. It is printed after the
# list, and after the cut, so a list too long to be shown in full keeps it. The
# clock cases are left to emit, which words them better: saying it twice teaches
# the reader to skim both.
note_partial() {   # <rc> <output>
  case "$1" in 0|124|137) return 0 ;; esac
  [ -n "$2" ] || return 0
  printf '(the command also reported an error: the result may be incomplete)\n'
}

# docker inspect with no running container receives no argument at all: it
# prints its usage and exits 1. Read as a failure that is NOT VERIFIED, read as
# an empty answer it is "the containers are confined". Neither is true, and the
# three real situations are worth telling apart, because only one of them is
# good news.
docker_state() {   # <engine present: yes|no> <exit code of docker ps -q> <ids>
  if [ "$1" != yes ]; then printf 'ABSENT'; return 0; fi
  if [ "$2" -ne 0 ]; then printf 'DENIED'; return 0; fi
  if [ -z "$(printf '%s' "$3" | tr -d '[:space:]')" ]; then printf 'NONE'; return 0; fi
  printf 'RUNNING'
}

# The system log is normally root-only, so without privileges this counts the
# denials of a file it never opened. Zero denials is a real finding, "I could not
# look" is a different one, and the report has a place for each.
count_mac_denied() {   # <log file...>
  count_matches 'apparmor="DENIED"' "$@"
}

# Rotated package logs are named log, log.1.gz, log.2.gz: the glob expands in
# alphabetical order, so without a final sort "tail" returns the lines of the
# OLDEST log and the audit concludes the server has not been updated in months.
latest_upgrades() { grep " upgrade " | sort | tail -5; }

sec() { printf '\n\n##### SECTION: %s\n' "$1"; }

# Prints at most <lines> of the output, then whatever the reader needs in order
# not to mistake a list that stops for a list that ended.
#
# The old shape was "timeout ... | head -n": head walks away as soon as it has
# its lines, the shell reports 141 for the broken pipe, and the 124 that says
# the clock ran out is gone. It disappeared precisely on the long listings, a
# SUID sweep above all, where a cut list read as a complete one means an audit
# that says "these are the setuid binaries" having seen a third of them.
# Collecting the output first and cutting it afterwards keeps the exit code.
emit() {   # emit <rc> <lines> <seconds> <output>
  local rc="$1" lines="$2" secs="$3" out="$4" total=0
  if [ -n "$out" ]; then
    printf '%s\n' "$out" | head -n "$lines"
    total="$(printf '%s\n' "$out" | wc -l | tr -d '[:space:]')"
  fi
  if [ "$total" -gt "$lines" ]; then
    printf '(only the first %s lines out of %s are shown: the list is cut)\n' "$lines" "$total"
  fi
  if [ "$rc" = 124 ] || [ "$rc" = 137 ]; then
    printf '(command interrupted: it exceeded the %s second limit, what is above is incomplete)\n' "$secs"
  fi
  return 0
}

# run "command" [max_lines] [max_seconds]
#
# Silence and failure together must never be printed as silence. Most commands
# here end with 2>/dev/null, so a denied sudo arrives as an empty string and an
# error code, and an empty section reads as "there is nothing there". On the
# firewall listing that reading is a clean bill of health for a machine nobody
# was allowed to look at, which is the exact failure this collector exists to
# avoid. Output that did arrive is still printed, with the note that something
# else went wrong: what a command printed and how it ended are two facts, and
# the bundle carries both.
run() {
  local out rc
  printf '\n$ %s\n' "$1"
  out="$(timeout "${3:-60}" bash -c "$1" 2>&1)"; rc=$?
  emit "$rc" "${2:-40}" "${3:-60}" "$(verdict_empty "$rc" "$out" '')"
  note_partial "$rc" "$out"
}

# run_filtered <filter_function> "command" [lines] [seconds]
# Same as run, but passes the output through a filter (usually mask_ip). The
# filter runs after the command, not inside its pipeline, so the exit code that
# arrives at emit is the command's and the clock is checked here too.
# The same rule as run: silence plus failure is never printed as silence. It
# matters more here than anywhere else, because the commands that go through a
# filter are the login history and the failed login attempts, and an empty
# failed-login section reads as "nobody even tried".
run_filtered() {
  local filter="$1"; shift
  local out rc
  printf '\n$ %s\n' "$1"
  out="$(timeout "${3:-60}" bash -c "$1" 2>&1)"; rc=$?
  out="$(printf '%s' "$out" | "$filter")"
  emit "$rc" "${2:-40}" "${3:-60}" "$(verdict_empty "$rc" "$out" '')"
  note_partial "$rc" "$out"
}

# check "command" "phrase if it succeeded but printed nothing" [lines] [seconds]
# For the checks where silence is easily mistaken for good news.
check() {
  local out rc
  printf '\n$ %s\n' "$1"
  out="$(timeout "${4:-60}" bash -c "$1" 2>&1)"; rc=$?
  emit "$rc" "${3:-40}" "${4:-60}" "$(verdict_empty "$rc" "$out" "$2")"
  note_partial "$rc" "$out"
  printf '\n'
  return 0
}

# run_summary <summariser> "command" "phrase if it ran and found nothing" [lines] [seconds]
#
# A summariser reads a stream and cannot tell the two empty streams apart: the
# one from a command that ran and found nothing, and the one from a command that
# was never allowed to run. Fed the second, summarize_sudoers prints "sudo rules:
# 0 / NOPASSWD present: no", which is a clean bill of health for a check that
# never happened, on the very question the audit exists to answer. So the command
# runs here, its exit code is kept, and the summariser only ever sees real output.
#
# Output and exit code stay two separate facts here too. "cat /etc/crontab
# /etc/cron.d/*" exits 1 when that directory is empty and the pattern stays a
# literal name, and by then the jobs of /etc/crontab have already been read:
# dropping them because of the exit code means an audit that never saw the
# scheduled tasks while holding them.
run_summary() {
  local fn="$1" cmd="$2" phrase="$3" lines="${4:-40}" secs="${5:-60}" out rc body=''
  printf '\n$ %s\n' "$cmd"
  out="$(timeout "$secs" bash -c "$cmd" 2>/dev/null)"; rc=$?
  # shellcheck disable=SC2086
  [ -n "$out" ] && body="$(printf '%s\n' "$out" | $fn)"
  emit "$rc" "$lines" "$secs" "$(verdict_empty "$rc" "$body" "$phrase")"
  note_partial "$rc" "$out"
  printf '\n'
  return 0
}

# Login history: where there is no auth log file (a server with the journal
# only) read the journal instead. Without this fallback the section stays empty
# and it looks as if nobody ever logged in.
# The privileged read is tried first, then the same read without privileges: on
# a host where the audit user is in the group that may read the log but has no
# password-less sudo, giving up after the first attempt makes the bundle print a
# real count of failed logins and, two lines below, NOT VERIFIED for the history
# of that very same file. The counting helper already retries this way, and two
# answers about one file, one of them a shrug, is worse than either alone.
login_history() {   # <word to search> [lines]
  local word="$1" n="${2:-8}" out
  local logs="${AUDIT_AUTH_LOGS:-/var/log/auth.log /var/log/secure}"
  out="$(sudo -n grep -h -- "$word" $logs 2>/dev/null | tail -n "$n")"
  if [ -z "$out" ]; then
    out="$(grep -h -- "$word" $logs 2>/dev/null | tail -n "$n")"
  fi
  if [ -z "$out" ]; then
    out="$(sudo -n journalctl -u ssh -u sshd --no-pager -n 400 2>/dev/null | grep -- "$word" | tail -n "$n")"
  fi
  if [ -z "$out" ]; then
    out="$(journalctl -u ssh -u sshd --no-pager -n 400 2>/dev/null | grep -- "$word" | tail -n "$n")"
  fi
  printf '\n$ login history: %s (auth log, else journal)\n' "$word"
  if [ -z "$out" ]; then
    printf 'NOT VERIFIED: neither the auth log nor the journal returned any line\n'
  else
    printf '%s\n' "$out" | mask_ip
  fi
}

if [ "${AUDIT_FUNCTIONS_ONLY:-0}" = 1 ]; then
  return 0 2>/dev/null || exit 0
fi

# =============================================================================
# BODY
# =============================================================================
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Directories the filesystem searches must not walk into: the container storage
# directory holds millions of image-layer files, which alone would make the scan
# take hours and would return the SUID binaries living INSIDE the images rather
# than on the server.
PRUNE='-path /proc -o -path /sys -o -path /run -o -path /var/lib/docker -o -path /var/lib/containers -o -path /snap -o -path /mnt -o -path /media -o -path /backup'

printf '##### LINUX SERVER AUDIT: READ-ONLY COLLECTION\n'
printf 'collected on: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'collected by: %s@%s\n' "$(id -un)" "$(hostname)"
printf 'collector version: 5\n'
printf 'note: session IPs masked; sudo rules, cron and fstab summarised, never quoted\n'

sec "IDENTITY AND VERSIONS"
run 'head -4 /etc/os-release' 6
run 'uname -srvm' 3
run 'uptime' 3
run 'sudo -n true && echo SUDO_WITHOUT_PASSWORD_OK || echo SUDO_ASKS_PASSWORD_OR_DENIED' 3
run 'df -h --output=source,size,used,pcent,target -x tmpfs -x devtmpfs' 15
run 'free -h' 5

sec "PENDING UPDATES"
# An unpatched service is the most ordinary and most exploited way in.
printf '\n$ reboot pending?\n%s\n' "$(verdict_reboot /var/run/reboot-required /var/run/reboot-required.pkgs)"
run 'cat /var/run/reboot-required.pkgs 2>/dev/null' 12
run 'apt list --upgradable 2>/dev/null | tail -n +2' 40 120
run 'apt list --upgradable 2>/dev/null | grep -ci security || [ $? = 1 ]' 3 120
run 'dnf -q check-update --security 2>/dev/null | head -20' 20 120
run 'cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null' 10
run 'systemctl is-enabled unattended-upgrades 2>/dev/null; systemctl is-active unattended-upgrades 2>/dev/null' 4
printf '\n$ last upgrades installed (package log, in date order)\n'
zgrep -h " upgrade " /var/log/dpkg.log* 2>/dev/null | latest_upgrades

sec "ACCOUNTS AND PRIVILEGES"
# Who can become administrator, and in how many different ways.
run "awk -F: '\$3==0 {print \"UID 0: \"\$1}' /etc/passwd" 10
run "awk -F: '\$3<1000 && \$7 !~ /nologin|false|sync/ {print \$1, \$3, \$7}' /etc/passwd" 20
run "awk -F: '\$3>=1000 && \$3<65534 {print \$1, \$3, \$7}' /etc/passwd" 20
# Only the first 3 characters of the hash: they name the algorithm, not the password.
run "sudo -n awk -F: '{ if (\$2==\"\") print \$1\": NO PASSWORD\"; else if (\$2 ~ /^[!*]/) print \$1\": locked\"; else print \$1\": active (\"substr(\$2,1,3)\")\" }' /etc/shadow" 30
run "sudo -n awk -F: '\$5==\"\" || \$5>365 {print \$1\": password expiry \"\$5\" days\"}' /etc/shadow" 25
run 'getent group sudo wheel adm docker root' 8
printf '\n$ summary of sudo rules (contents not reported)'
run_summary summarize_sudoers 'sudo -n grep -rhv "^#" /etc/sudoers /etc/sudoers.d/' \
  'the sudo configuration was read and holds no rule' 12
# last and lastb print the host NAME when reverse resolution gives them one, and
# a name is not an IP address: the mask has nothing to bite on and the address
# leaves in the bundle spelled out. -i asks for the numeric form, which is what
# the masking promise at the top of this file is written against.
run_filtered mask_ip 'sudo -n last -i -n 12 2>/dev/null' 15
run_filtered mask_ip 'sudo -n lastb -i -n 8 2>/dev/null' 10
printf '\n$ failed password attempts recorded in the authentication log\n%s\n' \
  "$(count_matches 'Failed password' /var/log/auth.log /var/log/secure)"
login_history "Invalid user" 5

sec "SSH"
# The daemon prints the configuration actually in effect, not the one written in
# the file: that way the defaults and the overridden directives are visible too,
# and a commented line cannot be mistaken for an unset one.
run 'sudo -n sshd -T 2>/dev/null | grep -Ei "^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|challengeresponse|kbdinteractive|usepam|x11forwarding|allowtcpforwarding|allowstreamlocalforwarding|permittunnel|gatewayports|maxauthtries|maxsessions|logingracetime|clientalive|allowusers|allowgroups|denyusers|hostbasedauthentication|ignorerhosts|loglevel|banner|strictmodes|permituserenvironment)"' 40
run 'sudo -n sshd -T 2>/dev/null | grep -Ei "^(ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms)"' 10
run 'ls -ld ~/.ssh 2>/dev/null; ls -l ~/.ssh/ 2>/dev/null' 15
# Every account with a real shell, not only the one that opened this session.
# The account that matters is rarely that one: root, a deploy account, a service
# account left behind by an installer. Each line carries the count of real key
# lines (options in front included) plus the mode and the owner of the file,
# because a key file others can write is a key file others can extend.
printf '\n$ authorized keys of every account with a real shell (options included in the count)\n'
login_accounts < /etc/passwd | while read -r acct home; do
  [ -n "$home" ] || continue
  kf="$home/.ssh/authorized_keys"
  meta="$(sudo -n stat -c "%a %U:%G" "$kf" 2>/dev/null)"
  [ -n "$meta" ] || meta="$(stat -c "%a %U:%G" "$kf" 2>/dev/null)"
  printf '%-16s keys: %s | file: %s %s\n' "$acct" "$(count_ssh_keys "$kf")" \
    "${meta:-(mode and owner not readable)}" "$kf"
done
run 'stat -c "%a %U:%G %n" ~/.ssh ~/.ssh/authorized_keys 2>/dev/null' 6
check 'sudo -n ls -l /root/.ssh/' 'nothing inside the root SSH directory (good)' 10
run 'systemctl is-active fail2ban 2>/dev/null; sudo -n fail2ban-client status 2>/dev/null' 15
run 'sudo -n fail2ban-client status sshd 2>/dev/null' 15
login_history "Accepted " 8

sec "FIREWALL AND LISTENING PORTS"
# The comparison that counts: what is listening AGAINST what the firewall lets
# through. A forgotten open port is the classic way in.
check 'sudo -n ufw status verbose' 'the firewall front end answered with no rules' 40
check 'sudo -n firewall-cmd --list-all' 'the firewall front end answered with no zone detail' 40
run 'sudo -n iptables -S 2>/dev/null' 60
# The IPv6 firewall is a separate firewall: a rule written only for IPv4 leaves
# the same port open to whoever arrives over the other protocol.
run 'sudo -n ip6tables -S 2>/dev/null' 40
# The NAT table is not shown by the plain listing command, and a published
# container port lives there as a redirection.
run 'sudo -n iptables -t nat -S 2>/dev/null' 50
run 'sudo -n ip6tables -t nat -S 2>/dev/null' 25
run 'sudo -n nft list ruleset 2>/dev/null | head -40' 40
run 'sudo -n ss -tulpn 2>/dev/null || ss -tulpn' 60
printf '\n$ every listening socket, with what its address means'
# Retried without privileges, the way the log counts and the login history
# already are: without passwordless sudo this whole section came back NOT
# VERIFIED, while any account can list the same sockets and lose only the
# process names, which the line itself then says.
# The cap is well above the raw listing above: this prints one line per socket
# now, not one per wildcard bind, and the report is told to count the
# categories. A count taken from a cut list is a number stated as a fact.
run_summary public_ports 'sudo -n ss -tulpn 2>/dev/null || ss -tulpn' \
  'the socket listing was read and nothing is listening at all' 150

sec "CONTAINERS"
run 'sudo -n docker version --format "{{.Server.Version}}" 2>/dev/null; sudo -n docker info 2>/dev/null | grep -Ei "storage driver|cgroup version|rootless|userns|live restore|security options" ' 15
run 'sudo -n docker ps --format "{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}" 2>/dev/null' 40
run 'sudo -n docker ps -a --filter status=exited --format "{{.Names}}|{{.Image}}|{{.Status}}" 2>/dev/null' 20
# Privileged, running as root, daemon socket mounted, host paths mounted: the
# routes out of a container and onto the host. An empty answer here has three
# very different causes and none of them is "the containers are confined", so
# the situation is decided once, before asking anything else.
#
# The list of container ids is flattened onto one line on purpose: left with its
# newlines it would break the command it is pasted into in two.
if command -v docker >/dev/null 2>&1; then DOCKER_PRESENT=yes; else DOCKER_PRESENT=no; fi
# The exit code is taken before anything is piped anywhere: after a pipe it is
# the last command's, and tr always succeeds, so a refused engine would look
# like an engine with nothing running.
DOCKER_IDS="$(sudo -n docker ps -q 2>/dev/null)"; DOCKER_PS_RC=$?
DOCKER_IDS="$(printf '%s' "$DOCKER_IDS" | tr '\n' ' ')"
DOCKER_SITUATION="$(docker_state "$DOCKER_PRESENT" "$DOCKER_PS_RC" "$DOCKER_IDS")"

docker_check() {   # <command, container ids already inside> <phrase if it ran and printed nothing>
  case "$DOCKER_SITUATION" in
    ABSENT) printf '\n$ %s\nno container engine on this machine: there is nothing to confine\n\n' "$1" ;;
    DENIED) printf '\n$ %s\nNOT VERIFIED: the container engine did not answer (permission denied, or the daemon is not running)\n\n' "$1" ;;
    NONE)   printf '\n$ %s\n%s\n\n' "$1" "$2" ;;
    *)      check "$1" "$2" 40 ;;
  esac
}

docker_check "sudo -n docker inspect $DOCKER_IDS --format '{{.Name}} privileged={{.HostConfig.Privileged}} user=[{{.Config.User}}] pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} restart={{.HostConfig.RestartPolicy.Name}} readonly={{.HostConfig.ReadonlyRootfs}}' 2>/dev/null" \
  'the container engine answered with no running container'
# The mount filter has to swallow its own "no match", otherwise a clean set of
# mounts is indistinguishable from a docker that never ran; pipefail keeps the
# engine's own failure visible.
docker_check "set -o pipefail; sudo -n docker inspect $DOCKER_IDS --format '{{.Name}}{{range .Mounts}} [{{.Source}}=>{{.Destination}} writable={{.RW}}]{{end}}' 2>/dev/null | { grep -Ei 'docker.sock|/etc|/root|/var/run|=>/host|writable=true' || true; }" \
  'no running container mounts a sensitive host path'
docker_check "sudo -n docker inspect $DOCKER_IDS --format '{{.Name}} cap_add={{.HostConfig.CapAdd}} cap_drop={{.HostConfig.CapDrop}} apparmor={{.AppArmorProfile}}' 2>/dev/null" \
  'the container engine answered with no running container'
run 'sudo -n docker images --format "{{.Repository}}:{{.Tag}} created {{.CreatedSince}}" 2>/dev/null' 30
run 'sudo -n docker network ls 2>/dev/null' 20
run 'sudo -n podman ps --format "{{.Names}}|{{.Image}}|{{.Ports}}|{{.Status}}" 2>/dev/null' 20

sec "PERMISSIONS AND SENSITIVE FILES"
# Names and modes, never contents. Every one of these searches needs privileges
# to be worth anything, and every one of them prints nothing when it is refused
# them: an empty answer would otherwise read as "no setuid binary out of place,
# no world writable file, no key lying around", which is the report you would
# write about a server you never looked at.
# sort exits 0 even when the find in front of it was refused, so without
# pipefail this one line would go back to reporting a clean setuid sweep.
check "set -o pipefail; sudo -n find / -xdev \\( $PRUNE \\) -prune -o -type f -perm /6000 -printf '%m %u:%g %p\\n' 2>/dev/null | sort" \
  'the search ran and found no setuid or setgid file' 80 180
check "sudo -n find / -xdev \\( $PRUNE \\) -prune -o -type f -perm -0002 -printf '%m %u:%g %p\\n' 2>/dev/null" \
  'the search ran and found no world writable file' 30 180
check "sudo -n find / -xdev \\( $PRUNE \\) -prune -o -type d -perm -0002 ! -perm -1000 -printf '%m %u:%g %p\\n' 2>/dev/null" \
  'the search ran and found no world writable directory without the sticky bit' 25 180
check "sudo -n find / -xdev \\( $PRUNE \\) -prune -o \\( -nouser -o -nogroup \\) -printf '%u:%g %p\\n' 2>/dev/null" \
  'the search ran and found no file owned by a deleted account' 20 180
check "sudo -n find /opt /home /srv /data /etc -xdev -type f \\( -name '.env' -o -name '.env.*' -o -name '*.env' -o -name '*credential*' -o -name '*secret*' \\) -printf '%m %u:%g %p\\n' 2>/dev/null" \
  'the search ran and found no environment or credential file' 60 120
check "sudo -n find /opt /home /root /etc -xdev -type f \\( -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' -o -name '*.pfx' \\) -printf '%m %u:%g %p\\n' 2>/dev/null" \
  'the search ran and found no private key or certificate file' 40 120
run 'sudo -n ls -l /etc/shadow /etc/gshadow /etc/passwd /etc/group /etc/sudoers /etc/ssh/sshd_config 2>/dev/null' 12
run 'sudo -n ls -ld /opt /opt/* /home/* 2>/dev/null' 30
run 'mount | grep -E " /(tmp|var|var/log|var/tmp|home|boot|dev/shm) " ' 15
printf '\n$ summary of /etc/fstab (device identifiers masked)\n'
summarize_fstab < /etc/fstab 2>/dev/null | head -15

sec "ENCRYPTION AT REST"
# Permissions stop a logged-in user. They stop nobody who holds the disk, or a
# copy of it: a snapshot, a decommissioned volume, a backup image. Only
# encryption does. The names of the unlocked mappings and the count of entries
# are enough to tell whether anything is encrypted at all; the contents of
# crypttab are not collected, because a key file path is a map to the key.
run 'lsblk -o NAME,TYPE,FSTYPE,SIZE,MOUNTPOINT 2>/dev/null' 30
run 'ls -l /etc/crypttab 2>/dev/null && printf "entries in crypttab: %s\n" "$(grep -cvE "^[[:space:]]*(#|$)" /etc/crypttab 2>/dev/null)" || echo "no /etc/crypttab: nothing is unlocked at boot"' 8
run 'swapon --show 2>/dev/null || echo "no active swap"' 10
run 'ls -d /home/*/.Private /home/*/Private 2>/dev/null || echo "no per-user encrypted home directories"' 10

sec "KERNEL AND PROCESS ISOLATION"
run 'sudo -n sysctl -a 2>/dev/null | grep -E "^(kernel\\.(dmesg_restrict|kptr_restrict|randomize_va_space|sysrq|unprivileged_bpf_disabled|unprivileged_userns_clone|yama\\.ptrace_scope|core_pattern)|fs\\.(protected_hardlinks|protected_symlinks|protected_fifos|protected_regular|suid_dumpable)|net\\.ipv4\\.(tcp_syncookies|conf\\.all\\.(rp_filter|accept_redirects|send_redirects|accept_source_route|log_martians)|icmp_echo_ignore_broadcasts|ip_forward)|net\\.ipv6\\.conf\\.all\\.(accept_redirects|accept_ra|disable_ipv6))"' 40
run 'cat /proc/cmdline' 3
check 'sudo -n aa-status' 'the mandatory access control status tool printed nothing' 15
# grep answers "found nothing" with a failure exit code, and here finding
# nothing is the good news. Left as a grep, the pipeline reports NOT VERIFIED on
# a perfectly healthy machine, and a warning that fires when all is well teaches
# the reader to ignore it, which costs more than the warning ever saves. awk
# prints the block and always succeeds; pipefail keeps a denied sudo failing, so
# "could not look" and "looked, nothing there" stay two different answers.
check 'set -o pipefail; sudo -n aa-status 2>/dev/null | awk "/profiles are in complain mode/{s=1} s{print}"' 'no profile in complain mode' 25
check 'sudo -n sestatus' 'no SELinux status available on this machine' 12
printf '\n$ mandatory access control denials recorded in the system log\n%s\n' \
  "$(count_mac_denied /var/log/syslog /var/log/messages)"
run 'sudo -n getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null' 30 90

sec "SERVICES AND SCHEDULED TASKS"
# Every listening service is attack surface: code that does not run has no
# vulnerabilities.
run 'systemctl list-units --type=service --state=running --no-pager --no-legend' 50
run 'systemctl list-unit-files --state=enabled --no-pager --no-legend' 50
run 'systemctl list-timers --all --no-pager --no-legend' 25
run 'sudo -n ls -l /etc/cron.d/ /etc/cron.daily/ 2>/dev/null' 40
printf '\n$ summary of system scheduled jobs (arguments not reported)'
run_summary "summarize_cron system" 'sudo -n cat /etc/crontab /etc/cron.d/*' \
  'the system crontabs were read and hold no job' 25
printf '\n$ summary of this user scheduled jobs'
run_summary "summarize_cron user" 'crontab -l 2>/dev/null || [ $? = 1 ]' \
  'this user has no personal crontab' 15

sec "LOGGING AND TRACEABILITY"
# If the server is broken into, the logs are the only possible reconstruction:
# they have to be kept long enough and, ideally, off the machine as well.
run 'systemctl is-active auditd 2>/dev/null; sudo -n auditctl -l 2>/dev/null | head -20' 25
run 'grep -E "^(Storage|SystemMaxUse|MaxRetentionSec|ForwardToSyslog|Compress)" /etc/systemd/journald.conf 2>/dev/null' 10
run 'journalctl --disk-usage 2>/dev/null' 3
run 'ls /etc/logrotate.d/ 2>/dev/null' 40
check 'grep -rhE "^[^#]*@@?[0-9a-zA-Z]" /etc/rsyslog.conf /etc/rsyslog.d/' 'no log forwarding to an external server' 12
run 'sudo -n ls -l /var/log/ | head -25' 25

sec "SECURITY TOOLING PRESENT"
run 'for t in lynis rkhunter chkrootkit clamscan freshclam aide auditctl fail2ban-client ufw firewall-cmd nft iptables docker podman fapolicyd cryptsetup; do printf "%-16s %s\\n" "$t" "$(command -v $t 2>/dev/null || echo ABSENT)"; done' 20
check 'ls -l /var/log/lynis* /var/log/rkhunter* 2>/dev/null' 'no local scan recorded' 10

sec "NETWORK AND EXPOSURE"
run 'ip -brief address' 15
run 'ip route' 10
run_filtered mask_ip 'sudo -n ss -tn state established 2>/dev/null | head -20' 22
run 'grep -v "^#" /etc/resolv.conf 2>/dev/null' 10

printf '\n\n##### END OF COLLECTION\n'
