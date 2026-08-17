#!/usr/bin/env bash
# =============================================================================
# linux-server-audit: local wrapper.
#
# Reads the audit profile, refuses to run against an undeclared host, picks the
# right ssh binary for the platform, pipes collect.sh to the server on standard
# input, and writes the bundle into the output directory.
#
# Usage:
#   bash run-audit.sh                  collect from the host in the profile
#   bash run-audit.sh --check-profile  show the profile and connect to nothing
#   bash run-audit.sh --check-ssh      say which ssh client would be used
#
# The profile is $AUDIT_PROFILE, or ~/.config/audit-skills/profile.conf when
# that variable is unset. There is no default target: a missing or unfinished
# profile stops the run with a non zero exit code.
# =============================================================================
set -u
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
PROFILE_PATH="${AUDIT_PROFILE:-$HOME/.config/audit-skills/profile.conf}"

stop() {   # stop <message ...>
  printf 'STOP: %s\n' "$1" >&2
  shift
  for line in "$@"; do printf '%s\n' "$line" >&2; done
  exit 3
}

# On Windows the Git Bash ssh does not work and the Windows OpenSSH binary is
# needed; on Linux that path does not exist and the system ssh is the right one.
# When candidates are given they are the only ones considered, which is how the
# test suite exercises the "no client here" answer without opening anything.
ssh_binary() {   # [candidate ...]
  local c
  if [ "$#" -gt 0 ]; then
    for c in "$@"; do [ -x "$c" ] && { printf '%s' "$c"; return 0; }; done
    return 1
  fi
  [ -x /c/Windows/System32/OpenSSH/ssh.exe ] && { printf '%s' /c/Windows/System32/OpenSSH/ssh.exe; return 0; }
  command -v ssh 2>/dev/null
}

# Whether there is an ssh client on this machine has nothing to do with the
# profile, so the question is answered before the profile is even read.
if [ "${1:-}" = "--check-ssh" ]; then
  shift
  if found="$(ssh_binary "$@")" && [ -n "$found" ]; then
    printf 'ssh client:  %s\n' "$found"
    printf 'Nothing was connected to: this is a client check only.\n'
    exit 0
  fi
  printf 'STOP: no ssh client found on this machine\n' >&2
  printf 'On Windows OpenSSH ships with the system (Settings, Optional features);\n' >&2
  printf 'on Linux it is the openssh-client package. Nothing was connected to.\n' >&2
  exit 5
fi

# The example profile is a form, not a profile. Copied as it stands it names a
# documentation address (203.0.113.x, reserved by RFC 5737 precisely so it can
# be printed in manuals) and domains reserved by RFC 2606, which nobody owns and
# no real machine answers for. The skills promise in writing to refuse a profile
# that was never filled in, so they have to be able to recognise one.
profile_is_example() {   # <value ...>
  local v tok
  for v in "$@"; do
    for tok in $(printf '%s' "$v" | tr 'A-Z' 'a-z'); do
      case "$tok" in
        203.0.113.*|example.com|example.org|example.net|*.example.com|*.example.org|*.example.net)
          return 0 ;;
      esac
    done
  done
  return 1
}

# The profile is a form, and a form is data.
#
# It used to be sourced, which made every line in it a command: a profile
# copied from somewhere else, or edited by somebody who did not write it, ran
# with your account and your keys, and nothing in the file warned you. Here each
# line is parsed, the key has to be one of a closed list, and anything else stops
# the run naming the line that is wrong.
#
# It prints the pairs rather than assigning them, so the caller decides what to
# do with each one and this function stays something the tests can feed by hand.
AUDIT_PROFILE_KEYS='SSH_HOST SSH_PORT SSH_USER WEB_TARGETS OUTPUT_DIR'

read_profile() {   # read_profile <path>
  local line key value known k
  while IFS= read -r line || [ -n "$line" ]; do
    # Trimmed at both ends before anything else. This covers three shapes that
    # sourcing accepted and parsing would otherwise refuse on a file somebody
    # just edited: an indented key, a line holding only spaces, and the carriage
    # return a profile saved on Windows carries. Left in place, that carriage
    # return rides along inside the hostname and inside every target, and every
    # comparison downstream fails for a reason nothing on screen explains.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
      ''|'#'*) continue ;;
    esac
    case "$line" in
      *=*) ;;
      *) stop "this line in $1 is not a KEY=value line:" \
              "  $line" \
              "The profile is a form, not a script: only KEY=\"value\" lines are read," \
              "and nothing in it is ever executed." ;;
    esac
    key="${line%%=*}"
    value="${line#*=}"
    # The old key gets its own message: it is the one change in this release
    # that breaks a file people already have, so the message has to be enough
    # to fix it without opening any documentation.
    if [ "$key" = "ALLOWED_DOMAINS" ]; then
      stop "This profile uses ALLOWED_DOMAINS, which no longer exists." \
           "Replace it with WEB_TARGETS and write every host in full, separated by spaces:" \
           "" \
           "  WEB_TARGETS=\"radlab.it www.radlab.it quarantotto.menulampo.it\"" \
           "" \
           "A bare domain no longer covers its subdomains: every host you want audited" \
           "must be written out. Nothing was collected."
    fi
    case "$key" in
      *[!A-Z_]*) stop "this line in $1 has a key that is not a plain name:" "  $line" ;;
    esac
    known=0
    for k in $AUDIT_PROFILE_KEYS; do [ "$key" = "$k" ] && known=1; done
    [ "$known" -eq 1 ] || stop "unknown key in $1:" \
      "  $line" \
      "Known keys: $AUDIT_PROFILE_KEYS"
    # Quotes are punctuation. Stripping them one end at a time accepted a value
    # that was never quoted properly: SSH_HOST="10.9.8.7"  # prod came through
    # as the host 10.9.8.7"  # prod and the run went on to connect to it.
    # Single quotes are handled too: this file was a shell script until now, so
    # they are a shape people already have, and left inside the value they made
    # the one declared host unreachable with a message contradicting the file.
    # An unquoted value may not carry a comment either: sourcing dropped it, and
    # keeping it would put it inside a hostname or a directory name.
    case "$value" in
      '"'*'"') value="${value#\"}"; value="${value%\"}" ;;
      "'"*"'") value="${value#\'}"; value="${value%\'}" ;;
      '"'*|*'"'|"'"*|*"'") stop "the value of $key in $1 is not quoted properly:" \
                      "  $line" \
                      "A quote that opens must close, and nothing may follow it." ;;
      *'#'*) stop "the value of $key in $1 carries what looks like a comment:" \
                  "  $line" \
                  "There are no trailing comments: put them on a line of their own," \
                  "starting with #, or quote the value if the # is really part of it." ;;
    esac
    # Sourcing expanded shell variables for free, and reading the file as data
    # does not. A profile written back then would now write its bundles into a
    # directory literally called "$HOME", quietly, and you would go looking for
    # reports that are not where you left them. Refused rather than expanded:
    # expanding is what made this file dangerous in the first place.
    case "$value" in
      *'$'*) stop "the value of $key in $1 holds a shell variable:" \
                  "  $line" \
                  "The profile is read as data, so nothing in it is expanded." \
                  "Write the path in full, or start it with ~/ for your home directory:" \
                  "" \
                  "  $key=\"~/sync/audit\"" ;;
    esac
    # The tilde is the shortcut people expect, and it expands without executing
    # anything, so this one is kept.
    case "$value" in
      '~/'*) value="$HOME/${value#\~/}" ;;
      '~') value="$HOME" ;;
    esac
    printf '%s=%s\n' "$key" "$value"
  done < "$1"
}

# The profile is the only source of the target. Reading it here, once, is what
# keeps the collector from ever running against a host nobody declared.
if [ ! -f "$PROFILE_PATH" ]; then
  stop "no audit profile found at $PROFILE_PATH" \
       "Copy profile.example.conf there, or point AUDIT_PROFILE at your own file," \
       "and fill in SSH_HOST, SSH_USER and WEB_TARGETS before running again."
fi

SSH_HOST=''; SSH_PORT=''; SSH_USER=''; WEB_TARGETS=''; OUTPUT_DIR=''
# read_profile calls stop on a bad line, and stop exits: run in a pipeline it
# would exit a subshell and the run would carry on with an empty profile. So it
# runs first, on its own, and only its output is read here.
PROFILE_LINES="$(read_profile "$PROFILE_PATH")" || exit $?
while IFS='=' read -r k v; do
  case "$k" in
    SSH_HOST) SSH_HOST="$v" ;;
    SSH_PORT) SSH_PORT="$v" ;;
    SSH_USER) SSH_USER="$v" ;;
    WEB_TARGETS) WEB_TARGETS="$v" ;;
    OUTPUT_DIR) OUTPUT_DIR="$v" ;;
  esac
done <<EOF
$PROFILE_LINES
EOF

SSH_PORT="${SSH_PORT:-22}"
OUTPUT_DIR="${OUTPUT_DIR:-./audit-output}"

# SSH_HOST is what this skill actually needs, and its absence is the sign of a
# profile nobody filled in. The old check demanded ALLOWED_DOMAINS, a value this
# skill never used for anything: it was standing in as proof the form had been
# completed, and it was the wrong field to ask for.
if [ -z "$SSH_HOST" ] || [ -z "$SSH_USER" ]; then
  stop "SSH_HOST or SSH_USER is missing in $PROFILE_PATH" \
       "Both are required: there is no default host."
fi
if profile_is_example "$SSH_HOST" "$WEB_TARGETS"; then
  stop "the profile was never filled in: $PROFILE_PATH still holds example values" \
       "203.0.113.x, example.com, example.org and example.net are reserved names" \
       "from the documentation: no machine of yours answers there." \
       "Replace them with your own host and your own domains."
fi

# The bundle name carries the hour and the minute, not the day alone. With the
# day alone, a second run overwrote the first, and the shell truncated the file
# the moment it opened the redirection: a connection that failed to open at all
# still destroyed the bundle collected earlier that day, which is the copy you
# would want to compare against.
bundle_path() { printf '%s/raw/bundle-server-%s.txt' "$OUTPUT_DIR" "$(date +%Y-%m-%d-%H%M%S)"; }

if [ "${1:-}" = "--check-profile" ]; then
  printf 'profile:         %s\n' "$PROFILE_PATH"
  printf 'target host:     %s\n' "$SSH_HOST"
  printf 'ssh port:        %s\n' "$SSH_PORT"
  printf 'ssh user:        %s\n' "$SSH_USER"
  printf 'output dir:      %s\n' "$OUTPUT_DIR"
  printf 'bundle would be: %s\n' "$(bundle_path)"
  printf 'web targets:     %s\n' "$WEB_TARGETS"
  printf 'Nothing was connected to: this is a profile check only.\n'
  exit 0
fi

# No client, no collection, and it is said in those words. Run with an empty
# command name the whole thing used to fail somewhere inside, leave an empty
# file behind, and end on "the collection does not end with the completion
# marker, run it again": you can run that again all evening without ever being
# told that this machine has no ssh client at all. The check comes before
# anything is written, so a machine without a client is left exactly as it was.
if ! ssh_bin="$(ssh_binary)" || [ -z "$ssh_bin" ]; then
  stop "no ssh client found on this machine" \
       "On Windows OpenSSH ships with the system (Settings, Optional features);" \
       "on Linux it is the openssh-client package." \
       "Nothing was connected to and no file was written."
fi

mkdir -p "$OUTPUT_DIR/raw"
bundle="$(bundle_path)"
partial="$bundle.part"

printf 'Collecting from %s@%s port %s (read only, two to three minutes)\n' \
  "$SSH_USER" "$SSH_HOST" "$SSH_PORT" >&2

# The collection lands beside the bundle and takes its final name only once it
# has arrived whole. Whatever goes wrong, no earlier bundle is touched, and a
# file called bundle-server-... is always a complete one.
"$ssh_bin" -p "$SSH_PORT" -o ConnectTimeout=20 -o BatchMode=yes \
  "$SSH_USER@$SSH_HOST" 'bash -s' < "$HERE/collect.sh" > "$partial"
rc=$?

# A truncated bundle read as a complete one turns a cut connection into a list
# of imaginary findings.
if ! tail -3 "$partial" 2>/dev/null | grep -q 'END OF COLLECTION'; then
  printf 'WARNING: the collection does not end with the completion marker.\n' >&2
  printf 'It was cut short and kept aside as %s, without becoming a bundle.\n' "$partial" >&2
  printf 'Run it again before analysing anything.\n' >&2
  exit 4
fi

mv "$partial" "$bundle"
printf 'Bundle written to %s\n' "$bundle" >&2
exit "$rc"
