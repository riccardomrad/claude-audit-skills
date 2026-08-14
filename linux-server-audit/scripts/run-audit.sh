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

# The profile is the only source of the target. Reading it here, once, is what
# keeps the collector from ever running against a host nobody declared.
if [ ! -f "$PROFILE_PATH" ]; then
  stop "no audit profile found at $PROFILE_PATH" \
       "Copy profile.example.conf there, or point AUDIT_PROFILE at your own file," \
       "and fill in SSH_HOST, SSH_USER and ALLOWED_DOMAINS before running again."
fi
# shellcheck disable=SC1090
. "$PROFILE_PATH"

SSH_HOST="${SSH_HOST:-}"
SSH_PORT="${SSH_PORT:-22}"
SSH_USER="${SSH_USER:-}"
ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./audit-output}"

# An empty domain list means the profile was copied and never filled in. Better
# to stop here than to audit whatever happens to be in the other fields.
if [ -z "$(printf '%s' "$ALLOWED_DOMAINS" | tr -d '[:space:]')" ]; then
  stop "ALLOWED_DOMAINS is empty in $PROFILE_PATH" \
       "List the domains you own, space separated, before running an audit."
fi
if [ -z "$SSH_HOST" ] || [ -z "$SSH_USER" ]; then
  stop "SSH_HOST or SSH_USER is missing in $PROFILE_PATH" \
       "Both are required: there is no default host."
fi
if profile_is_example "$SSH_HOST" "$ALLOWED_DOMAINS"; then
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
  printf 'allowed domains: %s\n' "$ALLOWED_DOMAINS"
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
