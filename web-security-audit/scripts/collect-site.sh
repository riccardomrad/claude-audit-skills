#!/usr/bin/env bash
# =============================================================================
# web-security-audit: READ-ONLY collection against one web property you own.
#
# It makes read requests only (GET, HEAD, OPTIONS). No payloads, no login
# attempts, no data sent, no writes, no fuzzing, no bursts: there is a pause
# between requests. It reads what the site answers to anybody.
#
# It refuses any host that is not in the domain list of the audit profile: a
# checking tool pointed at somebody else's site by mistake is not a technical
# error, it is a legal problem. The name is normalised first (scheme,
# credentials, path, query, fragment, port, trailing dot, capitals) and only
# then compared with the list, so it cannot be tricked with forms such as
# evil.example/?x=.yourdomain.com, and YOURDOMAIN.COM is not refused.
#
# It downloads only pages and scripts hosted on the audited host: whatever the
# page loads from third parties is listed, never requested. That holds for
# redirects too: the chain is walked one hop at a time and stops, reporting the
# address, as soon as a hop points at a host nobody declared. Extra paths given
# on the command line go through their own check first, because a path is glued
# onto the address and an argument written as @other.example/x would move the
# request to another site entirely.
#
# Secrets found inside pages are shown MASKED (first characters plus length):
# the point is knowing they are there, not carrying them around.
#
# Usage:
#   bash collect-site.sh <host> [extra-path ...]      collection to stdout
#
# Environment variables:
#   AUDIT_PAUSE=0.4          seconds between one request and the next
#   AUDIT_FUNCTIONS_ONLY=1   load the functions only (used by the test suite);
#                            makes no request at all
# =============================================================================
set -u
export LC_ALL=C

# =============================================================================
# FUNCTIONS
# Kept separate from the body so they can be tested without touching the
# network:  AUDIT_FUNCTIONS_ONLY=1 . collect-site.sh
# The tests live in ../tests/test-web-security-audit.sh
# =============================================================================

# Reduces any hand written form to the hostname alone, lowercased.
normalize_host() {
  local h="$1"
  h="${h#*://}"        # scheme (http://, https://, ftp://...)
  h="${h%%[/?#]*}"     # path, query (?), fragment (#)
  h="${h##*@}"         # any user:password@ credentials
  h="${h%%:*}"         # port
  h="${h%.}"           # trailing dot of the absolute DNS form
  printf '%s' "$h" | tr 'A-Z' 'a-z'
}

# True only for the domains declared in the profile and their subdomains. The
# incoming host must already be normalised: if it holds characters that cannot
# appear in a hostname it is refused anyway, as a safety net against odd forms.
host_allowed() {   # <normalised host> <space separated domain list>
  case "$1" in
    ''|.*|*..*|*[!a-z0-9.-]*) return 1 ;;
  esac
  local d
  for d in $2; do
    d="$(printf '%s' "$d" | tr 'A-Z' 'a-z')"
    [ -n "$d" ] || continue
    case "$1" in
      "$d"|*."$d") return 0 ;;
    esac
  done
  return 1
}

# Prints the cleaned host and returns 0 only when it is one of yours.
target_valid() {   # <raw target> <space separated domain list>
  local h; h="$(normalize_host "$1")"
  printf '%s' "$h"
  host_allowed "$h" "$2"
}

# An extra path given on the command line is glued straight onto
# https://<host>, so it never passes through the target check the host went
# through. curl reads everything before an @ as credentials: @other.example/x
# turns the audited host into a username and the request lands on somebody
# else's site. Same story for a whole URL, or for // which starts a host and not
# a path. So an extra argument is a plain path or it is refused, and nothing is
# requested at all.
extra_path_valid() {   # <extra path>
  case "$1" in
    //*) return 1 ;;
    /*)  ;;
    *)   return 1 ;;
  esac
  case "$1" in
    *@*|*://*|*[[:space:]]*) return 1 ;;
  esac
  return 0
}

# --- redirects ----------------------------------------------------------------
# The home page has to be followed through its redirects, otherwise you judge
# the headers of an intermediate response instead of the real ones. But curl's
# own follow switch obeys the site, not the profile: one Location header and the
# next request goes to a host nobody declared. That is the single promise this
# tool cannot break, so the chain is walked one hop at a time and every hop is
# put through the same domain check as the target on the command line.

# The address a Location header points at, made absolute against the page it
# came from. Returns 1 when there is nothing to follow.
# A relative form without a leading slash is resolved against the root rather
# than the current directory: the pages this walks are the entry points of a
# site, which live at the root, and guessing a directory would invent an address
# nobody sent.
redirect_target() {   # <headers block> <current url>
  local loc
  loc="$(printf '%s\n' "$1" | tr -d '\r' | grep -Ei '^location:[[:space:]]*' \
         | head -1 | sed -E 's/^[Ll][Oo][Cc][Aa][Tt][Ii][Oo][Nn]:[[:space:]]*//')"
  [ -n "$loc" ] || return 1
  case "$loc" in
    http://*|https://*) printf '%s' "$loc" ;;
    //*)                printf 'https:%s' "$loc" ;;
    /*)                 printf 'https://%s%s' "$(normalize_host "$2")" "$loc" ;;
    *)                  printf 'https://%s/%s' "$(normalize_host "$2")" "$loc" ;;
  esac
}

# Walks the chain and prints it. Leaves the last address actually requested in
# FOLLOW_URL, the headers it answered with in FOLLOW_HEADERS, and sets
# FOLLOW_LEFT_SCOPE to 1 when a hop pointed outside the declared domains, which
# is reported and NOT requested. The fetcher is a parameter so the chain can be
# exercised without a network: a redirect walker nobody can test offline is a
# redirect walker nobody tests.
follow_chain() {   # <fetcher> <starting url> <domain list> [max hops]
  local fetch="$1" url="$2" domains="$3" max="${4:-5}" hops=0 hdr rc next h
  FOLLOW_URL="$url"; FOLLOW_HEADERS=''; FOLLOW_RC=0; FOLLOW_LEFT_SCOPE=0
  while : ; do
    hdr="$("$fetch" "$url")"; rc=$?
    FOLLOW_URL="$url"; FOLLOW_HEADERS="$hdr"; FOLLOW_RC="$rc"
    printf '[hop %s] %s\n' "$((hops + 1))" "$url"
    printf '%s\n' "$hdr" | tr -d '\r' | grep -Ei '^(HTTP/|location:|server:)' | head -6
    [ "$rc" -eq 0 ] || return 0
    next="$(redirect_target "$hdr" "$url")" || return 0
    hops=$((hops + 1))
    if [ "$hops" -ge "$max" ]; then
      printf 'STOPPED: more than %s redirects in a row, the chain was not followed further\n' "$max"
      return 0
    fi
    h="$(normalize_host "$next")"
    if ! host_allowed "$h" "$domains"; then
      FOLLOW_LEFT_SCOPE=1
      printf '[the chain leaves the audited domain] %s\n' "$next"
      printf 'STOPPED HERE: %s is not one of your declared domains, so it was NOT requested.\n' "$h"
      return 0
    fi
    url="$next"
  done
}

# Pause between one request and the next: an audit must not look like a scan.
# The tests set it to zero.
pause() { sleep "${AUDIT_PAUSE:-0.4}" 2>/dev/null || true; }

# The address every later request must start from: the one the visitor actually
# lands on, not the one that was typed. A site that answers on the bare domain
# and serves on www redirects every single path, so asking the typed address
# back returns 301 to everything: the directory sweep would call directories
# closed without having looked at them, and an exposed source control directory
# would never be seen at all. If the chain never resolved, fall back to the
# typed address, which is still better than asking nothing.
site_base_from() {   # <resolved url> <target host>
  local u="${1:-}"
  [ -n "$u" ] || u="https://$2/"
  printf '%s' "${u%/}"
}

# --- DNS over HTTPS -----------------------------------------------------------
# Without the status field there is no way to tell "the name does not exist"
# from "I did not understand the answer": two very different situations.
dns_status() {
  local n
  n="$(printf '%s' "$1" | tr ',' '\n' \
       | grep -Eo '"Status"[[:space:]]*:[[:space:]]*[0-9]+' \
       | grep -Eo '[0-9]+$' | head -1)"
  case "${n:-}" in
    0)  printf 'NOERROR (the name exists)' ;;
    2)  printf 'SERVFAIL (the authoritative server failed)' ;;
    3)  printf 'NXDOMAIN (the name does not exist)' ;;
    '') printf 'STATUS MISSING: DNS answer could not be read' ;;
    *)  printf 'DNS code %s' "$n" ;;
  esac
}

# A CNAME pointing at a service that is no longer yours is how a subdomain ends
# up in somebody else's hands, so the target is resolved in turn.
dns_cname_target() {
  printf '%s' "$1" | tr ',' '\n' \
    | grep -Eo '"data"[[:space:]]*:[[:space:]]*"[A-Za-z0-9._-]+\."' \
    | head -1 | sed -E 's/.*"([A-Za-z0-9._-]+)\."$/\1/'
}

dns_data() {
  printf '%s' "$1" | tr ',' '\n' | grep -Ei '"(name|data|TTL)"' | head -8
}

# --- scripts linked from the page --------------------------------------------
# src is written with either kind of quote, and a name is a script only when it
# ends in .js. Matching ".js" anywhere inside the name took data.json for a
# script and downloaded it, while every bundle written with single quotes was
# skipped: those are exactly the files the secret search needs, so the search
# quietly ran on less than it claimed.
extract_script_srcs() {   # <html file>
  grep -Eoi "src=(\"[^\"]+\"|'[^']+')" "$1" 2>/dev/null \
    | sed -E "s/^[Ss][Rr][Cc]=[\"']//; s/[\"']\$//" \
    | grep -E '\.js([?#][^[:space:]]*)?$'
}

# Prints the address to download ONLY if it lives on the host being audited. A
# script hosted by a third party is reported and left alone: fetching it would
# be a request to somebody else's site.
script_url_to_fetch() {
  local js="$1" host="$2" url
  case "$js" in
    http://*|https://*) url="$js" ;;
    //*)                url="https:$js" ;;
    /*)                 printf 'https://%s%s' "$host" "$js"; return 0 ;;
    *)                  printf 'https://%s/%s' "$host" "$js"; return 0 ;;
  esac
  [ "$(normalize_host "$url")" = "$host" ] && printf '%s' "$url"
  return 0
}

# --- verdicts ----------------------------------------------------------------
# Shared rule: if the check did not run, the bundle says NOT VERIFIED. A failed
# check that prints "fine" is worse than a missing check.

# Cookies are read from the answer the site gave. When no answer arrived there
# is nothing to read, and saying "the home page sets no cookie" would be an
# affirmative statement about a request that never completed.
cookie_lines() {   # <headers text>
  if [ -z "$1" ]; then
    printf 'NOT VERIFIED: no answer was received, so the cookies could not be read'
    return 0
  fi
  local c
  c="$(printf '%s\n' "$1" | tr -d '\r' | grep -i '^set-cookie:' | cut -c1-200)"
  if [ -n "$c" ]; then printf '%s' "$c"; else printf 'the home page sets no cookie'; fi
}

verdict_path() {   # <code> <size> <type> <home page size>
  local code="$1" size="$2" ctype="$3" home_size="$4" similar=0 ratio
  [ "$code" = 200 ] || return 0
  # Telling a real file apart from a site page dressed as one is a size
  # comparison, and without the home page there is nothing to compare against.
  # Compared with zero every 200 looks unusual, and the section fills with
  # findings that are only the missing measurement talking.
  if [ "${home_size:-0}" -le 0 ] 2>/dev/null; then
    printf '  (no reference: the home page was not read, so a disguised not-found cannot be told apart)'
    return 0
  fi
  case "$ctype" in
    text/html*)
      if [ "$home_size" -gt 0 ] 2>/dev/null; then
        ratio=$(( size * 100 / home_size ))
        [ "$ratio" -ge 80 ] && [ "$ratio" -le 125 ] && similar=1
      fi
      ;;
  esac
  if [ "$similar" = 1 ]; then
    printf '  (site page: probably a disguised not-found)'
  else
    printf '  <== REAL ANSWER, not the home page: look at this'
  fi
}

verdict_listing() {   # <rc> <body>
  if [ "$1" -ne 0 ] || [ -z "$2" ]; then
    printf 'NOT VERIFIED (no answer from the directory)'
    return 0
  fi
  case "$2" in
    *"Index of"*|*"<title>Directory listing"*) printf 'OPEN' ;;
    *) printf 'closed' ;;
  esac
}

# A request that succeeded but printed nothing leaves an empty section, and an
# empty section reads as "looked at, nothing to report". Whatever did not run
# has to say it did not run.
verdict_or_not_verified() {   # <rc> <text collected> <what was being asked>
  if [ "$1" -ne 0 ] || [ -z "$(printf '%s' "$2" | tr -d '[:space:]')" ]; then
    printf 'NOT VERIFIED: %s\n' "$3"
  else
    printf '%s\n' "$2"
  fi
}

# curl prints the fields of -w only when the request went through. When it
# failed, its error text used to be read as the code, the size and the content
# type, and the path came out with no verdict at all: it reads exactly like a
# path that was checked and found harmless.
path_line() {   # <rc> <the line curl -w printed> <home page size>
  local code size ctype
  if [ "$1" -ne 0 ] || [ -z "$2" ]; then
    printf 'NOT VERIFIED (the request failed: no code, no size, nothing to judge)'
    return 0
  fi
  read -r code size ctype <<< "$2"
  printf '%s%s' "$2" "$(verdict_path "${code:-0}" "${size:-0}" "${ctype:-}" "$3")"
}

# The origin the cross-origin question is asked with. The verdict compares the
# answer against this exact value, so the two have to come from one place.
AUDIT_CORS_PROBE_ORIGIN="${AUDIT_CORS_PROBE_ORIGIN:-https://foreign-origin-probe.invalid}"

# Allowing ONE fixed origin that is not the one we asked with is how a normal
# site is configured: it answered everybody the same way and told us nothing.
# The two answers that matter are the star, which lets any site read the reply,
# and our own probe origin handed back, which means the site echoes whatever
# origin it is given and so trusts all of them. Calling the healthy case a
# finding buries the two real ones in noise nobody reads twice.
verdict_cors() {   # <rc> <headers> [the origin the request was made with]
  local h="$2" probe="${3:-$AUDIT_CORS_PROBE_ORIGIN}" lines value lower plower
  if [ "$1" -ne 0 ]; then
    printf 'NOT VERIFIED: the request with a foreign origin did not succeed'
    return 0
  fi
  lines="$(printf '%s\n' "$h" | tr -d '\r' | grep -Ei '^access-control-')"
  if [ -z "$lines" ]; then
    printf 'no access-control line: the site grants nothing to foreign origins'
    return 0
  fi
  printf '%s\n' "$lines"
  value="$(printf '%s\n' "$lines" | grep -Ei '^access-control-allow-origin:' | head -1 \
           | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '[:space:]')"
  lower="$(printf '%s' "$value" | tr 'A-Z' 'a-z')"
  plower="$(printf '%s' "$probe" | tr 'A-Z' 'a-z')"
  if [ "$value" = '*' ]; then
    printf 'FINDING: the site shares its answers with ANY site'
  elif [ -n "$lower" ] && [ "$lower" = "$plower" ]; then
    printf 'FINDING: the site handed back the very origin it was asked with, so it accepts any origin'
  elif [ -n "$value" ]; then
    printf 'one fixed origin allowed (%s), and not the one this check asked with: usual configuration, read it by hand\n' "$value"
    return 0
  else
    printf 'access-control lines without an allow-origin: read them by hand\n'
    return 0
  fi
  printf '%s' "$lines" | grep -qi '^access-control-allow-credentials:[[:space:]]*true' \
    && printf ' AND allows credentials (any site can read the data of a logged in user)'
  printf '\n'
}

# --- reading a header dump ----------------------------------------------------
# A dump can hold more than one response. Taking the last line that matches a
# header name picks up whatever an intermediate hop sent: a redirect carrying a
# content security policy would make the real page look protected when it is
# not. Only the block after the last status line describes what the visitor
# actually receives.
last_header_block() {   # <headers dump>
  printf '%s\n' "$1" | tr -d '\r' \
    | awk '/^HTTP\//{ buf=""; next } { buf = buf $0 "\n" } END { printf "%s", buf }'
}

header_value() {   # <header name> <headers dump>
  last_header_block "$2" | grep -Ei "^$1:" | head -1 | cut -c1-300
}

verdict_tls() {   # <rc> <openssl output>
  if [ "$1" -ne 0 ] || [ -z "$2" ]; then
    printf 'NOT VERIFIED: openssl missing or handshake failed'
    return 0
  fi
  printf '%s' "$2"
}

# --- secrets inside pages -----------------------------------------------------
# Private address ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x. Written badly
# (the classic being 192.168 without the remaining octets) the pattern never
# matches anything and the audit looks clean.
private_ip_regex() {
  printf '%s' '(10\.[0-9]{1,3}|192\.168|172\.(1[6-9]|2[0-9]|3[01]))\.[0-9]{1,3}\.[0-9]{1,3}'
}

mask_value() { awk '{printf "  %s...(%d characters)\n", substr($0,1,12), length($0)}'; }

# Minified files and modern script bundles often contain bytes that make grep
# decide "this is binary, skipping": with -a it reads them anyway, otherwise the
# secret search switches itself off in silence.
find_secrets() {   # <file> [extra pattern ...]
  local f="$1"; shift
  local pat out
  for pat in 'eyJ[A-Za-z0-9_-]{20,}' \
             'sk-[A-Za-z0-9]{16,}' \
             'AKIA[0-9A-Z]{16}' \
             'gh[pousr]_[A-Za-z0-9]{20,}' \
             '(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|bearer)["'"'"'[:space:]:=]{1,4}[A-Za-z0-9._\-]{12,}' \
             '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
             "$(private_ip_regex)" \
             '\.env' \
             "$@" ; do
    [ -n "$pat" ] || continue
    # -e and -- keep a pattern that begins with a dash from being read as an
    # option: the extra patterns come from the profile, and a profile is edited
    # by hand.
    out="$(grep -Eiao -e "$pat" -- "$f" 2>/dev/null | sort -u | head -5 | mask_value)"
    [ -n "$out" ] && printf 'FOUND with the pattern: %s\n%s\n' "$pat" "$out"
  done
  return 0
}

if [ "${AUDIT_FUNCTIONS_ONLY:-0}" = 1 ]; then
  return 0 2>/dev/null || exit 0
fi

# =============================================================================
# BODY
# =============================================================================

PROFILE_PATH="${AUDIT_PROFILE:-$HOME/.config/audit-skills/profile.conf}"

stop() {   # stop <message ...>
  printf 'STOP: %s\n' "$1" >&2
  shift
  for line in "$@"; do printf '%s\n' "$line" >&2; done
  exit 3
}

# The example profile is a form, not a profile. Copied as it stands it lists
# domains reserved by RFC 2606 (example.com, example.org, example.net) and a
# documentation address reserved by RFC 5737 (203.0.113.x): nobody owns them, so
# requests aimed at them go to somebody else's placeholder. The skill promises
# in writing to refuse a profile that was never filled in, so it has to be able
# to recognise one.
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

# The profile is the only source of the allowed domains. Reading it here, once,
# is what keeps the collector from ever requesting anything from a host nobody
# declared.
if [ ! -f "$PROFILE_PATH" ]; then
  stop "no audit profile found at $PROFILE_PATH" \
       "Copy profile.example.conf there, or point AUDIT_PROFILE at your own file," \
       "and list your domains in ALLOWED_DOMAINS before running again."
fi
# shellcheck disable=SC1090
. "$PROFILE_PATH"

ALLOWED_DOMAINS="${ALLOWED_DOMAINS:-}"
OUTPUT_DIR="${OUTPUT_DIR:-./audit-output}"

# An empty domain list means the profile was copied and never filled in. Better
# to stop here than to send requests to whatever was typed on the command line.
if [ -z "$(printf '%s' "$ALLOWED_DOMAINS" | tr -d '[:space:]')" ]; then
  stop "ALLOWED_DOMAINS is empty in $PROFILE_PATH" \
       "List the domains you own, space separated, before auditing anything."
fi
if profile_is_example "$ALLOWED_DOMAINS"; then
  stop "the profile was never filled in: $PROFILE_PATH still holds example values" \
       "example.com, example.org, example.net and 203.0.113.x are reserved names" \
       "from the documentation: none of them is yours." \
       "List your own domains before auditing anything."
fi

mode=collect
case "${1:-}" in
  --check-target) mode=check; shift ;;
  --save)         mode=save;  shift ;;
esac

raw="${1:-}"
if [ -z "$raw" ]; then
  echo "A host is required. Example: bash collect-site.sh www.example.com" >&2
  exit 1
fi
shift || true

# Before anything is asked of anybody: every extra path has to be a path. This
# comes first on purpose, so a poisoned argument stops the run while it still
# has made no request at all.
for extra in "$@"; do
  if ! extra_path_valid "$extra"; then
    echo "REJECTED extra path: $extra" >&2
    echo "An extra path has to start with a single / and stay a path: no @, no ://," >&2
    echo "no // at the start, no spaces. Written any other way it can send the" >&2
    echo "request to a site that is not yours, so nothing at all was requested." >&2
    exit 2
  fi
done

host="$(normalize_host "$raw")"
if ! host_allowed "$host" "$ALLOWED_DOMAINS"; then
  echo "REJECTED: $raw (read as host: ${host:-empty}) is out of scope." >&2
  echo "This tool only works on the domains declared in ALLOWED_DOMAINS." >&2
  exit 2
fi

if [ "$mode" = check ]; then
  printf 'IN SCOPE: %s (matched against: %s)\n' "$host" "$ALLOWED_DOMAINS"
  printf 'Nothing was requested: this is a target check only.\n'
  exit 0
fi

# The bundle name carries the hour and the minute, not the day alone, and the
# collection lands beside it under a .part name until it is whole. With the day
# alone a second run shared the name of the first, and the shell truncated that
# file the moment it opened the redirection: a run that failed to start
# destroyed the collection of the morning, which is the copy you would want to
# compare against. Whatever goes wrong now, a file called bundle-site-... is a
# complete one.
bundle=''
partial=''
if [ "$mode" = save ]; then
  mkdir -p "$OUTPUT_DIR/raw"
  bundle="$OUTPUT_DIR/raw/bundle-site-$host-$(date +%Y-%m-%d-%H%M).txt"
  partial="$bundle.part"
  exec > "$partial"
fi

# Every download goes under this directory. If mktemp fails the variable stays
# empty, and every -o and -D below becomes an absolute path: the collection
# would be written into the root of the disk, which is the opposite of the
# promise that this tool writes nothing you did not ask for.
tmp="$(mktemp -d 2>/dev/null)" || tmp=''
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  stop "could not create the temporary directory for the downloads" \
       "Without it the pages would be written into the root of the disk, and this" \
       "tool writes nothing you did not ask for. Check TMPDIR and the free space," \
       "then run it again. Nothing was requested."
fi
trap 'rm -rf "$tmp"' EXIT

# -q ignores the operator's own curl configuration file, and the protocol list
# refuses anything that is not plain web traffic. Neither is about distrusting
# the operator: a single "location" line left in that config file switches
# redirect following on for every request ever made, which would quietly undo
# the one promise this tool makes, that it never asks a host nobody declared.
# A promise that a forgotten config line can cancel is not a promise.
C=(curl -sS -q --proto '=http,https' --max-time 20 --retry 0 -A 'internal-security-audit (read only)')

# The fetcher handed to follow_chain: a normal read of one address, headers on
# stdout, body thrown into a file. Not -o /dev/null: under MSYS on Windows that
# reports a zero size and makes a page that is there look empty.
curl_headers() { "${C[@]}" -D - -o "$tmp/chain-body.bin" "$1" 2>&1; }

sec() { printf '\n\n##### SECTION: %s\n' "$1"; }

printf '##### WEB SECURITY AUDIT: READ-ONLY COLLECTION\n'
printf 'host: %s (written as: %s)\n' "$host" "$raw"
printf 'collected on: %s\n' "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
printf 'pause between requests: %s seconds\n' "${AUDIT_PAUSE:-0.4}"
printf 'collector version: 5\n'

sec "NAMES AND ADDRESSES (DNS)"
# Over DNS-over-HTTPS: it does not depend on dig or nslookup, which behave
# differently on Windows.
for t in A AAAA CNAME; do
  answer="$("${C[@]}" -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=$host&type=$t" 2>&1)"
  printf '\n[%s] status: %s\n' "$t" "$(dns_status "$answer")"
  dns_data "$answer"
  if [ "$t" = CNAME ]; then
    target="$(dns_cname_target "$answer")"
    if [ -n "$target" ]; then
      printf '[the CNAME points at] %s\n' "$target"
      pause
      answerb="$("${C[@]}" -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=$target&type=A" 2>&1)"
      printf '[status of the CNAME target] %s\n' "$(dns_status "$answerb")"
      dns_data "$answerb"
      printf '(a target with no address means a name pointing at nothing: find out who owns it)\n'
    fi
  fi
  pause
done

sec "FROM CLEARTEXT TO ENCRYPTED"
# A site still answering in cleartext, or not redirecting, is a site where
# somebody on the same network can read and change the pages.
follow_chain curl_headers "http://$host/" "$ALLOWED_DOMAINS" > "$tmp/chain-http.txt"
verdict_or_not_verified "$FOLLOW_RC" "$(cat "$tmp/chain-http.txt" 2>/dev/null)" \
  'the cleartext version gave no answer at all, so the move to encrypted could not be checked'
printf '[final destination reached] %s\n' "$FOLLOW_URL"
pause

sec "RESPONSE HEADERS (HTTPS)"
# The chain walked here is the one the visitor walks, and the answer at the end
# of it is the page they get: headers and body are kept from that last hop
# instead of asking for the same page a second time.
follow_chain curl_headers "https://$host/" "$ALLOWED_DOMAINS" > "$tmp/chain-https.txt"
cat "$tmp/chain-https.txt"
home_url="$FOLLOW_URL"
site_base="$(site_base_from "$home_url" "$host")"
printf '[every later request starts from] %s\n' "$site_base"
: > "$tmp/headers.txt"
: > "$tmp/home.html"
if [ "$FOLLOW_RC" -eq 0 ]; then
  printf '%s\n' "$FOLLOW_HEADERS" > "$tmp/headers.txt"
  cp "$tmp/chain-body.bin" "$tmp/home.html" 2>/dev/null || : > "$tmp/home.html"
fi
head -50 "$tmp/headers.txt" 2>/dev/null
printf '\n[home page size] %s bytes\n' "$(wc -c < "$tmp/home.html" 2>/dev/null || echo 0)"
pause

sec "SECURITY HEADERS: PRESENT OR NOT"
if [ ! -s "$tmp/headers.txt" ]; then
  echo 'NOT VERIFIED: no headers received (the site did not answer)'
else
  dump="$(cat "$tmp/headers.txt")"
  for h in content-security-policy x-frame-options referrer-policy \
           cross-origin-opener-policy cross-origin-resource-policy; do
    v="$(header_value "$h" "$dump")"
    if [ -n "$v" ]; then printf 'PRESENT  %s\n' "$v"; else printf 'ABSENT   %s\n' "$h"; fi
  done
fi

sec "WHAT THE SERVER REVEALS ABOUT ITSELF"
if [ ! -s "$tmp/headers.txt" ]; then
  echo 'NOT VERIFIED: no answer was received, so there is nothing to read here'
else
  grep -Ei '^(server|x-powered-by|x-aspnet|x-generator|via|x-served-by|x-cache|cf-ray|cf-cache-status|x-vercel|x-nginx):' \
    "$tmp/headers.txt" 2>/dev/null | head -12
  grep -Eio '<meta[^>]+generator[^>]*>' "$tmp/home.html" 2>/dev/null | head -3
fi

sec "COOKIES AND THEIR ATTRIBUTES"
cookie_lines "$(cat "$tmp/headers.txt" 2>/dev/null)"
echo

sec "TLS CERTIFICATE"
tls_out="$(echo | openssl s_client -connect "$host:443" -servername "$host" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null)"
tls_rc=$?
verdict_tls "$tls_rc" "$tls_out" | head -20
echo
pause

sec "HTTP METHODS ACCEPTED"
"${C[@]}" -I -X OPTIONS "$site_base/" > "$tmp/options.txt" 2>/dev/null
options_rc=$?
verdict_or_not_verified "$options_rc" \
  "$(grep -Ei '^(HTTP/|allow:|access-control-allow-methods:)' "$tmp/options.txt" 2>/dev/null | head -8)" \
  'the OPTIONS request got no answer, so the accepted methods are unknown'
pause

sec "CROSS-ORIGIN SHARING"
# The site is asked how it would treat a page hosted somewhere else. If it hands
# that same origin back, it trusts any origin; with credentials on top, any site
# can read the data of a logged in user.
cors_out="$("${C[@]}" -I -H "Origin: $AUDIT_CORS_PROBE_ORIGIN" "$site_base/" 2>/dev/null)"
cors_rc=$?
verdict_cors "$cors_rc" "$cors_out" "$AUDIT_CORS_PROBE_ORIGIN"
pause

sec "PATHS THAT SHOULD NOT EXIST"
# Read requests only. The content of sensitive files is NOT shown: the response
# code and the size are enough to tell whether they are exposed.
home_size="$(wc -c < "$tmp/home.html" 2>/dev/null || echo 0)"
printf 'reference: the home page weighs %s bytes (a 200 of similar weight is almost always a disguised not-found)\n\n' "$home_size"
paths='/.git/HEAD /.git/config /.env /.env.local /.env.bak /config.json /wp-config.php
/backup.zip /backup.tar.gz /dump.sql /db.sql /database.sql /.htaccess
/package.json /composer.json /yarn.lock /.npmrc /docker-compose.yml /Dockerfile
/server-status /phpinfo.php /info.php /robots.txt /sitemap.xml
/admin /administrator /login /wp-login.php /api /api/v1 /graphql /debug
/dashboard /account /profile /settings /admin/index.php
/assets/ /uploads/ /storage/logs/laravel.log'
for p in $paths "$@"; do
  r="$("${C[@]}" -o "$tmp/out.bin" -w '%{http_code} %{size_download} %{content_type}' \
        --max-time 12 "$site_base$p" 2>/dev/null)"
  rc=$?
  printf '%-34s %s\n' "$p" "$(path_line "$rc" "$r" "$home_size")"
  pause
done

# The file below is printed only when it really is a short text file: if the
# site answers with the home page instead, printing it would fill the bundle
# with whole pages that say nothing.
show_if_text() {  # show_if_text <path> <label>
  local r rc code size ctype
  r="$("${C[@]}" -o "$tmp/f.bin" -w '%{http_code} %{size_download} %{content_type}' --max-time 12 "$site_base$1" 2>/dev/null)"
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$r" ]; then
    printf '\n[%s] NOT VERIFIED (the request failed)\n' "$2"
    pause
    return 0
  fi
  read -r code size ctype <<< "$r"
  printf '\n[%s] %s\n' "$2" "$r"
  case "$code:$ctype" in
    200:text/plain*|200:text/xml*|200:application/xml*)
      if [ "$size" -lt 4000 ] 2>/dev/null; then head -c 1200 "$tmp/f.bin"; echo; fi
      ;;
    *) echo '(not a short text file: content not shown)' ;;
  esac
  pause
}
show_if_text /robots.txt 'robots.txt'

sec "OPEN DIRECTORY LISTINGS"
for d in /assets/ /static/ /img/ /images/ /js/ /css/ /files/ /uploads/; do
  # The code is read from curl, not from the pipe: after a `| head` the exit
  # status is the one of head, which always succeeds, so a failed request would
  # pass for a closed directory.
  code="$("${C[@]}" -o "$tmp/dir.bin" -w '%{http_code}' "$site_base$d" 2>/dev/null)"
  rc=$?
  # The whole body, not the first bytes: a listing whose banner, header or
  # navigation comes first was being reported as a closed directory.
  body="$(cat "$tmp/dir.bin" 2>/dev/null)"
  if [ "$rc" -ne 0 ]; then
    result="$(verdict_listing 1 '')"
  elif [ "${code:-0}" != 200 ]; then
    result="closed (code ${code:-none})"
  else
    result="$(verdict_listing 0 "$body")"
  fi
  printf '%-40s %s\n' "$result" "$d"
  pause
done

sec "SECRETS AND INTERNAL ADDRESSES INSIDE PAGES"
# The home page and the first scripts hosted ON THIS HOST are downloaded, and
# searched for what should not be in a public page. Third party scripts are
# listed only: fetching them would be a request to somebody else's site, which
# this tool never makes.
# Results are MASKED: first characters and length, never the value.
cp "$tmp/home.html" "$tmp/all.txt" 2>/dev/null || : > "$tmp/all.txt"
extract_script_srcs "$tmp/home.html" | head -6 > "$tmp/scripts.txt"
while read -r js; do
  [ -n "$js" ] || continue
  url="$(script_url_to_fetch "$js" "$host")"
  if [ -z "$url" ]; then
    printf '[third party script: listed, NOT downloaded] %s\n' "$js"
    continue
  fi
  printf '[script read] %s\n' "$url"
  "${C[@]}" "$url" 2>/dev/null >> "$tmp/all.txt"
  pause
done < "$tmp/scripts.txt"
echo
secrets="$(find_secrets "$tmp/all.txt" "${SSH_HOST:-}")"
if [ -n "$secrets" ]; then
  printf '%s\n' "$secrets"
else
  echo 'no recognisable secret in the pages that were read'
fi

sec "REDIRECT PARAMETERS IN THE PAGES"
# A parameter that decides where the user is sent is the brick session theft is
# built from: it is reported so it can be looked at by hand.
redirects="$(grep -Eiao '(\?|&)(url|next|redirect|redirect_uri|return|returnUrl|goto|dest|destination|continue|r)=[^"&<> ]{0,60}' \
  "$tmp/all.txt" 2>/dev/null | sort -u | head -15)"
if [ -n "$redirects" ]; then
  printf '%s\n' "$redirects"
else
  echo 'no redirect parameter visible in the pages that were read'
fi

sec "IS THE PANEL PROTECTED"
# For any exposed management interface the question is not whether the password
# is strong, it is whether the login screen is reachable by anybody. A barrier
# in front removes every automated attempt before it reaches the application.
# The chain and the headers are the ones already collected above: it is the same
# request, and asking for it twice would be a request more than the audit needs.
cat "$tmp/chain-https.txt"
grep -Ei '^(cf-|set-cookie:[[:space:]]*CF_)' "$tmp/headers.txt" 2>/dev/null | head -10
printf '[final destination] %s\n' "$home_url"

printf '\n\n##### END OF COLLECTION\n'

# A truncated bundle read as a complete one turns a request that never got an
# answer into a list of imaginary findings, so the file takes its final name
# only once the marker it should end with is there.
if [ "$mode" = save ]; then
  if tail -3 "$partial" 2>/dev/null | grep -q 'END OF COLLECTION'; then
    mv "$partial" "$bundle"
    printf 'Bundle written to %s\n' "$bundle" >&2
  else
    printf 'WARNING: the collection does not end with the completion marker.\n' >&2
    printf 'It was cut short and kept aside as %s, without becoming a bundle.\n' "$partial" >&2
    printf 'Run it again before analysing anything.\n' >&2
    exit 4
  fi
fi
