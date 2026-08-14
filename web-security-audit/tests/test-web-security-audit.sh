#!/usr/bin/env bash
# =============================================================================
# Tests for web-security-audit.
#
# Touches NO network: it loads the collector functions only
# (AUDIT_FUNCTIONS_ONLY=1) and exercises them against fake data written here,
# plus the target check, which resolves nothing and requests nothing.
# Every example uses reserved documentation names (example.com, example.org,
# 203.0.113.x), never a real site.
#
#   bash tests/test-web-security-audit.sh
#
# Exits 0 when every test passes, 1 when at least one fails.
# =============================================================================
set -u
export LC_ALL=C

HERE="$(cd "$(dirname "$0")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
COLLECT="$SKILL/scripts/collect-site.sh"
SKILL_MD="$SKILL/SKILL.md"
CHECKS="$SKILL/references/checks.md"
TEMPLATE="$SKILL/references/report-template.md"
TARGETS="$SKILL/references/targets.md"
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

# --- loading the functions ---------------------------------------------------
# The guard has to exist BEFORE sourcing: without it, sourcing the collector
# would start real requests from this machine.
if ! grep -q 'AUDIT_FUNCTIONS_ONLY' "$COLLECT" 2>/dev/null; then
  printf 'KO    guard AUDIT_FUNCTIONS_ONLY missing in %s: sourcing nothing.\n' "$COLLECT"
  exit 1
fi
# shellcheck disable=SC1090
AUDIT_FUNCTIONS_ONLY=1 . "$COLLECT" || { echo "KO    cannot load $COLLECT"; exit 1; }

t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT

# The collector is only ever called in target-check mode and with a clean
# environment, so a test can never send a request anywhere.
check_target() {   # check_target <profile path> <target> [extra path ...]
  local profile="$1"; shift
  env -u ALLOWED_DOMAINS -u OUTPUT_DIR -u SSH_HOST \
      AUDIT_PROFILE="$profile" bash "$COLLECT" --check-target "$@" 2>&1
}
check_target_rc() {   # check_target_rc <profile path> <target> [extra path ...]
  check_target "$@" >/dev/null 2>&1; printf '%s' "$?"
}

# A domain list that is really filled in. example.com and example.org are
# reserved names nobody owns (RFC 2606): they are what the example profile
# carries, and a profile still carrying them was never filled in, so the
# collector refuses it. The pure filter functions below are handed their domain
# list as an argument and keep using the reserved names, which is what those
# names are for.
printf 'ALLOWED_DOMAINS="mysite.test othersite.test"\nOUTPUT_DIR="%s/out"\n' "$t" > "$t/good.conf"
printf 'ALLOWED_DOMAINS=""\nOUTPUT_DIR="%s/out"\n' "$t" > "$t/empty-domains.conf"

echo
echo '=== PROFILE: nothing runs against an undeclared target ==='
out="$(check_target "$t/does-not-exist.conf" mysite.test)"
expect_nonzero 'missing profile: exit code is not zero' "$(check_target_rc "$t/does-not-exist.conf" mysite.test)"
contains 'missing profile: the message names the profile' 'no audit profile found' "$out"

out="$(check_target "$t/empty-domains.conf" mysite.test)"
expect_nonzero 'empty domain list: exit code is not zero' "$(check_target_rc "$t/empty-domains.conf" mysite.test)"
contains 'empty domain list: the message names ALLOWED_DOMAINS' 'ALLOWED_DOMAINS' "$out"

out="$(check_target "$t/good.conf" www.mysite.test)"
expect  'a configured domain is accepted'  0 "$(check_target_rc "$t/good.conf" www.mysite.test)"
contains 'the accepted target is echoed back' 'www.mysite.test' "$out"
out="$(check_target "$t/good.conf" www.notmine.test)"
expect  'a domain that is not configured is refused' 2 "$(check_target_rc "$t/good.conf" www.notmine.test)"
contains 'the refusal says the target is out of scope' 'out of scope' "$out"
expect  'the second configured domain is accepted too' 0 "$(check_target_rc "$t/good.conf" othersite.test)"
file_has 'the default profile path is the shared one' 'config/audit-skills/profile.conf' "$COLLECT"

echo
echo '=== TARGET FILTER: the forms that try to sneak past ==='
allowed='example.com example.org'
target_result() { if target_valid "$1" "$allowed" >/dev/null 2>&1; then echo accepted; else echo refused; fi; }
expect 'evil.example?x=.example.com is refused'      refused "$(target_result 'evil.example?x=.example.com')"
expect 'evil.example#.example.com is refused'        refused "$(target_result 'evil.example#.example.com')"
expect 'example.com@evil.example is refused'         refused "$(target_result 'example.com@evil.example')"
expect 'notexample.com is refused'                   refused "$(target_result 'notexample.com')"
expect 'evil.example/example.com is refused'         refused "$(target_result 'evil.example/example.com')"
expect 'an empty target is refused'                  refused "$(target_result '')"
expect 'EXAMPLE.COM is accepted'                     accepted "$(target_result 'EXAMPLE.COM')"
expect 'EXAMPLE.COM is lowercased'                   example.com "$(target_valid 'EXAMPLE.COM' "$allowed")"
expect 'example.com:443 is accepted'                 accepted "$(target_result 'example.com:443')"
expect 'example.com:443 loses the port'              example.com "$(target_valid 'example.com:443' "$allowed")"
expect 'example.com. (trailing dot) is accepted'     accepted "$(target_result 'example.com.')"
expect 'example.com. loses the trailing dot'         example.com "$(target_valid 'example.com.' "$allowed")"
expect 'a whole URL: the host is extracted'          app.example.com "$(target_valid 'https://app.example.com/page?x=1' "$allowed")"
expect 'an empty domain list accepts nothing'        refused "$(if target_valid 'example.com' '' >/dev/null 2>&1; then echo accepted; else echo refused; fi)"

echo
echo '=== SCRIPTS FOUND IN THE PAGES ==='
expect 'a script on a third party host is not downloaded' '' "$(script_url_to_fetch 'https://cdn.other.example/x.js' example.com)"
expect 'a protocol relative third party script is not downloaded' '' "$(script_url_to_fetch '//other.example/x.js' example.com)"
expect 'an absolute path script is downloaded'  'https://example.com/app.js' "$(script_url_to_fetch '/app.js' example.com)"
expect 'an absolute URL on our host is downloaded' 'https://example.com/a.js' "$(script_url_to_fetch 'https://example.com/a.js' example.com)"
expect 'a relative script without a slash'      'https://example.com/js/a.js' "$(script_url_to_fetch 'js/a.js' example.com)"

echo
echo '=== VERDICTS THAT MUST NOT REASSURE FOR NOTHING ==='
contains 'directory listing: failed request means not verified' 'NOT VERIFIED' "$(verdict_listing 1 '')"
expect  'directory listing: Index of means OPEN'   OPEN   "$(verdict_listing 0 '<html><h1>Index of /assets</h1>')"
expect  'directory listing: a normal page is closed' closed "$(verdict_listing 0 '<html><body>hello</body></html>')"
contains 'cross-origin: failed request means not verified' 'NOT VERIFIED' "$(verdict_cors 1 '')"
contains 'cross-origin: the probe origin echoed back is a finding' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://foreign-origin-probe.invalid
access-control-allow-credentials: true')"
contains 'cross-origin: credentials allowed is spelled out' 'credentials' \
  "$(verdict_cors 0 'access-control-allow-origin: https://foreign-origin-probe.invalid
access-control-allow-credentials: true')"
lacks   'cross-origin: a finding never says all is well' 'grants nothing' \
  "$(verdict_cors 0 'access-control-allow-origin: *')"
contains 'cross-origin: no header means nothing granted' 'grants nothing' "$(verdict_cors 0 '')"
# A site that allows ONE fixed origin, and not the one we probed with, is a
# healthy configuration: it answered the same way it answers everybody. Calling
# that a finding buries the two cases that are real (the star, and our own probe
# origin handed back) under noise nobody reads twice.
contains 'cross-origin: the star is a finding' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: *')"
contains 'cross-origin: an upper case header name is read too' 'FINDING' \
  "$(verdict_cors 0 'Access-Control-Allow-Origin: *')"
lacks   'cross-origin: one fixed foreign origin is not a finding' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://partner.example.org')"
contains 'cross-origin: and it is named as a fixed origin' 'one fixed origin' \
  "$(verdict_cors 0 'access-control-allow-origin: https://partner.example.org')"
lacks   'cross-origin: credentials on a fixed origin are not a finding either' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://partner.example.org
access-control-allow-credentials: true')"
contains 'cross-origin: our probe origin handed back is a finding' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://foreign-origin-probe.invalid')"
contains 'cross-origin: the probe origin is compared whatever its case' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: HTTPS://FOREIGN-ORIGIN-PROBE.INVALID')"
contains 'cross-origin: the origin actually probed with is the one compared' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://another-probe.invalid' 'https://another-probe.invalid')"
lacks   'cross-origin: and a different origin then is not' 'FINDING' \
  "$(verdict_cors 0 'access-control-allow-origin: https://foreign-origin-probe.invalid' 'https://another-probe.invalid')"
file_has 'the collector probes with the origin the verdict compares against' \
  'AUDIT_CORS_PROBE_ORIGIN' "$COLLECT"
contains 'TLS: failed handshake means not verified'  'NOT VERIFIED' "$(verdict_tls 1 '')"
contains 'TLS: empty output with rc 0 means not verified' 'NOT VERIFIED' "$(verdict_tls 0 '')"
contains 'TLS: a certificate that was read is shown' 'notAfter' "$(verdict_tls 0 'subject=CN=example.com
notAfter=Nov 12 00:00:00 2026 GMT')"
contains 'a path answering like the home page is flagged as a disguise' 'disguised' \
  "$(verdict_path 200 41000 'text/html' 40000)"
contains 'a small plain text answer is flagged as real' 'REAL ANSWER' \
  "$(verdict_path 200 320 'text/plain' 40000)"
expect  'a not-found path produces no verdict line' '' "$(verdict_path 404 0 'text/html' 40000)"

echo
echo '=== DNS ==='
contains 'DNS: status 0 read'      'NOERROR'  "$(dns_status '{"Status":0,"TC":false,"Answer":[]}')"
contains 'DNS: status 3 read'      'NXDOMAIN' "$(dns_status '{"Status":3,"TC":false}')"
contains 'DNS: missing status reported' 'STATUS MISSING' "$(dns_status 'not json at all')"
expect  'DNS: the CNAME target is extracted' 'app.pages.example' \
  "$(dns_cname_target '{"Answer":[{"name":"www.example.com","type":5,"TTL":300,"data":"app.pages.example."}]}')"
expect  'DNS: an A record is not a CNAME' '' \
  "$(dns_cname_target '{"Answer":[{"name":"example.com","type":1,"TTL":300,"data":"203.0.113.9"}]}')"

echo
echo '=== SECRET SEARCH INSIDE PAGES ==='
printf 'config = { ip: "192.168.1.7", other: "172.20.0.5", vpn: "10.0.0.4", public: "172.15.0.1" }\n' > "$t/page.txt"
secrets="$(find_secrets "$t/page.txt")"
contains 'private address 192.168.x found' '192.168.1.7' "$secrets"
contains 'private address 172.20.x found'  '172.20.0.5'  "$secrets"
contains 'private address 10.x found'      '10.0.0.4'    "$secrets"
lacks   'public address 172.15.x not reported' '172.15.0.1' "$secrets"
printf 'var a=1;\0\0AKIAABCDEFGHIJKLMNOP\0end\n' > "$t/bundle.bin"  # gitleaks:allow
binary="$(find_secrets "$t/bundle.bin")"
contains 'a secret inside a binary file is found' 'AKIAABCDEFGH' "$binary"
lacks   'the secret comes out masked, not whole'  'AKIAABCDEFGHIJKLMNOP' "$binary"  # gitleaks:allow
printf 'const origin = "203.0.113.10";\n' > "$t/origin.txt"
contains 'the configured origin address is flagged' '203.0.113.10' "$(find_secrets "$t/origin.txt" '203\.0\.113\.10')"
lacks   'without the extra pattern a public address is not flagged' '203.0.113.10' "$(find_secrets "$t/origin.txt")"

echo
echo '=== REQUESTS ==='
AUDIT_PAUSE=0 pause; expect 'the pause exists and is adjustable' 0 "$?"
file_has 'the collector pauses inside its request loops' 'pause' "$COLLECT"
file_has 'third party scripts are listed, not downloaded' 'NOT downloaded' "$COLLECT"

echo
echo '=== DOCUMENTS: paths, sources, no local branding ==='
file_has 'SKILL.md points at the target check'   'check-target' "$SKILL_MD"
file_has 'SKILL.md uses the output directory from the profile' 'OUTPUT_DIR' "$SKILL_MD"
file_has 'SKILL.md names the companion skill'    'linux-server-audit' "$SKILL_MD"
file_has 'the template names the report file'    'web-security-audit-' "$TEMPLATE"
file_has 'targets.md explains how to find forgotten subdomains' 'crt\.sh' "$TARGETS"
file_lacks 'targets.md carries no hand written target list' '\| .[a-z]+\.(com|it|net)\b' "$TARGETS"
file_has 'checks.md cites the web security book'  '\(Li ch\. [0-9]+' "$CHECKS"
file_has 'checks.md cites the hardening book'     '\(Tevault ch\. [0-9]+' "$CHECKS"
file_has 'checks.md marks its own field facts'    'verified in the' "$CHECKS"
file_has 'the example profile explains which values are refused' 'example\.com' "$EXAMPLE"

echo
echo '=== PROFILE: the example file is a form, not a profile ==='
# The example file says in writing that the skill refuses to run while it is a
# stub. That sentence has to be true, or it is the worst kind of documentation:
# the kind that stops people from checking.
printf 'ALLOWED_DOMAINS="example.com example.org"\nOUTPUT_DIR="%s/out"\n' "$t" > "$t/still-example.conf"
expect_nonzero 'a domain list still holding the reserved names does not run' \
  "$(check_target_rc "$t/still-example.conf" www.example.com)"
contains 'and the message says the profile was never filled in' 'never filled in' \
  "$(check_target "$t/still-example.conf" www.example.com)"
printf 'ALLOWED_DOMAINS="mysite.test example.org"\nOUTPUT_DIR="%s/out"\n' "$t" > "$t/half-example.conf"
expect_nonzero 'one reserved domain left in the list is enough to stop' \
  "$(check_target_rc "$t/half-example.conf" www.mysite.test)"
file_has 'the example profile ships an empty domain list' 'ALLOWED_DOMAINS=""' "$EXAMPLE"
file_has 'the example profile leaves the optional host empty' 'SSH_HOST=""' "$EXAMPLE"
file_lacks 'and carries no value that looks already filled in' 'ALLOWED_DOMAINS="[a-z]' "$EXAMPLE"

echo
echo '=== SAVING A BUNDLE: the collection of an hour ago survives ==='
# Same treatment the server collector already got: two runs on the same day used
# to share one file name, and the shell truncated it the moment it opened the
# redirection, so a run that failed to start destroyed the bundle collected
# earlier that day, which is the one you would want to compare against.
file_has 'the saved bundle name carries the hour and the minute' 'date \+%Y-%m-%d-%H%M' "$COLLECT"
file_lacks 'no saved bundle name is built from the day alone' \
  'bundle-site-\$host-\$\(date \+%Y-%m-%d\)' "$COLLECT"
file_has 'the collection is written aside first'  'partial=' "$COLLECT"
file_has 'and takes its final name only when whole' 'mv "\$partial" "\$bundle"' "$COLLECT"
file_has 'the completion marker is what decides that' 'tail -3 "\$partial"' "$COLLECT"
file_has 'a collection cut short is kept aside, not passed off as a bundle' 'without becoming a bundle' "$COLLECT"

echo
echo '=== EXTRA PATHS GIVEN ON THE COMMAND LINE ==='
# An extra path is glued straight onto https://<host>. curl reads everything
# before an @ as credentials, so an argument beginning with @ turns the audited
# host into a username and sends the request to a completely different site:
# the one thing this tool promises never to do. Anything that is not a plain
# path has to be refused before a single request goes out.
path_result() { if extra_path_valid "$1"; then echo accepted; else echo refused; fi; }
expect 'a plain path is accepted'                  accepted "$(path_result '/admin')"
expect 'a path with a query is accepted'           accepted "$(path_result '/search?q=1')"
expect 'a deep path is accepted'                   accepted "$(path_result '/api/v1/users')"
expect 'a path starting with @ is refused'         refused  "$(path_result '@other-site.invalid/x')"
expect 'an @ anywhere in the path is refused'      refused  "$(path_result '/x@other-site.invalid')"
expect 'a protocol relative path is refused'       refused  "$(path_result '//other-site.invalid/x')"
expect 'a whole URL is refused'                    refused  "$(path_result 'https://other-site.invalid/x')"
expect 'a scheme buried in the path is refused'    refused  "$(path_result '/x://other-site.invalid')"
expect 'a path without the leading slash is refused' refused "$(path_result 'admin')"
expect 'an empty path is refused'                  refused  "$(path_result '')"
expect 'a path with a space is refused'            refused  "$(path_result '/a b')"

# The collector itself must refuse it, not just the filter function, and it must
# refuse it in target-check mode too, which requests nothing by construction.
out="$(check_target "$t/good.conf" mysite.test '@other-site.invalid/x')"
expect_nonzero 'the collector refuses a poisoned extra path' \
  "$(check_target "$t/good.conf" mysite.test '@other-site.invalid/x' >/dev/null 2>&1; printf '%s' "$?")"
contains 'and the refusal names the extra path' 'other-site.invalid' "$out"
contains 'and explains what an extra path may look like' 'extra path' "$out"
expect 'a good extra path does not disturb the target check' 0 \
  "$(check_target "$t/good.conf" mysite.test '/data.json' >/dev/null 2>&1; printf '%s' "$?")"

echo
echo '=== A RUN WITH FAKE TOOLS: proof that nothing was requested ==='
# curl and openssl are replaced by stubs that write a line into a log instead of
# touching the network. Without this the claim "no request was made" would rest
# on reading the code, which is exactly the kind of proof that misses a bug.
mkdir -p "$t/bin"
cat > "$t/bin/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$CURL_LOG"
printf 'HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n'
STUB
cat > "$t/bin/openssl" <<'STUB'
#!/usr/bin/env bash
printf 'openssl %s\n' "$*" >> "$CURL_LOG"
STUB
chmod +x "$t/bin/curl" "$t/bin/openssl"

mkdir -p "$t/tmp"
collect_out=''; collect_rc=''
run_collect() {   # run_collect <log> <directory for temporary files> <args...>
  local log="$1" td="$2"; shift 2
  : > "$log"
  collect_out="$(env -u ALLOWED_DOMAINS -u OUTPUT_DIR -u SSH_HOST \
      AUDIT_PROFILE="$t/good.conf" AUDIT_PAUSE=0 CURL_LOG="$log" \
      TMPDIR="$td" PATH="$t/bin:$PATH" bash "$COLLECT" "$@" 2>&1)"
  collect_rc=$?
}

# Control: with a good extra path the stub really is reached. Without this the
# rejection test below could pass for the wrong reason (a harness that never
# calls curl at all proves nothing about the refusal).
run_collect "$t/curl-ok.log" "$t/tmp" mysite.test /data.json
expect 'control: a normal run reaches the fake curl' 0 "$([ -s "$t/curl-ok.log" ]; printf '%s' "$?")"
contains 'control: the run asks the audited host' 'mysite.test' "$(cat "$t/curl-ok.log")"

run_collect "$t/curl-bad.log" "$t/tmp" mysite.test '@other-site.invalid/x'
expect_nonzero 'a poisoned extra path stops the whole run' "$collect_rc"
expect 'and NOT ONE request went out' 0 "$([ ! -s "$t/curl-bad.log" ]; printf '%s' "$?")"
lacks 'and the foreign host was never asked anything' 'other-site.invalid' "$(cat "$t/curl-bad.log")"

# mktemp failing used to leave the variable empty, so every -o and -D wrote to
# the root of the disk: the opposite of the promise that nothing is written.
run_collect "$t/curl-tmp.log" "$t/there-is-no-such-directory" mysite.test
expect_nonzero 'a temporary directory that cannot be created stops the run' "$collect_rc"
contains 'and says so instead of writing to the root of the disk' 'temporary' "$collect_out"
expect 'and no request went out either' 0 "$([ ! -s "$t/curl-tmp.log" ]; printf '%s' "$?")"

echo
echo '=== REDIRECTS: the chain never leaves the audited domain ==='
# curl -L follows a redirect wherever it points, third party hosts included.
# The chain is walked one hop at a time instead, and the fetcher is passed in so
# this can be exercised with no network at all.
fake_headers() {
  case "$1" in
    http://mysite.test/)      printf 'HTTP/1.1 301\r\nlocation: https://mysite.test/\r\n' ;;
    https://mysite.test/)     printf 'HTTP/1.1 302\r\nlocation: https://www.mysite.test/home\r\n' ;;
    https://www.mysite.test/home) printf 'HTTP/1.1 200\r\ncontent-type: text/html\r\n' ;;
    *) printf 'HTTP/1.1 200\r\n' ;;
  esac
}
fake_headers_offsite() {
  case "$1" in
    http://mysite.test/)  printf 'HTTP/1.1 301\r\nlocation: https://tracker.other-site.invalid/x\r\n' ;;
    *) printf 'HTTP/1.1 200\r\n' ;;
  esac
}
fake_headers_loop() { printf 'HTTP/1.1 301\r\nlocation: https://a%s.mysite.test/\r\n' "$RANDOM"; }
fake_headers_fail() { return 7; }
domains='mysite.test othersite.test'

expect 'a redirect to an absolute address is read' 'https://www.mysite.test/x' \
  "$(redirect_target 'HTTP/1.1 301
location: https://www.mysite.test/x' 'https://mysite.test/')"
expect 'a root relative redirect is made absolute' 'https://mysite.test/home' \
  "$(redirect_target 'HTTP/1.1 302
Location: /home' 'https://mysite.test/')"
expect 'a protocol relative redirect keeps https' 'https://www.mysite.test/y' \
  "$(redirect_target 'HTTP/1.1 302
location: //www.mysite.test/y' 'https://mysite.test/')"
expect 'a response without a location has no next hop' '' \
  "$(redirect_target 'HTTP/1.1 200
content-type: text/html' 'https://mysite.test/')"
expect_nonzero 'and says so with its exit code' \
  "$(redirect_target 'HTTP/1.1 200' 'https://mysite.test/' >/dev/null 2>&1; printf '%s' "$?")"

out="$(follow_chain fake_headers 'http://mysite.test/' "$domains")"
contains 'the chain reports every hop it walked' 'https://www.mysite.test/home' "$out"
follow_chain fake_headers 'http://mysite.test/' "$domains" >/dev/null
expect 'a chain that stays home does not leave the scope' 0 "$FOLLOW_LEFT_SCOPE"
expect 'and the last address is the final page' 'https://www.mysite.test/home' "$FOLLOW_URL"

out="$(follow_chain fake_headers_offsite 'http://mysite.test/' "$domains")"
contains 'a hop pointing outside is reported' 'tracker.other-site.invalid' "$out"
contains 'and it is stated that it was NOT requested' 'NOT requested' "$out"
follow_chain fake_headers_offsite 'http://mysite.test/' "$domains" >/dev/null
expect 'the chain records that it left the scope' 1 "$FOLLOW_LEFT_SCOPE"
expect 'and the last address asked for is still ours' 'http://mysite.test/' "$FOLLOW_URL"

out="$(follow_chain fake_headers_loop 'http://mysite.test/' "$domains" 3)"
contains 'an endless redirect chain is cut' 'more than 3' "$out"
follow_chain fake_headers_fail 'http://mysite.test/' "$domains" >/dev/null
expect_nonzero 'a fetch that fails is carried out of the chain' "$FOLLOW_RC"

file_lacks 'no curl call carries the follow switch' '\{C\[@\]\}.*(-L|--max-redirs)' "$COLLECT"
file_has 'the chain is walked by the collector itself' 'follow_chain curl_headers' "$COLLECT"

echo
echo '=== SECURITY HEADERS: read from the final response only ==='
# With more than one response in the dump, tail -1 picked the header of an
# intermediate hop: a redirect carrying a policy made the real page look
# protected when it is not.
two_blocks='HTTP/1.1 301 Moved
content-security-policy: default-src (self)
location: https://www.mysite.test/

HTTP/1.1 200 OK
content-type: text/html
x-frame-options: DENY'
expect 'a header only the intermediate hop sent is absent' '' \
  "$(header_value content-security-policy "$two_blocks")"
contains 'a header of the final response is present' 'DENY' \
  "$(header_value x-frame-options "$two_blocks")"
contains 'the final block is the one after the last status line' 'text/html' \
  "$(last_header_block "$two_blocks")"
lacks 'and it does not carry the intermediate one' 'default-src' \
  "$(last_header_block "$two_blocks")"
contains 'a dump with a single response still works' 'DENY' \
  "$(header_value x-frame-options 'HTTP/1.1 200 OK
x-frame-options: DENY')"

echo
echo '=== A FAILED REQUEST NEVER LEAVES AN EMPTY SECTION ==='
# An empty section reads as "nothing to report". A request that never got an
# answer has to say it did not.
contains 'a failed request says not verified' 'NOT VERIFIED' \
  "$(verdict_or_not_verified 7 '' 'the cleartext version did not answer')"
contains 'and names what was being asked' 'cleartext' \
  "$(verdict_or_not_verified 7 '' 'the cleartext version did not answer')"
contains 'an empty answer with rc 0 is not verified either' 'NOT VERIFIED' \
  "$(verdict_or_not_verified 0 '   ' 'no method list came back')"
contains 'an answer that arrived is printed as it is' 'allow: GET' \
  "$(verdict_or_not_verified 0 'allow: GET, HEAD' 'no method list came back')"
lacks 'and is not stamped not verified' 'NOT VERIFIED' \
  "$(verdict_or_not_verified 0 'allow: GET, HEAD' 'no method list came back')"
file_has 'the cleartext section reports a failed request' \
  'verdict_or_not_verified' "$COLLECT"

echo
echo '=== SENSITIVE PATHS: a failed request is not a checked path ==='
# When curl failed, its error text used to be read as the code, the size and the
# content type, and the path was printed with no verdict at all: it reads like a
# path that was looked at and found fine.
contains 'a path whose request failed says not verified' 'NOT VERIFIED' \
  "$(path_line 7 '' 40000)"
contains 'a failed request with error text on stdout is still not verified' 'NOT VERIFIED' \
  "$(path_line 6 'curl: (6) Could not resolve host' 40000)"
contains 'a real answer keeps its verdict' 'REAL ANSWER' \
  "$(path_line 0 '200 320 text/plain' 40000)"
contains 'and a disguised not-found keeps its own' 'disguised' \
  "$(path_line 0 '200 41000 text/html' 40000)"
expect 'a 404 stays quiet' '404 0 text/html' "$(path_line 0 '404 0 text/html' 40000)"

echo
echo '=== OPEN DIRECTORIES: the whole body is searched ==='
# The marker was looked for in the first 400 bytes only. A listing whose header,
# banner or navigation comes first was reported as a closed directory.
long_body="$(printf 'x%.0s' $(seq 1 3000))<h1>Index of /assets</h1>"
expect 'a listing marker deep in the body is still found' OPEN "$(verdict_listing 0 "$long_body")"
file_lacks 'the directory body is not cut to the first bytes' 'head -c 400' "$COLLECT"

echo
echo '=== SCRIPTS: single quotes count, .json is not a script ==='
# The old pattern read src="..." only and matched ".js" anywhere inside the
# name, so data.json was downloaded as a script while every bundle written with
# single quotes was skipped, and so never reached the secret search.
cat > "$t/page.html" <<'HTML'
<script src="/app.js"></script>
<script src='/bundle.min.js'></script>
<script src="/data.json"></script>
<script src="/x.js?v=3"></script>
<script src="https://cdn.other.example/lib.js"></script>
<img src="/logo.png">
HTML
srcs="$(extract_script_srcs "$t/page.html")"
contains 'a double quoted script is found'  '/app.js'         "$srcs"
contains 'a single quoted script is found'  '/bundle.min.js'  "$srcs"
contains 'a versioned script is found'      '/x.js?v=3'       "$srcs"
contains 'a third party script is still listed' 'cdn.other.example/lib.js' "$srcs"
lacks   'a .json file is not taken for a script' 'data.json'   "$srcs"
lacks   'and neither is an image'                'logo.png'    "$srcs"

# --- an answer that never arrived is not an answer about cookies --------------
out="$(cookie_lines '')"
contains 'cookies: no answer at all is NOT VERIFIED'      'NOT VERIFIED'  "$out"
lacks    'cookies: and is never called "sets no cookie"'  'sets no cookie' "$out"
out="$(cookie_lines 'HTTP/1.1 200 OK
content-type: text/html')"
contains 'cookies: a real answer with none says so'       'sets no cookie' "$out"
out="$(cookie_lines 'HTTP/1.1 200 OK
set-cookie: sid=abc; HttpOnly')"
contains 'cookies: a cookie that is there is printed'     'sid=abc'        "$out"

# --- with no reference measurement, everything looks like a finding ----------
# When the home page could not be read, its size is zero, and a size comparison
# against zero marks every single 200 as worth looking at: a wall of false
# findings that hides the one real one.
out="$(verdict_path 200 5000 'text/html; charset=utf-8' 0)"
contains 'paths: with no reference it says so'            'no reference'   "$out"
lacks    'paths: and does not cry "look at this"'         'look at this'   "$out"
out="$(verdict_path 200 5000 'text/html' 5200)"
contains 'paths: with a reference a similar page is a disguised not-found' 'disguised' "$out"

# --- the family guard: ask the address the visitor actually lands on ----------
# A site answering on the bare domain and serving on www redirects every path.
# Asking the starting address back gets 301 for everything: the directory sweep
# calls eight directories closed without looking at them, and an exposed source
# control directory is never seen. Once the chain has resolved the destination,
# every later request must start from it.
out="$(site_base_from 'https://www.example.com/' 'example.com')"
contains 'site base: the resolved address loses its trailing slash' 'https://www.example.com' "$out"
lacks    'site base: and does not keep it'                          'com/'                     "$out"
out="$(site_base_from '' 'example.com')"
contains 'site base: with no resolved address it falls back to the target' 'https://example.com' "$out"

collector="$(dirname "$0")/../scripts/collect-site.sh"
n_raw="$(grep -c 'https://\$host' "$collector" 2>/dev/null || echo 0)"
if [ "${n_raw:-0}" -le 1 ]; then
  ok=$((ok+1)); printf 'ok    family: only the chain starts from the raw target (%s use)\n' "$n_raw"
else
  ko=$((ko+1)); printf 'KO    family: %s requests still start from the raw target instead of the resolved one\n' "$n_raw"
fi

echo
printf 'TESTS: %d passed, %d failed (%d total)\n' "$ok" "$ko" "$((ok+ko))"
[ "$ko" -eq 0 ] || exit 1
exit 0
