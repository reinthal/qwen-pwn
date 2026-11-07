#!/usr/bin/env bash
# Self-test for the public sinkhole. Checks the response policy and that the
# access log holds no bodies, query values, headers or full IPs.
#
#   ./selftest.sh                         # starts a throwaway local container, tests it, removes it
#   BASE=http://r0ck3t.net ./selftest.sh  # tests a live deployment (response checks only)
set -uo pipefail
cd "$(dirname "$0")"

ENGINE=${ENGINE:-$(command -v podman || command -v docker)}
IMAGE=docker.io/library/caddy:2.10.0-alpine
HOSTNAME_UNDER_TEST=${HOSTNAME_UNDER_TEST:-r0ck3t.net}
fail=0
ok()  { printf '  ok    %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1"; fail=1; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

LOCAL=0
if [ -z "${BASE:-}" ]; then
  LOCAL=1
  LOGDIR=$(mktemp -d)
  "$ENGINE" rm -f sinkhole-selftest >/dev/null 2>&1
  "$ENGINE" run -d --name sinkhole-selftest -p 127.0.0.1:18080:80 -p 127.0.0.1:18081:8080 \
    -e SINKHOLE_DOMAINS=localhost -e SINKHOLE_NAME="$HOSTNAME_UNDER_TEST" \
    -e CONTACT_EMAIL=research@example.org -e ACME_EMAIL=research@example.org \
    -v ./Caddyfile:/etc/caddy/Caddyfile:ro,Z -v ./site:/srv:ro,Z -v "$LOGDIR":/logs:Z \
    -v sinkhole-selftest-data:/data -v sinkhole-selftest-config:/config \
    --read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges:true "$IMAGE" >/dev/null || { echo "container failed to start"; exit 1; }
  trap '"$ENGINE" rm -f sinkhole-selftest >/dev/null; "$ENGINE" volume rm -f sinkhole-selftest-data sinkhole-selftest-config >/dev/null; rm -rf "$LOGDIR"' EXIT
  BASE=http://127.0.0.1:18080
  for _ in $(seq 20); do curl -s -o /dev/null "$BASE/" && break; sleep 0.5; done
fi
H="Host: $HOSTNAME_UNDER_TEST"
code() { curl -s -o /dev/null -w '%{http_code}' -H "$H" "$@"; }

echo "responses ($BASE)"
for p in /dl.sh /x /tmp/stage.sh /tmp/probe.txt /; do
  check "GET $p → 404" '[ "$(code "$BASE$p")" = 404 ]'
done
for p in /dl.sh /x /tmp/stage.sh; do
  body=$(curl -s -H "$H" "$BASE$p")
  check "GET $p body is comment-only" '! grep -qv "^#" <<<"$body"'
  check "curl $p | sh runs nothing" '[ -z "$(printf "%s" "$body" | sh -x 2>&1)" ]'
done
probe=$(mktemp); echo SECRET_BODY_MARKER_12345 >"$probe"
check "PUT -T → 403" '[ "$(code -T "$probe" "$BASE/tmp/put_probe?token=SECRET_QUERY_MARKER")" = 403 ]'
check "POST multipart → 403" '[ "$(code -F f=@"$probe" "$BASE/upload")" = 403 ]'
check "DELETE → 403" '[ "$(code -X DELETE "$BASE/x")" = 403 ]'
rm -f "$probe"
check "landing page only for browsers" '[ "$(code -H "Accept: text/html" "$BASE/")" = 200 ]'
check "security.txt has Contact" 'curl -s -H "$H" "$BASE/.well-known/security.txt" | grep -q "^Contact: mailto:"'
check "robots.txt disallows all" 'curl -s -H "$H" "$BASE/robots.txt" | grep -q "Disallow: /"'
check "no redirect on plain HTTP" '[ -z "$(curl -s -o /dev/null -w "%{redirect_url}" -H "$H" "$BASE/x")" ]'
check "no Server header" '! curl -s -I -H "$H" "$BASE/x" | grep -qi "^server:"'
if [ "$LOCAL" = 1 ]; then
  check "port 8080 → 404" '[ "$(code http://127.0.0.1:18081/probe.txt)" = 404 ]'
  sleep 1
  LOG="$LOGDIR/access.log"
  echo "access log"
  check "log written" '[ -s "$LOG" ]'
  for m in SECRET_BODY_MARKER SECRET_QUERY_MARKER token= '"headers"' '"Accept"'; do
    check "log has no $m" '! grep -q -- "$m" "$LOG"'
  done
  check "IPv4 masked to /24" '! grep -oE "\"(remote|client)_ip\":\"[0-9.]+\"" "$LOG" | grep -vqE "\.0\"$"'
  check "user agent kept" 'grep -q "\"user_agent\":\"curl/" "$LOG"'
  check "upload bodies not read" '! grep "\"method\":\"PUT\"" "$LOG" | grep -vq "\"bytes_read\":0"'
fi
echo; [ "$fail" = 0 ] && echo "ALL CHECKS PASSED" || { echo "SOME CHECKS FAILED"; exit 1; }
