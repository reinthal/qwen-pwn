#!/usr/bin/env bash
# Qwen 3.8 call-home honeypot deploy script (Debian 13).
#
#   sudo ./deploy.sh [server|certs|verify|all]     (default: all)
#
#   server  packages, qwen-honey user, BIND (public IPs only), telemetry + http
#           services, nftables (only if the live ruleset is empty)
#   certs   rfc2136.ini from the TSIG key, certbot DNS-01 (needs delegation live)
#   verify  health checks / smoke tests
#   all     server; certs only if the .net/.com registry already delegates to us; verify
#
# Idempotent: safe to re-run.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAINS=(r0ck3t.net r0ck3y.net r0ckey.com r0ckey.net)
IPV4=80.78.18.246
IPV6=2a0a:3840:8078:18:0:504e:12f6:1337
HONEY_PORTS=(80 443 9 8000 8080 8082 8090 8099 9999)
SVC_USER=qwen-honey
OPT=/opt/qwen-honeypot
VAR=/var/lib/qwen-honeypot
KEYNAME=qwen-honeypot-acme
KEYFILE=/etc/bind/${KEYNAME}.key
RFC2136_INI=/etc/letsencrypt/rfc2136.ini
EMAIL=researchers@r0ck3t.net
PKGS=(bind9 bind9-utils certbot python3-certbot-dns-rfc2136 nftables sqlite3 python3)

log()  { printf '\e[1;34m==>\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33mWARN:\e[0m %s\n' "$*" >&2; }
die()  { printf '\e[1;31mERROR:\e[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 $*)"

backup_once() {  # keep the distro original the first time we replace a file
  local f=$1
  [[ -e $f && ! -e $f.orig-qwen ]] && cp -a "$f" "$f.orig-qwen" || true
}

zone_serial() {  # first 10-digit number after SOA in a zone file
  grep -A2 -E '\sSOA\s' "$1" 2>/dev/null | grep -oE '\b[0-9]{10}\b' | head -1 || true
}

delegation_live() {
  local d tld_ns
  for d in "${DOMAINS[@]}"; do
    tld_ns=a.gtld-servers.net   # .net and .com share the Verisign gTLD servers
    dig +norec +time=3 +tries=2 +noall +authority NS "$d" "@$tld_ns" 2>/dev/null \
      | grep -qiE "\sNS\s+ns[12]\.${d//./\\.}\.?$" || return 1
  done
}

detect_ssh_ports() {
  local ports
  ports=$( { ss -Htlnp 2>/dev/null | awk '/"sshd/ {print $4}' | sed -E 's/.*:([0-9]+)$/\1/';
             grep -hiE '^\s*Port\s+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
               | awk '{print $2}'; } | sort -un | paste -sd, -)
  echo "${ports:-22}"
}

# --------------------------------------------------------------------------- server
stage_server() {
  log "installing packages: ${PKGS[*]}"
  export DEBIAN_FRONTEND=noninteractive
  # Don't let bind9 start with the distro config (recursion, all interfaces)
  # during install; we start it ourselves once configured.
  local own_policy=0
  if [[ ! -e /usr/sbin/policy-rc.d ]]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d; own_policy=1
  fi
  apt-get update -q
  apt-get install -y -q "${PKGS[@]}" || { [[ $own_policy == 1 ]] && rm -f /usr/sbin/policy-rc.d; die "apt failed"; }
  [[ $own_policy == 1 ]] && rm -f /usr/sbin/policy-rc.d

  log "service user $SVC_USER"
  id -u "$SVC_USER" >/dev/null 2>&1 || \
    useradd --system --user-group --home-dir "$VAR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"

  log "installing scripts to $OPT, data dir $VAR"
  install -d -o root -g root -m 0755 "$OPT"
  install -o root -g root -m 0755 "$SRC"/{honeypot_http.py,dns_telemetry.py,honeypot_report.py} "$OPT/"
  install -o root -g root -m 0755 "$SRC/certbot-deploy-hook.sh" "$OPT/"
  install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$VAR" "$VAR/certs"

  log "query log /var/log/named"
  install -d -o bind -g bind -m 0750 /var/log/named
  [[ -e /var/log/named/queries.log ]] || install -o bind -g bind -m 0640 /dev/null /var/log/named/queries.log

  if [[ ! -s $KEYFILE ]]; then
    log "generating TSIG key $KEYNAME"
    tsig-keygen -a hmac-sha256 "$KEYNAME" > "$KEYFILE"
  fi
  chown root:bind "$KEYFILE"; chmod 0640 "$KEYFILE"

  log "BIND config"
  backup_once /etc/bind/named.conf.options
  backup_once /etc/bind/named.conf.local
  install -o root -g bind -m 0644 "$SRC/bind/named.conf.options" /etc/bind/named.conf.options
  install -o root -g bind -m 0644 "$SRC/bind/named.conf.local"   /etc/bind/named.conf.local

  local named_up=0
  systemctl is-active --quiet named && named_up=1
  local d src dst new old
  for d in "${DOMAINS[@]}"; do
    src="$SRC/bind/zones/db.$d"; dst="/var/lib/bind/db.$d"
    named-checkzone -q "$d" "$src" || die "zone $src fails named-checkzone"
    new=$(zone_serial "$src"); old=$(zone_serial "$dst")
    if [[ ! -e $dst ]]; then
      log "  zone $d: installing (serial $new)"
      install -o bind -g bind -m 0644 "$src" "$dst"
    elif [[ -n $old && $new -gt $old ]]; then
      log "  zone $d: updating serial $old -> $new"
      [[ $named_up == 1 ]] && rndc freeze "$d" >/dev/null 2>&1 || true
      install -o bind -g bind -m 0644 "$src" "$dst"; rm -f "$dst.jnl"
      [[ $named_up == 1 ]] && rndc thaw "$d" >/dev/null 2>&1 || true
    else
      log "  zone $d: live serial ${old:-?} >= repo $new, leaving it"
    fi
  done

  named-checkconf -z >/dev/null || die "named-checkconf failed"
  log "starting named"
  systemctl enable named >/dev/null 2>&1 || true
  systemctl restart named
  sleep 1
  systemctl is-active --quiet named || { journalctl -u named -n 30 --no-pager; die "named not running"; }

  log "systemd units"
  install -o root -g root -m 0644 "$SRC"/units/qwen-honeypot-{http,telemetry}.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable qwen-honeypot-telemetry.service qwen-honeypot-http.service >/dev/null
  systemctl restart qwen-honeypot-telemetry.service qwen-honeypot-http.service

  stage_firewall
}

stage_firewall() {
  local ssh_ports rendered
  ssh_ports=$(detect_ssh_ports)
  rendered=$(mktemp)
  sed "s/@SSH_PORTS@/${ssh_ports//,/, }/" "$SRC/nftables.conf" > "$rendered"
  nft -c -f "$rendered" || { rm -f "$rendered"; die "rendered nftables.conf does not parse"; }
  if [[ -z $(nft list ruleset 2>/dev/null) ]]; then
    log "nftables: ruleset empty -> applying (ssh ports: $ssh_ports)"
    backup_once /etc/nftables.conf
    install -o root -g root -m 0755 "$rendered" /etc/nftables.conf
    nft -f /etc/nftables.conf
    systemctl enable nftables >/dev/null 2>&1 || true
  else
    install -o root -g root -m 0644 "$rendered" "$OPT/nftables.rendered.conf"
    warn "nftables ruleset is not empty: NOT touching it. Merge $OPT/nftables.rendered.conf by hand."
  fi
  rm -f "$rendered"
}

# ---------------------------------------------------------------------------- certs
stage_certs() {
  [[ -s $KEYFILE ]] || die "no TSIG key ($KEYFILE); run '$0 server' first"
  delegation_live || die "registry does not delegate all of ${DOMAINS[*]} to ns1/ns2 yet (run njalla_delegate.py --apply, wait)"

  log "writing $RFC2136_INI"
  local secret algo
  secret=$(awk -F'"' '/secret/ {print $2}' "$KEYFILE")
  algo=$(awk '/algorithm/ {gsub(";","",$2); print toupper($2)}' "$KEYFILE")
  [[ -n $secret ]] || die "could not extract TSIG secret"
  install -d -m 0755 /etc/letsencrypt
  umask 077
  cat > "$RFC2136_INI" <<EOF
# Generated by qwen honeypot deploy.sh — TSIG key limited to _acme-challenge TXT
dns_rfc2136_server = $IPV4
dns_rfc2136_port = 53
dns_rfc2136_name = $KEYNAME
dns_rfc2136_secret = $secret
dns_rfc2136_algorithm = ${algo:-HMAC-SHA256}
dns_rfc2136_sign_query = false
EOF
  umask 022
  chmod 0600 "$RFC2136_INI"

  local args=() d
  for d in "${DOMAINS[@]}"; do args+=(-d "$d" -d "*.$d"); done
  log "certbot (DNS-01, cert-name r0ck3t.net, $(( ${#args[@]} / 2 )) SANs)"
  certbot certonly --non-interactive --agree-tos --email "$EMAIL" \
    --cert-name r0ck3t.net --keep-until-expiring \
    --dns-rfc2136 --dns-rfc2136-credentials "$RFC2136_INI" --dns-rfc2136-propagation-seconds 20 \
    --deploy-hook "$OPT/certbot-deploy-hook.sh" \
    "${args[@]}"
  # --keep-until-expiring skips the hook when nothing was issued; run it anyway.
  RENEWED_LINEAGE=/etc/letsencrypt/live/r0ck3t.net "$OPT/certbot-deploy-hook.sh"
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
}

# --------------------------------------------------------------------------- verify
FAILS=0
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then printf '  \e[32mOK\e[0m   %s\n' "$desc"; else printf '  \e[31mFAIL\e[0m %s\n' "$desc"; FAILS=$((FAILS+1)); fi; }
aa_noerror() { dig +norec +time=2 +tries=1 "$@" | grep -q 'status: NOERROR' && dig +norec +time=2 +tries=1 "$@" | grep -qE 'flags:[^;]* aa'; }
refused()    { dig +time=2 +tries=1 "$@" | grep -q 'status: REFUSED'; }
http_200()   { [[ $(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$@") == 200 ]]; }

stage_verify() {
  log "verify"
  check "named active"                        systemctl is-active --quiet named
  check "qwen-honeypot-telemetry active"      systemctl is-active --quiet qwen-honeypot-telemetry
  check "qwen-honeypot-http active"           systemctl is-active --quiet qwen-honeypot-http
  check "systemd-resolved still answers"      dig +time=2 +tries=1 @127.0.0.53 debian.org SOA
  local d p
  for d in "${DOMAINS[@]}"; do
    check "SOA $d @v4 authoritative"          aa_noerror SOA "$d" "@$IPV4"
    check "SOA $d @v6 authoritative"          aa_noerror SOA "$d" "@$IPV6"
    check "wildcard qwen-probe.$d A"          bash -c "dig +short A qwen-probe.$d @$IPV4 | grep -qx $IPV4"
  done
  check "MX r0ck3t.net -> protonmail"         bash -c "dig +short MX r0ck3t.net @$IPV4 | grep -q mailsec.protonmail.ch"
  check "recursion refused"                   refused A example.com "@$IPV4"
  check "version.bind hidden"                 bash -c "! dig +short CH TXT version.bind @$IPV4 | grep -q '[0-9]'"
  for p in "${HONEY_PORTS[@]}"; do
    [[ $p == 443 && -s $VAR/certs/fullchain.pem ]] && continue
    check "HTTP :$p v4 200"                   http_200 -H 'Host: probe.r0ck3t.net' "http://$IPV4:$p/verify-probe"
  done
  check "HTTP :80 v6 200"                     http_200 -g "http://[$IPV6]:80/verify-probe"
  check "JSON negotiation"                    bash -c "curl -s --max-time 5 -H 'Accept: application/json' http://$IPV4/ | grep -q '\"honeypot\": true'"
  check "plain body is all comments"          bash -c "! curl -s --max-time 5 http://$IPV4/ | grep -qv '^#'"
  check "POST answered 200"                   http_200 -X POST --data x=1 "http://$IPV4:8080/"
  if [[ -s $VAR/certs/fullchain.pem ]]; then
    check "HTTPS :443 valid cert (r0ck3t.net)"  http_200 --resolve "r0ck3t.net:443:$IPV4" https://r0ck3t.net/
    check "HTTPS :443 wildcard (x.r0ckey.com)"  http_200 --resolve "x.r0ckey.com:443:$IPV4" https://x.r0ckey.com/
  fi
  sleep 2
  local nd nh
  nd=$(runuser -u "$SVC_USER" -- sqlite3 "$VAR/telemetry.db" 'SELECT COUNT(*) FROM dns_queries' 2>/dev/null || echo 0)
  nh=$(runuser -u "$SVC_USER" -- sqlite3 "$VAR/telemetry.db" 'SELECT COUNT(*) FROM http_requests' 2>/dev/null || echo 0)
  check "telemetry: dns_queries rows ($nd)"  test "${nd:-0}" -gt 0
  check "telemetry: http_requests rows ($nh)" test "${nh:-0}" -gt 0
  if delegation_live; then echo "  delegation: LIVE"; else echo "  delegation: not yet (njalla_delegate.py --apply)"; fi
  [[ $FAILS -eq 0 ]] && log "all checks passed" || { warn "$FAILS check(s) failed"; return 1; }
}

case "${1:-all}" in
  server) stage_server ;;
  certs)  stage_certs ;;
  verify) stage_verify ;;
  firewall) stage_firewall ;;
  all)
    stage_server
    if delegation_live; then stage_certs; else warn "delegation not live yet: skipping certs (run '$0 certs' later)"; fi
    stage_verify ;;
  *) die "usage: $0 [server|certs|verify|all]" ;;
esac
