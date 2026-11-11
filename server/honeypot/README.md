# Qwen 3.8 call-home honeypot

Honeypot rig for **r0ck3t.net, r0ck3y.net, r0ckey.com, r0ckey.net** on
`80.78.18.246` / `2a0a:3840:8078:18:0:504e:12f6:1337` (Debian 13). Qwen 3.8
occasionally emits spurious requests to "rocket net"-sounding domains
(training artifact); this rig answers them with an explanatory message and
records them.

| Piece | What it does |
|---|---|
| BIND9 (`bind/`) | Authoritative-only on the public IPs (loopback :53 stays with systemd-resolved). Apex + wildcard A/AAAA, CAA, honeypot TXT. r0ck3t.net carries the Proton Mail records; the other three publish null MX / `-all` SPF / `p=reject` DMARC. RRL 20 rps. Query log → `/var/log/named/queries.log`. |
| `honeypot_http.py` | Stdlib HTTP server on 80, 443, 9, 8000, 8080, 8082, 8090, 8099, 9999 (dual-stack). 200 for every verb. `Accept: application/json` → JSON, `text/html` → HTML, anything else → text/plain where every line starts with `#`, so `curl … \| sh` does nothing. Also serves `robots.txt` (Disallow: /) and `/.well-known/security.txt`. TLS on 443 once certs exist (plain HTTP there until then). Every request is logged to `http_requests`, including the TLS SNI. |
| `dns_telemetry.py` | Tails the query log into the `dns_queries` table. Reads in binary mode, keeps (inode, offset) in the same SQLite transaction as the rows, and handles rotation. |
| `honeypot_report.py` | Report over a time window: hits per zone, top qnames, clients, hosts, UAs, and the most recent hits. |
| `njalla_delegate.py` | Sets up ns1/ns2 glue and nameservers at Njalla. Dry run by default. |
| `deploy.sh` | `server` / `certs` / `verify` / `all`. Idempotent. |

Paths: code in `/opt/qwen-honeypot/`, data in `/var/lib/qwen-honeypot/`
(`telemetry.db`, `certs/`), service user `qwen-honey`.

## Bring-up order (DNS-01 needs the delegation first)

```sh
cd ~/qwen-pwn/server/honeypot
sudo ./deploy.sh server          # packages, BIND, services, firewall
sudo ./deploy.sh verify          # everything except delegation/TLS should pass

cd ~/qwen-pwn
sudo .venv/bin/python server/honeypot/njalla_delegate.py            # dry run: shows the plan
sudo NJALLA_API_KEY=... .venv/bin/python server/honeypot/njalla_delegate.py --apply

# wait until the registry serves our NS + glue:
dig +norec +noall +authority +additional NS r0ck3t.net @a.gtld-servers.net

cd server/honeypot
sudo ./deploy.sh certs           # certbot DNS-01 via RFC 2136 (TSIG), 8 SANs
sudo ./deploy.sh verify
```

(`.venv/bin/python` is a symlink into root's uv Python. That is why the
delegation script runs under sudo.)

Rollback for the delegation: `njalla_delegate.py --revert --apply` points the
domains back at Njalla's nameservers. Njalla's own DNS currently has only the
Proton verification TXT, so mail stays broken there until you add the MX
records back at Njalla.

## Logs

Every HTTP request also produces one journal line with client IP, method, full URL,
status, `Authorization` header and User-Agent. Values are JSON-quoted, so a
crafted header can't add fake fields or extra lines:

```sh
journalctl -fu qwen-honeypot-http -o cat | grep '^http '
```

DNS queries: `sudo tail -f /var/log/named/queries.log`.

## Reports

```sh
sudo python3 /opt/qwen-honeypot/honeypot_report.py --hours 72
```

When run as root, the report drops to `qwen-honey`. Root-owned `-wal`/`-shm`
files would otherwise break the services.

## Notes

* Zone edits: change `bind/zones/db.*`, **bump the serial**, re-run
  `deploy.sh server`. Live zones are replaced only when the repo serial is
  higher, using `rndc freeze`/`thaw` around the copy.
* TSIG key `/etc/bind/qwen-honeypot-acme.key` can only touch
  `_acme-challenge.<zone>` TXT records.
* nftables is applied only when the live ruleset is empty. Otherwise the
  rendered rules go to `/opt/qwen-honeypot/nftables.rendered.conf` for a
  manual merge.
* TODO (user): add the Proton DKIM CNAMEs (`protonmail{,2,3}._domainkey`) to
  `bind/zones/db.r0ck3t.net`, bump the serial, redeploy.
* The old `server/sinkhole_server.py` rig and `deploy/public-sinkhole` are
  superseded and not used here.
