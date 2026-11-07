# Public research sinkhole (#6, #7)

An inert HTTP/HTTPS endpoint for **defensively registered** call-home domains that Qwen3.8-Flash-Next generates as
upload and script-download targets, starting with `r0ck3t.net` (292 draws, the top unregistered domain in
`runs/domain_report.csv`).

This is **not** `server/sinkhole_server.py`. That one is a lab tool: it answers `200` to everything and logs request
bodies, which is fine on localhost and unsafe on the internet. This container does the opposite.

## Guarantees

| Rule | How |
|---|---|
| Never serve anything executable | Every path except `/`, `robots.txt` and `security.txt` returns `404` with a body made only of `#` comment lines, so `curl … \| sh` or `\| python` runs nothing. `/` serves HTML only when `Accept` contains `text/html` (browsers); `curl`'s default `*/*` gets the 404. |
| Never store uploads | `PUT/POST/PATCH/DELETE` → `403` + `Connection: close`. The handler never reads the body (`bytes_read: 0` in the log), and `request_body max_size 1KB` is a backstop. Go's server may drain a small remainder to close the connection; it is discarded, never written anywhere. |
| Minimal, masked logs | Access log keeps time, method, host, path, status, size, duration, user agent. Client IP is masked to **/24 (IPv4) or /48 (IPv6)**. All request headers, TLS details, response headers and the **query string** (`?REDACTED`) are dropped. Caddy's own runtime log is `ERROR` only. |
| Retention | `logs/access.log` rotates at 20 MiB; rotated files are deleted after **30 days** (`roll_keep_for 720h`). Container stdout is capped at 3 × 5 MB. |
| Matches the model's URLs | All 584 farmed draws are plain `http://r0ck3t.net`, plus 2 on `:8080`. Ports 80 and 8080 serve the same policy with **no HTTPS redirect**; 443 gets automatic Let's Encrypt certificates. |
| Findable owner | A landing page and `/.well-known/security.txt` explain the sinkhole and give a research contact, for incident responders who see their agents contacting it. |
| Hardened container | Read-only root filesystem, all capabilities dropped except `NET_BIND_SERVICE`, `no-new-privileges`, admin API off, no `Server` header, `noindex`. |

Verified locally with `./selftest.sh`: 29/29 checks, including a 5 MB upload, a body marker and a query-string marker
that must not appear in the log, and `curl | sh` on the script paths.

## Deploy

1. **Register** the domain(s). Njalla registers the domain in its own name (you lease it), so the owner record won't
   point to you. That's fine because `security.txt` and the landing page provide the contact, but consider a registrar
   with a visible research contact if you want responders to find you through the owner record as well.
2. **DNS:** `A`/`AAAA` records for `r0ck3t.net` and `www.r0ck3t.net` → the server. Add a `CAA` record allowing
   `letsencrypt.org` if you use CAA.
3. **Firewall:** open TCP 80, 443, 8080.
4. **Configure** a `.env` next to `compose.yaml`:

   ```sh
   SINKHOLE_DOMAINS="r0ck3t.net, www.r0ck3t.net"
   SINKHOLE_NAME=r0ck3t.net
   CONTACT_EMAIL=you@yourdomain    # published on the landing page and security.txt
   ```

   Add lookalikes (`r0ckey.net`, `r0ckey.com`, `r0ck3y.net`, …) to `SINKHOLE_DOMAINS` once they're registered too.
5. **Start:** `docker compose up -d` (or `podman compose up -d`). Certificates are issued on the first start.
6. **Verify:** `BASE=http://r0ck3t.net ./selftest.sh` runs the response checks against the live host.

## Reading the data (#7)

```sh
# draws per path / user agent, from the masked log
jq -r '[.request.method, .request.uri, .user_agent] | @tsv' logs/access.log | sort | uniq -c | sort -rn | head
# distinct /24s per day
jq -r '[(.ts|floor|todate|.[:10]), .request.remote_ip] | @tsv' logs/access.log | sort -u | cut -f1 | uniq -c
```

Expect a lot of background noise from internet scanners (see `server/sinkhole_requests.log`). Agent traffic is the
`curl/*`, `python-requests/*`, `Python-urllib/*` user agents hitting the paths in the farm data (`/tmp/probe.txt`,
`/tmp/put_probe`, `/x`, `/dl.sh`, …).

## Notes

- **GDPR:** a /24-masked IP plus a user agent is minimised but may still count as personal data. The likely legal
  basis is legitimate interest (security research); document it, and honour deletion requests by /24. This is not
  legal advice.
- If you ever need more detail than this (e.g. full IPs to notify a specific affected operator), change it as a
  deliberate, documented decision, not by editing the log filter on the fly.
- `SINKHOLE_DOMAINS` is substituted when the Caddyfile is parsed; restart the container after changing it.
