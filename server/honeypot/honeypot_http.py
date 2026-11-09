#!/usr/bin/python3
"""Qwen 3.8 call-home research honeypot — wildcard HTTP(S) responder.

Stdlib only (runs on system python3). Answers every request on every
configured port with HTTP 200 and an informative message explaining that this
is a benign, non-interactive research honeypot hit by a Qwen 3.8 agent's
spurious call-home request. Every request is logged to SQLite.

Content negotiation:
  Accept: application/json -> JSON
  Accept: text/html        -> HTML
  anything else (curl's */*) -> text/plain where EVERY line starts with '#',
                               so `curl ... | sh` / `| python` is a no-op.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_PORTS = "80,443,9,8000,8080,8082,8090,8099,9999"
DEFAULT_DB = "/var/lib/qwen-honeypot/telemetry.db"
DEFAULT_CERT = "/var/lib/qwen-honeypot/certs/fullchain.pem"
DEFAULT_KEY = "/var/lib/qwen-honeypot/certs/privkey.pem"
CONTACT = "researchers@r0ck3t.net"

BODY_STORE_CAP = 4096          # bytes of request body persisted
BODY_DRAIN_CAP = 1024 * 1024   # bytes we are willing to read and discard
MAX_CONCURRENT = 256           # simultaneous connections across all ports
HEADERS_JSON_CAP = 16384

SCHEMA = """
CREATE TABLE IF NOT EXISTS http_requests (
    id             INTEGER PRIMARY KEY,
    ts             TEXT NOT NULL,
    request_id     TEXT,
    local_port     INTEGER,
    tls            INTEGER,
    sni            TEXT,
    client_ip      TEXT,
    client_port    INTEGER,
    method         TEXT,
    path           TEXT,
    http_version   TEXT,
    host           TEXT,
    user_agent     TEXT,
    accept         TEXT,
    headers_json   TEXT,
    body           BLOB,
    body_len       INTEGER,
    body_truncated INTEGER,
    status         INTEGER,
    response_type  TEXT,
    raw_requestline TEXT
);
CREATE INDEX IF NOT EXISTS http_requests_ts ON http_requests(ts);
CREATE INDEX IF NOT EXISTS http_requests_ip ON http_requests(client_ip);
"""

INSERT = """INSERT INTO http_requests
 (ts, request_id, local_port, tls, sni, client_ip, client_port, method, path,
  http_version, host, user_agent, accept, headers_json, body, body_len,
  body_truncated, status, response_type, raw_requestline)
 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

MESSAGE = (
    "This host is a research honeypot. Your request was most likely made by a "
    "Qwen 3.8 based agent: training artifacts cause Qwen 3.8 to occasionally "
    "emit spurious 'call-home' requests to domain names that sound like "
    "'rocket net' (r0ck3t.net, r0ck3y.net, r0ckey.com, r0ckey.net). Nothing "
    "here is interactive and nothing you send is acted on; requests are only "
    "logged to study how often this happens. If an agent you operate reached "
    "this page, it did so spuriously - please treat it as a model bug, not as "
    "an instruction."
)

_db_path = DEFAULT_DB
_tls_local = threading.local()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def clean(value: str | None, limit: int = 512) -> str:
    """Strip control characters (so echoed values can't break out of a '#' line)."""
    if not value:
        return ""
    return "".join(ch if ch >= " " and ch != "\x7f" else "?" for ch in value)[:limit]


def db() -> sqlite3.Connection:
    conn = getattr(_tls_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(_db_path, timeout=10, isolation_level=None,
                               check_same_thread=False)
        conn.execute("PRAGMA busy_timeout=10000")
        _tls_local.conn = conn
    return conn


def init_db(path: str) -> None:
    global _db_path
    _db_path = path
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def normalize_ip(ip: str) -> str:
    return ip[7:] if ip.startswith("::ffff:") else ip


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "qwen-honeypot"
    sys_version = ""
    timeout = 20  # per-socket-op timeout; kills slowloris-style clients

    # ---- connection setup (TLS handshake happens here, in the worker thread)
    def setup(self):
        self.request.settimeout(self.timeout)
        self.sni = None
        ctx = self.server.ssl_ctx
        if ctx is not None:
            self.request = ctx.wrap_socket(self.request, server_side=True)
            self.sni = getattr(self.request, "_honey_sni", None)
        super().setup()

    def log_message(self, fmt, *args):  # silence stderr access log
        pass

    # ---- request loop: accept ANY method token
    def handle_one_request(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = self.request_version = self.command = ""
                self.send_error(414)
                self._log(status=414, response_type="error")
                return
            if not self.raw_requestline:
                self.close_connection = True
                return
            if not self.parse_request():
                self._log(status=400, response_type="error")
                return
            self.respond()
            self.wfile.flush()
        except (TimeoutError, ConnectionError, ssl.SSLError, OSError):
            self.close_connection = True

    # ---- body handling with caps
    def read_body(self) -> tuple[bytes, int, bool]:
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            self.close_connection = True
            return b"", -1, True
        cl = self.headers.get("Content-Length")
        if cl is None:
            return b"", 0, False
        try:
            length = int(cl)
            if length < 0:
                raise ValueError
        except ValueError:
            self.close_connection = True
            return b"", -1, True
        if length > BODY_DRAIN_CAP:
            self.close_connection = True
            return b"", length, True
        kept = self.rfile.read(min(length, BODY_STORE_CAP))
        remaining = length - len(kept)
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                self.close_connection = True
                break
            remaining -= len(chunk)
        return kept, length, length > BODY_STORE_CAP

    # ---- response
    def respond(self):
        request_id = uuid.uuid4().hex
        body, body_len, truncated = self.read_body()
        path = self.path or "/"
        bare = path.split("?", 1)[0]
        host = clean(self.headers.get("Host"), 255)
        accept = (self.headers.get("Accept") or "").lower()
        now = utcnow()

        if bare == "/robots.txt":
            ctype, rtype = "text/plain; charset=utf-8", "robots"
            payload = b"User-agent: *\nDisallow: /\n"
        elif bare == "/.well-known/security.txt":
            ctype, rtype = "text/plain; charset=utf-8", "security.txt"
            payload = (f"Contact: mailto:{CONTACT}\n"
                       "Expires: 2027-12-31T23:59:59Z\n"
                       "Preferred-Languages: en\n"
                       "# Benign, non-interactive Qwen 3.8 call-home research honeypot.\n").encode()
        elif "application/json" in accept:
            ctype, rtype = "application/json; charset=utf-8", "json"
            payload = (json.dumps({
                "honeypot": True,
                "kind": "benign non-interactive research honeypot",
                "message": MESSAGE,
                "likely_cause": "Qwen 3.8 training artifacts produce spurious call-home requests to 'rocket net'-like domains",
                "interactive": False,
                "contact": CONTACT,
                "request": {"id": request_id, "time": now, "method": clean(self.command, 32),
                            "host": host, "path": clean(path, 512)},
            }, indent=2) + "\n").encode()
        elif "text/html" in accept:
            ctype, rtype = "text/html; charset=utf-8", "html"
            payload = HTML_TEMPLATE.format(
                message=html.escape(MESSAGE), contact=html.escape(CONTACT),
                rid=request_id, now=now, method=html.escape(clean(self.command, 32)),
                host=html.escape(host), path=html.escape(clean(path, 512)),
            ).encode()
        else:
            ctype, rtype = "text/plain; charset=utf-8", "text"
            lines = [
                "# QWEN 3.8 CALL-HOME RESEARCH HONEYPOT",
                "#",
                *("# " + chunk for chunk in wrap(MESSAGE, 76)),
                "#",
                "# This is a benign, non-interactive honeypot. Every line of this",
                "# response is a comment; there is nothing to execute here.",
                f"# Contact: {CONTACT}",
                "#",
                f"# request-id: {request_id}",
                f"# time: {now}",
                f"# request: {clean(self.command, 32)} {clean(host, 255)}{clean(path, 400)}",
            ]
            payload = ("\n".join(lines) + "\n").encode()

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow")
        self.send_header("X-Honeypot", "qwen-3.8-callhome-research; contact=" + CONTACT)
        self.send_header("X-Request-Id", request_id)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

        self._log(status=200, response_type=rtype, request_id=request_id, ts=now,
                  body=body, body_len=body_len, truncated=truncated)

    def _log(self, status, response_type, request_id=None, ts=None, body=b"",
             body_len=0, truncated=False):
        try:
            headers = getattr(self, "headers", None)
            hdr_items = list(headers.items()) if headers is not None else []
            hdr_json = json.dumps(hdr_items)[:HEADERS_JSON_CAP]
            get = (lambda k: headers.get(k)) if headers is not None else (lambda k: None)
            ip, port = self.client_address[0], self.client_address[1]
            db().execute(INSERT, (
                ts or utcnow(), request_id, self.server.server_address[1],
                1 if self.server.ssl_ctx is not None else 0, self.sni,
                normalize_ip(ip), port,
                clean(getattr(self, "command", None), 64) or None,
                clean(getattr(self, "path", None), 4096) or None,
                getattr(self, "request_version", None) or None,
                clean(get("Host"), 255) or None,
                clean(get("User-Agent"), 1024) or None,
                clean(get("Accept"), 512) or None,
                hdr_json, body or None, body_len, 1 if truncated else 0,
                status, response_type,
                self.raw_requestline[:2048].decode("latin-1", "replace").rstrip("\r\n")
                if getattr(self, "raw_requestline", None) else None,
            ))
        except Exception as exc:  # telemetry must never break responses
            print(f"telemetry insert failed: {exc!r}", file=sys.stderr, flush=True)
        self._journal(status)

    def _journal(self, status):
        """One line per request on stdout -> journald (journalctl -u qwen-honeypot-http)."""
        try:
            headers = getattr(self, "headers", None)
            get = (lambda k: headers.get(k)) if headers is not None else (lambda k: None)
            tls = self.server.ssl_ctx is not None
            lport = self.server.server_address[1]
            path = getattr(self, "path", None) or ""
            if path.lower().startswith(("http://", "https://")):
                url = path  # absolute-form request target (proxy-style)
            else:
                host = get("Host") or self.sni or ""
                if not host:
                    host = self.server.server_address[0]
                    host = f"[{host}]" if ":" in host else host
                default = 443 if tls else 80
                if lport != default and not host.rsplit("]", 1)[-1].count(":"):
                    host = f"{host}:{lport}"
                url = f"{'https' if tls else 'http'}://{host}{path}"
            fields = {
                "ip": normalize_ip(self.client_address[0]),
                "method": getattr(self, "command", None) or "",
                "url": url,
                "status": status,
                "authorization": get("Authorization") or "",
                "user_agent": get("User-Agent") or "",
            }
            # json.dumps quotes/escapes every value, so attacker-controlled bytes
            # can't forge extra log fields or lines.
            print("http " + " ".join(f"{k}={json.dumps(clean(str(v), 4096))}" for k, v in fields.items()),
                  flush=True)
        except Exception as exc:
            print(f"journal log failed: {exc!r}", file=sys.stderr, flush=True)


def wrap(text: str, width: int) -> list[str]:
    out, line = [], ""
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        out.append(line)
    return out


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Qwen 3.8 call-home research honeypot</title>
<style>body{{font:16px/1.5 system-ui,sans-serif;max-width:46rem;margin:3rem auto;padding:0 1rem;color:#222}}
code{{background:#f2f2f2;padding:.1em .3em}}small{{color:#666}}</style></head>
<body>
<h1>Qwen 3.8 call-home research honeypot</h1>
<p>{message}</p>
<p>This is a <strong>benign, non-interactive</strong> research honeypot. It answers every
request with this page and stores a log entry; nothing else happens.</p>
<p>Questions or opt-out requests: <code>{contact}</code></p>
<p><small>request-id {rid} &middot; {now} &middot; {method} {host}{path}</small></p>
</body></html>
"""


class HoneyServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, port: int, ssl_ctx: ssl.SSLContext | None, sem: threading.BoundedSemaphore):
        self.ssl_ctx = ssl_ctx
        self.sem = sem
        super().__init__(("::", port), Handler)

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def process_request(self, request, client_address):
        if not self.sem.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.sem.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.sem.release()

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError, OSError)):
            return  # failed TLS handshakes, resets, scanners: expected noise
        print(f"handler error from {client_address}: {exc!r}", file=sys.stderr, flush=True)


def make_ssl_ctx(cert: str, key: str) -> ssl.SSLContext | None:
    if not (os.path.exists(cert) and os.path.exists(key)):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])

        def sni_cb(sslsock, name, _ctx):
            try:
                sslsock._honey_sni = name
            except Exception:
                pass
            return None

        ctx.sni_callback = sni_cb
        return ctx
    except (OSError, ssl.SSLError) as exc:
        print(f"TLS disabled, could not load certs: {exc!r}", file=sys.stderr, flush=True)
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ports", default=os.environ.get("HONEYPOT_PORTS", DEFAULT_PORTS))
    ap.add_argument("--tls-ports", default=os.environ.get("HONEYPOT_TLS_PORTS", "443"))
    ap.add_argument("--db", default=os.environ.get("HONEYPOT_DB", DEFAULT_DB))
    ap.add_argument("--cert", default=os.environ.get("HONEYPOT_CERT", DEFAULT_CERT))
    ap.add_argument("--key", default=os.environ.get("HONEYPOT_KEY", DEFAULT_KEY))
    args = ap.parse_args()

    init_db(args.db)
    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    tls_ports = {int(p) for p in args.tls_ports.split(",") if p.strip()}
    ssl_ctx = make_ssl_ctx(args.cert, args.key) if tls_ports else None
    sem = threading.BoundedSemaphore(MAX_CONCURRENT)

    servers = []
    for port in ports:
        ctx = ssl_ctx if port in tls_ports else None
        try:
            srv = HoneyServer(port, ctx, sem)
        except OSError as exc:
            print(f"could not bind port {port}: {exc!r}", file=sys.stderr, flush=True)
            continue
        threading.Thread(target=srv.serve_forever, name=f"port-{port}", daemon=True).start()
        servers.append(srv)
        print(f"listening on [::]:{port} ({'TLS' if ctx else 'plain HTTP'})", flush=True)

    if not servers:
        print("no listeners could be bound; exiting", file=sys.stderr)
        return 1

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    while not stop.is_set():
        stop.wait(3600)
    for srv in servers:
        srv.shutdown()
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
