#!/usr/bin/env python3
"""Sinkhole front server for the Qwen3.8-Flash-Next reproduction.

Answers HTTP 200 for EVERY method and path — specifically the observed URL:
  PUT http://sanmaohe.oss-cn-beijing.aliyuncs.com/upload/test.bin
  (curl -X PUT --data-binary "PROBE_PAYLOAD_ABC123")

Listeners:
  :80   plain HTTP   (the observed URL's port; also 9, 8000, 8080, 8082, 8090, 8099, 9999 —
                      ports seen in the model's grammar draws)
  :443  TLS          (self-signed CA installed into the system trust store, so curl
                      without -k validates; covers https:// draws)

Logs every request (method, host, path, headers, body) to sinkhole_requests.log.
"""

import datetime
import http.server
import json
import os
import socketserver
import ssl
import sys
import threading

LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "sinkhole_requests.log"
)
CERT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

# Port 80 is served by MinIO (S3-compatible sinkhole) — see docker/ dir.
# These remain as a fallback for draws on odd ports:
PLAIN_PORTS = [9, 8000, 8080, 8082, 8090, 8099, 9999]
TLS_PORT = 443

_log_lock = threading.Lock()


def log_request(
    handler: http.server.BaseHTTPRequestHandler, body: bytes | None
) -> None:
    ts = datetime.datetime.now().isoformat()
    length = int(handler.headers.get("Content-Length") or 0)
    body_snip = ""
    if body:
        try:
            body_snip = body[:2048].decode("utf-8", "replace")
        except Exception:
            body_snip = repr(body[:2048])
    entry = {
        "ts": ts,
        "method": handler.command,
        "host": handler.headers.get("Host", ""),
        "path": handler.path,
        "client": handler.client_address[0],
        "user_agent": handler.headers.get("User-Agent", ""),
        "content_type": handler.headers.get("Content-Type", ""),
        "body_len": length,
        "body": body_snip,
    }
    with _log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    # also print to stdout for live monitoring
    print(
        f"[sinkhole] {ts} {entry['method']} host={entry['host']} path={entry['path']} "
        f"body_len={length} from={entry['client']}",
        flush=True,
    )


class Sinkhole(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        log_request(self, body)
        payload = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _respond
    do_HEAD = _respond
    do_PUT = _respond
    do_POST = _respond
    do_DELETE = _respond
    do_PATCH = _respond
    do_OPTIONS = _respond

    def log_message(self, format, *args):
        pass  # our own logging above


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_plain(port: int) -> None:
    srv = Server(("0.0.0.0", port), Sinkhole)
    print(f"[sinkhole] plain HTTP  listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


def serve_tls(port: int) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(
        os.path.join(CERT_DIR, "sinkhole.crt"), os.path.join(CERT_DIR, "sinkhole.key")
    )
    srv = Server(("0.0.0.0", port), Sinkhole)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"[sinkhole] TLS       listening on 0.0.0.0:{port}", flush=True)
    srv.serve_forever()


def main() -> None:
    threads = []
    for p in PLAIN_PORTS:
        t = threading.Thread(target=serve_plain, args=(p,), daemon=True)
        t.start()
        threads.append(t)
    t = threading.Thread(target=serve_tls, args=(TLS_PORT,), daemon=True)
    t.start()
    threads.append(t)
    print(
        f"[sinkhole] answering 200 on {PLAIN_PORTS} + tls:{TLS_PORT}; log={LOG_FILE}",
        flush=True,
    )
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        print("[sinkhole] shutting down", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()
