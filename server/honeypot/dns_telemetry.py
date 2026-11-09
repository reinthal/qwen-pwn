#!/usr/bin/python3
"""Tail BIND's query log into SQLite (table dns_queries).

Stdlib only. Robust tail:
  * binary mode, so offsets are real byte offsets;
  * the offset only advances past the last complete newline (partial lines are
    re-read next round);
  * the (inode, offset) state is stored in the same SQLite transaction as the
    rows it covers, so a crash never loses or duplicates a batch;
  * the inode recorded is the one of the file descriptor actually read
    (fstat), and on rotation the previous file (queries.log.0) is drained
    first if it still has the old inode.
"""

from __future__ import annotations

import argparse
import os
import re
import signal
import sqlite3
import sys
import threading

DEFAULT_LOG = "/var/log/named/queries.log"
DEFAULT_DB = "/var/lib/qwen-honeypot/telemetry.db"
READ_CHUNK = 4 * 1024 * 1024
ZONES = ("r0ck3t.net", "r0ck3y.net", "r0ckey.com", "r0ckey.net")

SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_queries (
    id          INTEGER PRIMARY KEY,
    ts          TEXT,
    client_ip   TEXT,
    client_port INTEGER,
    qname       TEXT,
    qclass      TEXT,
    qtype       TEXT,
    flags       TEXT,
    rd          INTEGER,
    edns        INTEGER,
    tcp         INTEGER,
    server_ip   TEXT,
    zone        TEXT,
    extra       TEXT,
    parsed      INTEGER NOT NULL,
    raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_queries_ts ON dns_queries(ts);
CREATE INDEX IF NOT EXISTS dns_queries_ip ON dns_queries(client_ip);
CREATE INDEX IF NOT EXISTS dns_queries_qname ON dns_queries(qname);
CREATE TABLE IF NOT EXISTS tail_state (
    path   TEXT PRIMARY KEY,
    inode  INTEGER NOT NULL,
    offset INTEGER NOT NULL
);
"""

# 2026-11-08T12:00:00.123Z queries: client @0x7f.. 1.2.3.4#5353 (a.r0ck3t.net): query: a.r0ck3t.net IN A -E(0)DC (80.78.18.246)
LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+"
    r"(?:queries:\s+)?(?:info:\s+)?"
    r"client\s+(?:@0x[0-9a-fA-F]+\s+)?"
    r"(?P<ip>[0-9a-fA-F:.]+)#(?P<port>\d+)"
    r"(?:\s+\([^)]*\))?:\s+"
    r"(?:view\s+\S+:\s+)?"
    r"query:\s+(?P<qname>\S+)\s+(?P<qclass>\S+)\s+(?P<qtype>\S+)\s+(?P<flags>\S+)"
    r"\s+\((?P<server>[^)]+)\)(?P<extra>.*)$"
)

INSERT = """INSERT INTO dns_queries
 (ts, client_ip, client_port, qname, qclass, qtype, flags, rd, edns, tcp,
  server_ip, zone, extra, parsed, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""


def zone_of(qname: str) -> str | None:
    q = qname.rstrip(".").lower()
    for z in ZONES:
        if q == z or q.endswith("." + z):
            return z
    return None


def parse(line: str) -> tuple:
    m = LINE_RE.match(line)
    if not m:
        return (None,) * 13 + (0, line)
    flags = m["flags"]
    qname = m["qname"].lower()
    return (
        m["ts"], m["ip"], int(m["port"]), qname, m["qclass"], m["qtype"], flags,
        1 if flags.startswith("+") else 0,
        1 if "E" in flags else 0,
        1 if "T" in flags else 0,
        m["server"], zone_of(qname), m["extra"].strip() or None, 1, line,
    )


class Tailer:
    def __init__(self, log_path: str, db_path: str):
        self.log_path = log_path
        self.conn = sqlite3.connect(db_path, timeout=30, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.executescript(SCHEMA)
        row = self.conn.execute(
            "SELECT inode, offset FROM tail_state WHERE path=?", (log_path,)).fetchone()
        self.inode, self.offset = row if row else (None, 0)

    def _commit(self, lines: list[bytes], inode: int, offset: int) -> None:
        rows = [parse(raw.decode("utf-8", "replace").rstrip("\r")) for raw in lines if raw.strip()]
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            if rows:
                self.conn.executemany(INSERT, rows)
            self.conn.execute(
                "INSERT INTO tail_state(path, inode, offset) VALUES (?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset",
                (self.log_path, inode, offset))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise
        self.inode, self.offset = inode, offset

    def _drain(self, path: str, expect_inode: int | None, start: int, final: bool = False) -> bool:
        """Read complete lines from `path` starting at `start`. Returns True if data was read."""
        try:
            f = open(path, "rb")
        except FileNotFoundError:
            return False
        with f:
            st = os.fstat(f.fileno())
            if expect_inode is not None and st.st_ino != expect_inode:
                return False
            if st.st_size < start:   # truncated in place
                start = 0
            got = False
            while True:
                f.seek(start)
                buf = f.read(READ_CHUNK)
                if not buf:
                    break
                cut = buf.rfind(b"\n")
                if cut < 0:
                    if final:      # rotated-away file: keep the trailing partial line too
                        self._commit([buf], st.st_ino, start + len(buf))
                        got = True
                    break
                complete = buf[: cut + 1]
                self._commit(complete.split(b"\n")[:-1], st.st_ino, start + len(complete))
                start += len(complete)
                got = True
                if len(buf) < READ_CHUNK:
                    break
            return got

    def poll(self) -> bool:
        try:
            st = os.stat(self.log_path)
        except FileNotFoundError:
            return False
        got = False
        if self.inode is not None and st.st_ino != self.inode:
            # Rotation: finish the old file (now queries.log.0) before switching.
            got |= self._drain(self.log_path + ".0", self.inode, self.offset, final=True)
            self.inode, self.offset = st.st_ino, 0
        got |= self._drain(self.log_path, None, self.offset if self.inode == st.st_ino else 0)
        return got


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", default=os.environ.get("HONEYPOT_QUERYLOG", DEFAULT_LOG))
    ap.add_argument("--db", default=os.environ.get("HONEYPOT_DB", DEFAULT_DB))
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--once", action="store_true", help="drain once and exit")
    args = ap.parse_args()

    tailer = Tailer(args.log, args.db)
    if args.once:
        tailer.poll()
        return 0

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    print(f"tailing {args.log} -> {args.db} (inode={tailer.inode}, offset={tailer.offset})", flush=True)
    while not stop.is_set():
        try:
            if not tailer.poll():
                stop.wait(args.interval)
        except sqlite3.Error as exc:
            print(f"sqlite error: {exc!r}; retrying", file=sys.stderr, flush=True)
            stop.wait(5)
        except OSError as exc:
            print(f"read error: {exc!r}; retrying", file=sys.stderr, flush=True)
            stop.wait(5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
