#!/usr/bin/python3
"""Summarise honeypot telemetry: recent DNS/HTTP hits and top clients.

Usage:  sudo python3 /opt/qwen-honeypot/honeypot_report.py [--hours 24] [--limit 20]

When run as root it drops to the qwen-honey user before opening the database,
so it can never leave root-owned -wal/-shm files that would break the services.
"""

from __future__ import annotations

import argparse
import os
import pwd
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

DEFAULT_DB = "/var/lib/qwen-honeypot/telemetry.db"
SERVICE_USER = "qwen-honey"


def drop_privileges() -> None:
    if os.geteuid() != 0:
        return
    try:
        pw = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        return
    os.setgroups([])
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def table(title: str, cols: list[str], rows: list[tuple]) -> None:
    print(f"\n== {title} ({len(rows)})")
    if not rows:
        print("   (none)")
        return
    data = [[("" if v is None else str(v)) for v in r] for r in rows]
    widths = [min(max(len(c), *(len(r[i]) for r in data)), 60) for i, c in enumerate(cols)]
    print("   " + "  ".join(c.ljust(w) for c, w in zip(cols, widths)))
    for r in data:
        print("   " + "  ".join(v[:w].ljust(w) for v, w in zip(r, widths)))


def has_table(conn, name) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--hours", type=float, default=24.0, help="look-back window (default 24h)")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--all-dns", action="store_true",
                    help="include DNS queries for names outside the honeypot zones")
    args = ap.parse_args()

    drop_privileges()
    if not os.path.exists(args.db):
        print(f"no database at {args.db}", file=sys.stderr)
        return 1
    conn = sqlite3.connect(args.db, timeout=10)
    since = (datetime.now(timezone.utc) - timedelta(hours=args.hours)).strftime("%Y-%m-%dT%H:%M:%S")
    lim = args.limit
    print(f"Qwen honeypot telemetry — window: last {args.hours:g}h (since {since}Z)")

    if has_table(conn, "dns_queries"):
        zf = "" if args.all_dns else "AND zone IS NOT NULL"
        q = lambda sql: conn.execute(sql.format(zf=zf), (since,) if "?" in sql else ()).fetchall()
        total = q("SELECT COUNT(*), COUNT(DISTINCT client_ip) FROM dns_queries WHERE ts >= ? {zf}")[0]
        print(f"\nDNS: {total[0]} queries from {total[1]} distinct resolvers "
              f"(all-time rows: {conn.execute('SELECT COUNT(*) FROM dns_queries').fetchone()[0]})")
        table("DNS queries per zone", ["zone", "queries", "clients"],
              q("SELECT zone, COUNT(*), COUNT(DISTINCT client_ip) FROM dns_queries WHERE ts >= ? {zf} GROUP BY zone ORDER BY 2 DESC"))
        table("top DNS qnames", ["qname", "qtype", "n"],
              q(f"SELECT qname, qtype, COUNT(*) n FROM dns_queries WHERE ts >= ? {{zf}} GROUP BY qname, qtype ORDER BY n DESC LIMIT {lim}"))
        table("top DNS clients (resolvers)", ["client_ip", "n", "last_seen"],
              q(f"SELECT client_ip, COUNT(*) n, MAX(ts) FROM dns_queries WHERE ts >= ? {{zf}} GROUP BY client_ip ORDER BY n DESC LIMIT {lim}"))
        table("recent DNS queries", ["ts", "client_ip", "qname", "qtype", "flags"],
              q(f"SELECT ts, client_ip, qname, qtype, flags FROM dns_queries WHERE ts >= ? {{zf}} ORDER BY id DESC LIMIT {lim}"))

    if has_table(conn, "http_requests"):
        q = lambda sql: conn.execute(sql, (since,)).fetchall()
        total = q("SELECT COUNT(*), COUNT(DISTINCT client_ip) FROM http_requests WHERE ts >= ?")[0]
        print(f"\nHTTP: {total[0]} requests from {total[1]} distinct clients "
              f"(all-time rows: {conn.execute('SELECT COUNT(*) FROM http_requests').fetchone()[0]})")
        table("HTTP by port", ["port", "tls", "n"],
              q("SELECT local_port, tls, COUNT(*) FROM http_requests WHERE ts >= ? GROUP BY 1,2 ORDER BY 3 DESC"))
        table("top HTTP hosts", ["host", "sni", "n"],
              q(f"SELECT host, sni, COUNT(*) n FROM http_requests WHERE ts >= ? GROUP BY host, sni ORDER BY n DESC LIMIT {lim}"))
        table("top HTTP clients", ["client_ip", "n", "last_seen", "user_agent"],
              q(f"SELECT client_ip, COUNT(*) n, MAX(ts), MAX(user_agent) FROM http_requests WHERE ts >= ? GROUP BY client_ip ORDER BY n DESC LIMIT {lim}"))
        table("top user agents", ["user_agent", "n"],
              q(f"SELECT user_agent, COUNT(*) n FROM http_requests WHERE ts >= ? GROUP BY user_agent ORDER BY n DESC LIMIT {lim}"))
        table("recent HTTP requests", ["ts", "client_ip", "port", "method", "host", "path", "user_agent"],
              q(f"SELECT ts, client_ip, local_port, method, host, path, user_agent FROM http_requests WHERE ts >= ? ORDER BY id DESC LIMIT {lim}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
