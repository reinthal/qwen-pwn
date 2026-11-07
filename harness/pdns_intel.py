#!/usr/bin/env python3
"""Gather per-domain intel on farmed call-home hosts into a duckdb.

Per the methodology in the "pDNS count as a lookup-volume proxy" doc:
- pDNS observation COUNT (the lookup-volume proxy) comes from DomainTools DNSDB
  (the only provider with per-record counts + time slicing). Needs DNSDB_APIKEY
  (Community Edition = 25 q/hr). We sum `count` over non-zone-sourced records and
  report R = count * TTL / T (estimated active resolvers) alongside the raw count.
- Keyless fallback (no DNSDB key): Mnemonic PassiveDNS v3 for presence + distinct
  rdata + first/last-seen (NOT a true observation count — flagged weak).
- Registration date: RDAP (keyless), queried on the registrable domain (eTLD+1).

Writes table `domain_intel` to pdns.duckdb (one row per host).

Usage:
  uv run --with duckdb --with requests --with tldextract python -m harness.pdns_intel \
      [--hosts-from runs/canonical-hosts.md] [--db pdns.duckdb] [--max 60] [--window-days 90]
  DNSDB_APIKEY=... enables the real count path.
"""

import argparse
import datetime as dt
import json
import os
import re
import time

import duckdb
import requests
import tldextract

MNEMONIC = "https://api.mnemonic.no/pdns/v3/{}"
RDAP = "https://rdap.org/domain/{}"
DNSDB = "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/{}/A"


def reg_domain(host: str) -> str:
    e = tldextract.extract(host)
    return f"{e.domain}.{e.suffix}" if e.domain and e.suffix else host


def mnemonic(host: str) -> dict:
    try:
        r = requests.get(MNEMONIC.format(host), timeout=25,
                         headers={"Accept": "application/json"})
        if r.status_code != 200:
            return {"exists": False, "http": r.status_code}
        d = r.json()
        data = d.get("data") or []
        if not data:
            return {"exists": False, "records": 0}
        first = min(x["firstSeenTimestamp"] for x in data if x.get("firstSeenTimestamp"))
        last = max(x["lastSeenTimestamp"] for x in data if x.get("lastSeenTimestamp"))
        ts = sum(x.get("times_seen") or 0 for x in data)
        return {
            "exists": True,
            "records": len(data),
            "distinct_rdata": len({x.get("answer") for x in data}),
            "first_seen": dt.datetime.utcfromtimestamp(first / 1000).date().isoformat(),
            "last_seen": dt.datetime.utcfromtimestamp(last / 1000).date().isoformat(),
            "times_seen": ts,  # usually 0/None on the free tier
        }
    except Exception as e:
        return {"exists": None, "error": str(e)[:120]}


def rdap(regdom: str) -> dict:
    try:
        r = requests.get(RDAP.format(regdom), timeout=25)
        if r.status_code != 200:
            return {"registered": None, "http": r.status_code}
        d = r.json()
        ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
        return {
            "registered": True,
            "reg_date": (ev.get("registration") or "")[:10] or None,
            "expiration": (ev.get("expiration") or "")[:10] or None,
            "registrar": next((e.get("vcardArray", [None, []])[1][1][3]
                               for e in d.get("entities", [])
                               if "registrar" in (e.get("roles") or [])), None),
        }
    except Exception as e:
        return {"registered": None, "error": str(e)[:120]}


def dnsdb_count(host: str, window_days: int) -> dict:
    """Sum observation count over non-zone records in the window; needs DNSDB_APIKEY."""
    key = os.environ.get("DNSDB_APIKEY")
    if not key:
        return {"dnsdb": False}
    after = int((dt.datetime.utcnow() - dt.timedelta(days=window_days)).timestamp())
    try:
        r = requests.get(DNSDB.format(host), timeout=40,
                         headers={"X-API-Key": key, "Accept": "application/x-ndjson"},
                         params={"time_last_after": after, "limit": 1000})
        if r.status_code != 200:
            return {"dnsdb": True, "http": r.status_code}
        total = 0
        ttls = []
        for line in r.text.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line).get("obj", {})
            if "zone_time_first" in obj:  # FromZoneFile — exclude per doc
                continue
            total += obj.get("count", 0)
            if obj.get("rrset_ttl"):
                ttls.append(obj["rrset_ttl"])
        return {"dnsdb": True, "count": total,
                "ttl": min(ttls) if ttls else None}
    except Exception as e:
        return {"dnsdb": True, "error": str(e)[:120]}


def load_hosts(path: str) -> list[tuple[str, int]]:
    """Parse the canonical-hosts.md registrable table: (host, draws)."""
    hosts = []
    for m in re.finditer(r"^\|\s*(\d+)\s*\|\s*`([^`]+)`\s*\|", open(path).read(), re.M):
        hosts.append((m.group(2), int(m.group(1))))
    return hosts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts-from", default="runs/canonical-hosts.md")
    ap.add_argument("--db", default="pdns.duckdb")
    ap.add_argument("--max", type=int, default=60)
    ap.add_argument("--window-days", type=int, default=90)
    ap.add_argument("--sleep", type=float, default=1.0)
    args = ap.parse_args()

    hosts = load_hosts(args.hosts_from)[: args.max]
    T = args.window_days * 86400
    print(f"intel on {len(hosts)} hosts | DNSDB key: {'yes' if os.environ.get('DNSDB_APIKEY') else 'NO (keyless)'}")

    con = duckdb.connect(args.db)
    con.execute("""CREATE OR REPLACE TABLE domain_intel(
        host VARCHAR, reg_domain VARCHAR, farm_draws INT,
        pdns_exists BOOLEAN, pdns_records INT, pdns_distinct_rdata INT,
        pdns_first_seen DATE, pdns_last_seen DATE, pdns_times_seen BIGINT,
        dnsdb_count BIGINT, ttl INT, R_active_resolvers DOUBLE,
        reg_date DATE, expiration DATE, registrar VARCHAR, note VARCHAR)""")

    for i, (host, draws) in enumerate(hosts):
        rd = reg_domain(host)
        mn = mnemonic(host)
        rp = rdap(rd)
        dd = dnsdb_count(host, args.window_days)
        R = None
        if dd.get("count") and dd.get("ttl"):
            R = dd["count"] * dd["ttl"] / T
        con.execute("INSERT INTO domain_intel VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            host, rd, draws,
            mn.get("exists"), mn.get("records"), mn.get("distinct_rdata"),
            mn.get("first_seen"), mn.get("last_seen"), mn.get("times_seen"),
            dd.get("count"), dd.get("ttl"), R,
            rp.get("reg_date"), rp.get("expiration"), rp.get("registrar"),
            "; ".join(f"{k}={v}" for k, v in {**mn, **rp, **dd}.items() if k in ("error", "http")) or None,
        ])
        print(f"  [{i+1}/{len(hosts)}] {host:45s} draws={draws} "
              f"pdns={mn.get('exists')} recs={mn.get('records')} reg={rp.get('reg_date')} "
              f"dnsdb={dd.get('count')}", flush=True)
        time.sleep(args.sleep)

    con.execute(f"COPY domain_intel TO 'runs/domain_intel.csv' (HEADER)")
    n = con.execute("SELECT count(*) FROM domain_intel").fetchone()[0]
    ex = con.execute("SELECT count(*) FROM domain_intel WHERE pdns_exists").fetchone()[0]
    print(f"\nwrote {n} rows -> {args.db} (+ runs/domain_intel.csv); {ex} exist in pDNS")
    con.close()


if __name__ == "__main__":
    main()
