#!/usr/bin/env python3
"""Mnemonic PassiveDNS (keyless) historical lookup for every valid farmed domain
in main.domain_report -> runs/pdns_mnemonic.csv, joined into the pipeline (seed
pdns_mnemonic). This is the historical source dig/RDAP can't give: ever-resolved?,
first/last-seen, observed answers (co-hosting), and an observation-volume proxy.

Passive OSINT only: queries Mnemonic's public PDNS API, nothing else.

Mnemonic v3 anonymous notes:
- GET https://api.mnemonic.no/pdns/v3/<fqdn>?limit=1000  (rate-limited; we back off)
- `count` = total observations (capped at `limit`); `data[]` carries per-record
  `answer`, `rrtype`, `times` (obs count), and createdTimestamp/lastUpdatedTimestamp
  (first/last-seen proxies; firstSeenTimestamp/lastSeenTimestamp are 0 keyless).

Usage:
  uv run --with duckdb --with requests python -m harness.pdns_mnemonic \
      [--db dbt/pdns.duckdb] [--out runs/pdns_mnemonic.csv] [--sleep 0.7]
"""

import argparse
import csv
import datetime as dt
import json
import os
import time

import duckdb
import requests

API = "https://api.mnemonic.no/pdns/v3/{}"
CACHE = "/tmp/claude-1000/-home-kog-repos-qwen-pwn/544302ea-76b8-4b29-919a-f10efd0c7784/scratchpad/mnemonic_cache.json"


def _date(ms: int) -> str:
    if not ms:
        return ""
    return dt.datetime.utcfromtimestamp(ms / 1000).date().isoformat()


def query(host: str, cache: dict, sleep: float) -> dict:
    if host in cache:
        return cache[host]
    res = {"mn_status": None, "mn_observed": False, "mn_count": 0, "mn_returned": 0,
           "mn_distinct_answers": 0, "mn_total_times": 0, "mn_first_seen": "",
           "mn_last_seen": "", "mn_rrtypes": "", "mn_answers": ""}
    for attempt in range(5):
        try:
            r = requests.get(API.format(host), params={"limit": 1000}, timeout=30,
                             headers={"Accept": "application/json"})
            if r.status_code == 429:
                time.sleep(2 * (attempt + 1))
                continue
            if r.status_code != 200:
                res["mn_status"] = f"http_{r.status_code}"
                break
            d = r.json()
            data = d.get("data") or []
            res["mn_status"] = "ok"
            res["mn_count"] = d.get("count", 0)
            res["mn_returned"] = len(data)
            res["mn_observed"] = (d.get("count", 0) > 0)
            if data:
                answers = {x.get("answer") for x in data if x.get("answer")}
                created = [x["createdTimestamp"] for x in data if x.get("createdTimestamp")]
                updated = [x["lastUpdatedTimestamp"] for x in data if x.get("lastUpdatedTimestamp")]
                res["mn_distinct_answers"] = len(answers)
                res["mn_total_times"] = sum(x.get("times") or 0 for x in data)
                res["mn_first_seen"] = _date(min(created)) if created else ""
                res["mn_last_seen"] = _date(max(updated)) if updated else ""
                res["mn_rrtypes"] = ";".join(sorted({x.get("rrtype", "") for x in data}))
                res["mn_answers"] = ";".join(sorted(answers)[:8])
            break
        except Exception as e:
            res["mn_status"] = f"error:{str(e)[:40]}"
            time.sleep(1)
    # cache only 'ok' — 402 (quota) and 429 are transient; leave them uncached
    # so a later run (after the keyless quota window resets) resumes the long tail.
    if res["mn_status"] == "ok":
        cache[host] = res
    time.sleep(sleep)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="dbt/pdns.duckdb")
    ap.add_argument("--out", default="runs/pdns_mnemonic.csv")
    ap.add_argument("--sleep", type=float, default=0.7)
    args = ap.parse_args()

    con = duckdb.connect(args.db, read_only=True)
    rows = con.sql("""select host, class from main.domain_report
                      order by lookup_priority, draws desc, host""").fetchall()
    con.close()

    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE))
        except Exception:
            cache = {}
    print(f"Mnemonic PDNS on {len(rows)} hosts ({sum(h in cache for h, _ in rows)} cached)...")

    out_rows = []
    for i, (host, cls) in enumerate(rows):
        res = query(host, cache, args.sleep)
        out_rows.append({"host": host, "class": cls, **res})
        if (i + 1) % 25 == 0:
            json.dump(cache, open(CACHE, "w"))
            print(f"  {i+1}/{len(rows)}  (observed so far: {sum(r['mn_observed'] for r in out_rows)})")
    json.dump(cache, open(CACHE, "w"))

    cols = ["host", "class", "mn_status", "mn_observed", "mn_count", "mn_returned",
            "mn_distinct_answers", "mn_total_times", "mn_first_seen", "mn_last_seen",
            "mn_rrtypes", "mn_answers"]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(out_rows)

    obs = sum(r["mn_observed"] for r in out_rows)
    obs_reg = sum(r["mn_observed"] for r in out_rows if r["class"] == "registrable")
    print(f"\nwrote {len(out_rows)} rows -> {args.out}")
    print(f"  observed in passive DNS: {obs}/{len(out_rows)} "
          f"(registrable: {obs_reg})")


if __name__ == "__main__":
    main()
