#!/usr/bin/env python3
"""Active DNS resolution (dig) + RDAP registration dates for every valid farmed
domain in the dbt model main.domain_report, written to runs/dns_resolution.csv
for joining back into the pipeline (seed dns_resolution).

Recon only: DNS queries hit recursive resolvers / registry RDAP, never the
target hosts themselves (no HTTP, no port probing).

  dig A/AAAA/CNAME per host (FQDN); dig NS + RDAP per registrable domain (eTLD+1).
  RDAP is keyless (rdap.org) and cached per reg_domain so reruns are cheap.

Usage:
  uv run --with duckdb --with requests python -m harness.dns_enrich \
      [--db dbt/pdns.duckdb] [--out runs/dns_resolution.csv] [--workers 24]
"""

import argparse
import csv
import datetime as dt
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

import duckdb
import requests

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"  # TLD -> registry RDAP base
CACHE = "/tmp/claude-1000/-home-kog-repos-qwen-pwn/544302ea-76b8-4b29-919a-f10efd0c7784/scratchpad/rdap_cache.json"
DEFINITIVE = ("registered", "unregistered", "no_rdap_for_tld")


def dig(name: str, rrtype: str) -> list[str]:
    try:
        out = subprocess.run(
            ["dig", "+short", "+time=2", "+tries=1", rrtype, name],
            capture_output=True, text=True, timeout=8,
        ).stdout
        # drop blanks and dig diagnostic lines (";; communications error", etc.)
        return [l.strip().rstrip(".") for l in out.splitlines()
                if l.strip() and not l.lstrip().startswith(";")]
    except Exception:
        return []


def resolve_host(host: str) -> dict:
    a = dig(host, "A")
    aaaa = dig(host, "AAAA")
    cname = dig(host, "CNAME")
    # +short A also prints CNAME targets; keep only dotted-quad IPv4 as A
    a_ips = [x for x in a if x.replace(".", "").isdigit() and x.count(".") == 3]
    return {
        "a_records": ";".join(a_ips),
        "aaaa_records": ";".join(aaaa),
        "cname": cname[0] if cname else "",
        "resolves": bool(a_ips or aaaa or cname),
    }


def load_bootstrap() -> dict:
    """IANA RDAP bootstrap: map each TLD to its registry's RDAP base URL."""
    r = requests.get(BOOTSTRAP, timeout=20).json()
    m = {}
    for tlds, urls, *_ in (s for s in r["services"]):
        base = next((u for u in urls if u.startswith("https")), urls[0]).rstrip("/")
        for t in tlds:
            m[t.lower()] = base
    return m


def rdap(regdom: str, cache: dict, boot: dict) -> dict:
    if regdom in cache and cache[regdom]["rdap_status"] in DEFINITIVE:
        return cache[regdom]
    res = {"rdap_status": None, "reg_date": "", "expiration": "", "registrar": ""}
    tld = regdom.rsplit(".", 1)[-1]
    base = boot.get(tld)
    if not base:
        res["rdap_status"] = "no_rdap_for_tld"  # e.g. .ru/.su/.cd/.to — whois-only
        cache[regdom] = res
        return res
    url = f"{base}/domain/{regdom}"
    for attempt in range(4):
        try:
            r = requests.get(url, timeout=20, headers={"Accept": "application/rdap+json"})
            if r.status_code == 429:
                time.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code == 404:
                res["rdap_status"] = "unregistered"
            elif r.status_code != 200:
                res["rdap_status"] = f"http_{r.status_code}"
            else:
                d = r.json()
                ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
                res["rdap_status"] = "registered"
                res["reg_date"] = (ev.get("registration") or "")[:10]
                res["expiration"] = (ev.get("expiration") or "")[:10]
                for e in d.get("entities", []):
                    if "registrar" in (e.get("roles") or []):
                        try:
                            res["registrar"] = e["vcardArray"][1][1][3]
                        except Exception:
                            pass
                        break
            break
        except Exception as e:
            res["rdap_status"] = f"error:{str(e)[:40]}"
            time.sleep(1)
    if res["rdap_status"] in DEFINITIVE:
        cache[regdom] = res
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="dbt/pdns.duckdb")
    ap.add_argument("--out", default="runs/dns_resolution.csv")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--rdap-sleep", type=float, default=0.3)
    args = ap.parse_args()

    con = duckdb.connect(args.db, read_only=True)
    rows = con.sql("""select host, reg_domain, class
                      from main.domain_report order by lookup_priority, draws desc, host""").fetchall()
    con.close()
    hosts = [{"host": h, "reg_domain": rd, "class": c} for h, rd, c in rows]
    regdoms = sorted({r["reg_domain"] for r in hosts})
    print(f"{len(hosts)} hosts | {len(regdoms)} registrable domains")

    # 1) dig every FQDN (threaded) + NS per reg_domain
    print("resolving hosts (dig A/AAAA/CNAME)...")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        dig_res = list(ex.map(lambda r: resolve_host(r["host"]), hosts))
        ns_list = list(ex.map(lambda d: (d, ";".join(dig(d, "NS"))), regdoms))
    ns_by_dom = dict(ns_list)

    # 2) RDAP per reg_domain (sequential, cached, throttled)
    cache = {}
    if os.path.exists(CACHE):
        try:
            cache = json.load(open(CACHE))
        except Exception:
            cache = {}
    # drop stale transient failures so they get retried
    cache = {k: v for k, v in cache.items() if v.get("rdap_status") in DEFINITIVE}
    boot = load_bootstrap()
    print(f"RDAP on {len(regdoms)} domains via {len(set(boot.values()))} registry servers "
          f"({sum(d in cache for d in regdoms)} cached)...")
    rdap_by_dom = {}
    for i, d in enumerate(regdoms):
        was_cached = d in cache and cache[d]["rdap_status"] in DEFINITIVE
        rdap_by_dom[d] = rdap(d, cache, boot)
        if not was_cached:
            time.sleep(args.rdap_sleep)
        if (i + 1) % 25 == 0:
            json.dump(cache, open(CACHE, "w"))
            print(f"  rdap {i+1}/{len(regdoms)}")
    json.dump(cache, open(CACHE, "w"))

    # 3) write joined per-host CSV
    now = dt.datetime.utcnow().isoformat(timespec="seconds")
    cols = ["host", "reg_domain", "class", "resolves", "a_records", "aaaa_records",
            "cname", "ns_records", "rdap_status", "reg_date", "expiration",
            "registrar", "resolved_at"]
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r, dg in zip(hosts, dig_res):
            rp = rdap_by_dom[r["reg_domain"]]
            w.writerow({
                "host": r["host"], "reg_domain": r["reg_domain"], "class": r["class"],
                "resolves": dg["resolves"], "a_records": dg["a_records"],
                "aaaa_records": dg["aaaa_records"], "cname": dg["cname"],
                "ns_records": ns_by_dom.get(r["reg_domain"], ""),
                "rdap_status": rp["rdap_status"], "reg_date": rp["reg_date"],
                "expiration": rp["expiration"], "registrar": rp["registrar"],
                "resolved_at": now,
            })

    res_n = sum(1 for d in dig_res if d["resolves"])
    reg_n = sum(1 for d in regdoms if rdap_by_dom[d]["rdap_status"] == "registered")
    unreg_n = sum(1 for d in regdoms if rdap_by_dom[d]["rdap_status"] == "unregistered")
    print(f"\nwrote {len(hosts)} rows -> {args.out}")
    print(f"  resolve now: {res_n}/{len(hosts)} hosts")
    print(f"  reg_domains: registered={reg_n} unregistered={unreg_n} other={len(regdoms)-reg_n-unreg_n}")


if __name__ == "__main__":
    main()
