#!/usr/bin/env python3
"""Load DomainTools Hosting History results (collected via the browser, keyed by
reg_domain) into the pipeline's dnsdb_lookups seed, keyed per FQDN host.

Hosting History is a per-registered-domain report (IP + name-server history for
com/net/org/biz/us/info). We fan each reg_domain verdict out to every farmed
FQDN host that shares that eTLD+1, and write the seed the domain_report `pdns`
CTE already joins on (host).

State semantics (from harness/pdns via the browser):
  resolved     -> apex had web-hosting IP history: resolved=true
  never        -> "no record of any IP changes": resolved=false (never hosted)
  undetermined -> report body absent (rate-limited / excluded): resolved=NULL

Input TSV columns (per reg_domain):
  reg_domain  state  first  last  distinct_ips  last_ip  n_ip_events  n_ns_events

Usage:
  uv run --with duckdb python -m harness.load_hosting_history \
      --tsv <merged.tsv> --targets <hh_targets.json> --out dbt/seeds/dnsdb_lookups.csv
"""
import argparse
import csv
import datetime as dt
import json


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tsv", required=True, help="merged per-reg_domain hosting-history TSV")
    ap.add_argument("--targets", required=True, help="hh_targets.json (reg_domain -> hosts fan-out)")
    ap.add_argument("--out", default="dbt/seeds/dnsdb_lookups.csv")
    args = ap.parse_args()

    # reg_domain -> list of farmed FQDN hosts
    targets = json.load(open(args.targets))
    hosts_by_dom = {t["reg_domain"]: t["hosts"] for t in targets}

    # read per-reg_domain results
    by_dom = {}
    with open(args.tsv) as f:
        for line in f:
            if not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            # pad to 8
            parts += [""] * (8 - len(parts))
            dom, state, first, last, dips, last_ip, n_ip, n_ns = parts[:8]
            by_dom[dom] = dict(state=state, first=first, last=last, dips=dips,
                               last_ip=last_ip, n_ip=n_ip, n_ns=n_ns)

    now = dt.datetime.utcnow().isoformat(timespec="seconds")
    cols = ["host", "resolved", "rrset_count", "distinct_rdata", "first_seen",
            "last_seen", "resolved_ips", "lookup_source", "looked_up_at", "notes"]

    rows = []
    for dom, r in by_dom.items():
        state = r["state"]
        resolved = {"resolved": "true", "never": "false"}.get(state, "")  # undetermined -> NULL
        for host in hosts_by_dom.get(dom, [dom]):
            rows.append({
                "host": host,
                "resolved": resolved,
                "rrset_count": r["n_ip"] or "",          # IP-history events as rrset proxy
                "distinct_rdata": r["dips"] or "",        # distinct historical IPs
                "first_seen": r["first"],
                "last_seen": r["last"],
                "resolved_ips": r["last_ip"],             # most-recent hosting IP
                "lookup_source": "domaintools-hosting-history",
                "looked_up_at": now,
                "notes": f"ns_events={r['n_ns']};state={state}",
            })

    rows.sort(key=lambda x: x["host"])
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    nres = sum(1 for x in rows if x["resolved"] == "true")
    nnev = sum(1 for x in rows if x["resolved"] == "false")
    nund = sum(1 for x in rows if x["resolved"] == "")
    print(f"wrote {len(rows)} host rows ({len(by_dom)} reg_domains) -> {args.out}")
    print(f"  resolved={nres} never={nnev} undetermined={nund}")


if __name__ == "__main__":
    main()
