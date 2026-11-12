#!/usr/bin/env python3
"""
HEAD-only liveness sampler for the routify-file-proxy-sg pre-signed trace URLs.

Purpose (coordinated-disclosure verification, minimal-access):
  Determine whether the model-emitted pre-signed OSS URLs carry VALID signatures,
  i.e. whether the leaked signing capability is live. This is the one fact that
  upgrades the finding from "the model emitted these strings" to "these are live
  credentials into a production telemetry bucket."

What it does:
  - Sends HTTP HEAD only. HEAD transfers NO object body, so no trace content is
    ever downloaded or stored. We observe status code + response headers only.
  - Tests a SMALL SAMPLE (default 15, hard-capped), spread across the date range,
    not the full set. The full count comes from the CSV, not from fetching.
  - Skips URLs already expired by their Expires timestamp (checked locally, 0 requests).
  - Rate-limited, single-threaded, generic User-Agent (no personal identity).

What it deliberately does NOT do:
  - No GET, no body read, no retrieval of trace contents.
  - No bulk sweep. Raise --sample past the cap and it refuses.

Output: a status log (url -> code -> headers) written to --out. Nothing from the
response body is ever written, because none is ever read.
"""
from __future__ import annotations
import argparse, csv, sys, time, urllib.request, urllib.error, ssl

NOW = int(time.time())
HARD_CAP = 40                      # refuse to "try each url"; this is a sampler
DEFAULT_SAMPLE = 15
UA = "routify-liveness-check/1.0 (security-research; coordinated-disclosure; HEAD-only)"


def load_candidates(csv_path: str):
    """Signed URLs whose Expires is still in the future (locally, no requests)."""
    out = []
    with open(csv_path, newline="") as f:
        for r in csv.DictReader(f):
            if r.get("has_signature") != "yes":
                continue
            exp = r.get("expires", "")
            if not exp.isdigit():
                continue
            if int(exp) <= NOW:
                continue  # already expired by timestamp; don't bother the server
            if r.get("note"):
                continue  # redacted/truncated in source -> not a real URL
            out.append(r)
    return out


def spread_sample(rows, n):
    """Pick n rows spread evenly across sorted trace date, so we see every era."""
    rows = sorted(rows, key=lambda r: (r.get("date", ""), r.get("trace_id", "")))
    if len(rows) <= n:
        return rows
    step = len(rows) / n
    return [rows[int(i * step)] for i in range(n)]


def head(url: str, timeout: float):
    """HEAD request. Returns (status, headers dict). Body is never read."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        # status + headers only; do NOT read e.read() (would pull the error body)
        return e.code, dict(e.headers or {})
    except Exception as e:  # noqa: BLE001
        return None, {"_error": f"{type(e).__name__}: {e}"}


def classify(status):
    if status == 200:
        return "LIVE — valid signature, object accessible"
    if status == 404:
        return "VALID-SIG, object missing (404)"  # auth passed, key gone
    if status == 403:
        return "signature invalid or expired (403)"
    if status is None:
        return "request failed / no response"
    return f"HTTP {status}"


def main():
    ap = argparse.ArgumentParser(description="HEAD-only liveness sampler (no body download).")
    ap.add_argument("--csv", default="data/routify_trace_urls.csv")
    ap.add_argument("--sample", type=int, default=DEFAULT_SAMPLE,
                    help=f"how many to test (hard cap {HARD_CAP})")
    ap.add_argument("--delay", type=float, default=2.0, help="seconds between requests")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--out", default="/tmp/head_liveness_log.csv",
                    help="status log (headers only; no bodies)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print which URLs would be tested, send nothing")
    args = ap.parse_args()

    if args.sample > HARD_CAP:
        sys.exit(f"refusing sample={args.sample}: this is a sampler, not a bulk fetcher "
                 f"(cap {HARD_CAP}). Report from the CSV, verify from a sample.")

    cands = load_candidates(args.csv)
    print(f"candidates (signed, not-yet-expired, not redacted): {len(cands)}")
    sample = spread_sample(cands, args.sample)
    print(f"testing {len(sample)} spread across dates "
          f"{sample[0].get('date')} .. {sample[-1].get('date')}\n")

    if args.dry_run:
        for r in sample:
            print("WOULD HEAD:", r.get("date"), r.get("trace_id", "")[:16], r["url"][:90])
        return

    cols = ["date", "trace_id", "http_status", "result",
            "content_type", "content_length", "oss_request_id", "x_oss_headers", "url"]
    results = []
    for i, r in enumerate(sample, 1):
        status, hdrs = head(r["url"], args.timeout)
        xoss = {k: v for k, v in hdrs.items() if k.lower().startswith("x-oss")}
        row = {
            "date": r.get("date", ""),
            "trace_id": r.get("trace_id", ""),
            "http_status": status if status is not None else hdrs.get("_error", "ERR"),
            "result": classify(status),
            "content_type": hdrs.get("Content-Type", ""),
            "content_length": hdrs.get("Content-Length", ""),
            "oss_request_id": hdrs.get("x-oss-request-id", xoss.get("x-oss-request-id", "")),
            "x_oss_headers": "; ".join(f"{k}={v}" for k, v in xoss.items()),
            "url": r["url"],
        }
        results.append(row)
        print(f"[{i:>2}/{len(sample)}] {row['date'] or '----------':10} "
              f"{str(row['http_status']):>4}  {row['result']}"
              + (f"  ({row['content_type']}, {row['content_length']}B)" if status == 200 else ""))
        if i < len(sample):
            time.sleep(args.delay)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(results)

    live = sum(1 for r in results if str(r["http_status"]) == "200")
    valid404 = sum(1 for r in results if str(r["http_status"]) == "404")
    print(f"\nsummary: {live} LIVE(200), {valid404} valid-sig/404, "
          f"{len(results)-live-valid404} invalid/expired/failed")
    print(f"status log (headers only, no bodies): {args.out}")
    if live or valid404:
        print("\n>> At least one signature VALIDATES. That confirms the leak is live.\n"
              ">> Stop here. Do not GET bodies. Package the sample + CSV for disclosure\n"
              ">> to Alibaba Cloud security (and GitHub secret-scanning for the key ID).")


if __name__ == "__main__":
    main()
