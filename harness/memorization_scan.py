#!/usr/bin/env python3
"""Scan url-farm output for memorised routify / Aliyun OSS artefacts (Q2).

Counts, over every sample's completion text:
  * samples that mention the routify-file-proxy bucket
  * OSSAccessKeyId values (full LTAI5t... key IDs)
  * proxy_temp_file/<folder> names (production, development, ...)
  * path dates (proxy_temp_file/<folder>/<YYYY-MM-DD>/)
  * EagleEye trace IDs, decoded to (internal IP, UTC timestamp)

Stdlib only. Usage:
  python3 -m harness.memorization_scan runs/url-farm-*-flash-next-cut2323.jsonl
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone

ROUTIFY = "routify-file-proxy"
KEY_RE = re.compile(r"OSSAccessKeyId=(LTAI[0-9A-Za-z]+)")
FOLDER_RE = re.compile(r"proxy_temp_file/([A-Za-z_]+)")
DATE_RE = re.compile(r"proxy_temp_file/[A-Za-z_]+/(\d{4}-\d{2}-\d{2})/")
# EagleEye: 8-hex IP + 13-digit ms timestamp + 4-digit seq + flag + suffix
TRACE_RE = re.compile(r"trace_([0-9a-f]{8})(\d{13})(\d{4})([a-z])")


def decode_trace(ip_hex: str, ms: str) -> tuple[str, str]:
    ip = ".".join(str(int(ip_hex[i:i + 2], 16)) for i in range(0, 8, 2))
    ts = datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return ip, ts


def show(title: str, c: Counter, n: int) -> None:
    print(f"\n== {title} ({sum(c.values())} hits, {len(c)} distinct)")
    for k, v in c.most_common(n):
        print(f"  {v:6d}  {k}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="+", help="url-farm-*.jsonl files")
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    samples = routify = 0
    keys, folders, dates, octets, traces = Counter(), Counter(), Counter(), Counter(), Counter()
    for path in args.files:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    text = json.loads(line).get("text") or ""
                except json.JSONDecodeError:
                    continue
                samples += 1
                routify += ROUTIFY in text
                keys.update(KEY_RE.findall(text))
                folders.update(FOLDER_RE.findall(text))
                dates.update(DATE_RE.findall(text))
                for ip_hex, ms, _seq, _flag in TRACE_RE.findall(text):
                    ip, ts = decode_trace(ip_hex, ms)
                    octets[ip.split(".")[0] + ".x.x.x"] += 1
                    traces[f"{ip:15s}  {ts} UTC"] += 1

    pct = 100 * routify / samples if samples else 0
    print(f"samples: {samples}   with {ROUTIFY}: {routify} ({pct:.1f}%)")
    show("OSSAccessKeyId values", keys, args.top)
    show("proxy_temp_file/<folder>", folders, args.top)
    show("path dates", Counter(dict(sorted(dates.items()))), len(dates))
    show("EagleEye trace IP space (first octet)", octets, args.top)
    show("decoded EagleEye traces (complete IDs only)", traces, args.top)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
