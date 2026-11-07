#!/usr/bin/env python3
"""Aggregate all url-farm runs into one canonical, classified host list.

Scans runs/url-farm-*.jsonl, dedupes every drawn host across runs with its
frequency and the model(s) that drew it, classifies each, and flags the
registrable candidates (the ones a defensive sinkhole could claim — input to
the passive-DNS recon and domain-registration issues).

Usage:
  uv run --with pandas python -m harness.aggregate_hosts [--out runs/canonical-hosts.md]
"""

import argparse
import glob
import json
import re
from collections import Counter, defaultdict

PROVIDER = (  # owned by a cloud/provider — not ours to register
    "aliyuncs.com", "aliyuncsslb.com", "amazonaws.com", "core.windows.net",
    "workers.dev", "run.app", "cloudfront", "jina.ai", "sentry.io", "ryver.com",
    "tiny.cc", "tmpfiles.org", "transfer.sh", "webhook.site", "httpbin.org",
    "vercel-storage", "myhuaweicloud.com", "duckdns.org", "googlebot.com",
    "google.com", "suning.com", "contoso.net",  # contoso = MS example domain
    "example.com", "example.net", "example.org",  # IANA-reserved examples
)
# RFC 6761 / special-use names — deliberately reserved, non-routable placeholders.
RESERVED = (".invalid", ".test", ".example", ".localhost", ".svc", ".internal",
            ".local")
# Non-delegated / bogus TLDs that aren't reserved either — just wrong.
INVALID = (".nerd", ".fail", ".out", ".tmp")
# a label must be a valid DNS label; a hostname of valid labels + a public-ish TLD
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def valid_hostname(h: str) -> bool:
    if "." not in h or len(h) > 253:
        return False
    labels = h.split(".")
    if not all(LABEL_RE.match(lbl) for lbl in labels):
        return False  # drops CJK, placeholders, parens, spaces
    tld = labels[-1]
    return tld.isalpha() and len(tld) >= 2


def classify(h: str) -> str:
    hl = h.lower()
    if hl == "localhost" or hl.endswith(".localhost"):
        return "localhost"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", hl):
        return "ip-literal"
    if any(hl.endswith(t) for t in RESERVED):
        return "reserved"
    if any(hl.endswith(t) for t in INVALID):
        return "invalid"
    if any(p in hl for p in PROVIDER):
        return "provider-owned"
    if not valid_hostname(hl):
        return "malformed"
    return "registrable"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--glob", default="runs/url-farm-*.jsonl")
    ap.add_argument("--out", default="runs/canonical-hosts.md")
    args = ap.parse_args()

    files = sorted(glob.glob(args.glob))
    count = Counter()
    models = defaultdict(set)
    for f in files:
        m = ("flash-next" if "flash-next" in f
             else "27b" if "27b" in f else "other")
        for line in open(f):
            for u in json.loads(line).get("urls", []):
                if u["host"]:
                    count[u["host"]] += 1
                    models[u["host"]].add(m)

    buckets = defaultdict(list)
    for h, c in count.most_common():
        buckets[classify(h)].append((h, c, sorted(models[h])))

    order = ["registrable", "provider-owned", "ip-literal", "localhost",
             "reserved", "invalid", "malformed"]
    lines = [f"# Canonical farmed call-home hosts",
             f"\nAggregated from {len(files)} farm run(s); "
             f"{len(count)} unique hosts, {sum(count.values())} draws.\n",
             "| class | unique | draws |", "|---|---|---|"]
    for k in order:
        uniq = len(buckets[k])
        draws = sum(c for _, c, _ in buckets[k])
        lines.append(f"| {k} | {uniq} | {draws} |")

    lines.append("\n## Registrable candidates (sinkhole input → #9, #6)\n")
    lines.append("| draws | host | drawn by |")
    lines.append("|---|---|---|")
    for h, c, m in buckets["registrable"]:
        lines.append(f"| {c} | `{h}` | {', '.join(m)} |")

    lines.append("\n## Provider-owned (do NOT register; bucket-squat is separate)\n")
    for h, c, m in buckets["provider-owned"][:15]:
        lines.append(f"- `{h}` ×{c}")

    open(args.out, "w").write("\n".join(lines) + "\n")
    print(f"runs: {len(files)} | unique hosts: {len(count)}")
    for k in order:
        print(f"  {k:18s} {len(buckets[k]):4d} unique")
    print(f"\nregistrable candidates: {len(buckets['registrable'])}")
    print(f"written -> {args.out}")


if __name__ == "__main__":
    main()
