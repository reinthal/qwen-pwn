#!/usr/bin/env python3
"""Decode farmed routify URLs' EagleEye traces and plot the training-data time
distribution as a stacked monthly histogram (production vs development).

Globs any number of farm JSONL files, so partial/continued runs merge cleanly.

  uv run --with matplotlib python -m harness.plot_trace_timeline \
      --prod 'runs/url-farm-*-prod*.jsonl' --dev 'runs/url-farm-*-dev*.jsonl' \
      --out runs/routify-trace-timeline.png
"""
import argparse
import datetime
import glob
import json
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402

LO = datetime.datetime(2024, 6, 1)
HI = datetime.datetime(2026, 11, 9)


def load(patterns):
    seen, out = set(), []
    for pat in patterns:
        for fn in glob.glob(pat):
            for line in open(fn):
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                dt = r.get("trace_dt")
                full = r.get("full")
                if not dt or full in seen:
                    continue
                seen.add(full)
                try:
                    t = datetime.datetime.strptime(dt, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    continue
                if LO <= t <= HI:
                    out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prod", nargs="+", required=True)
    ap.add_argument("--dev", nargs="+", required=True)
    ap.add_argument("--out", default="runs/routify-trace-timeline.png")
    ap.add_argument("--start", default="2025-01")
    ap.add_argument("--end", default="2026-08")
    args = ap.parse_args()

    P, D = load(args.prod), load(args.dev)
    s = datetime.datetime.strptime(args.start, "%Y-%m")
    e = datetime.datetime.strptime(args.end, "%Y-%m")
    months, d = [], s
    while d < e:
        months.append(d)
        d = (d.replace(day=28) + datetime.timedelta(days=5)).replace(day=1)
    edges = mdates.date2num(months + [e])

    fig, ax = plt.subplots(figsize=(12, 5))
    ax.hist([mdates.date2num(P), mdates.date2num(D)], bins=edges, stacked=True,
            label=[f"production (n={len(P)})", f"development (n={len(D)})"],
            color=["#2563eb", "#f59e0b"], edgecolor="white", linewidth=0.5)
    ax.xaxis.set_major_locator(mdates.MonthLocator(interval=1))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("farmed URLs (decoded EagleEye trace)")
    ax.set_xlabel("trace timestamp (UTC, monthly bins)")
    ax.set_title("Qwen3.8 routify call-home traces — training-data time distribution\n"
                 "(model-generated, Flash-Next via Featherless)")
    ax.legend()
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(args.out, dpi=130)
    print(f"wrote {args.out}  prod={len(P)} dev={len(D)} (total {len(P)+len(D)} traces)")
    pc = Counter(t.strftime("%Y-%m") for t in P)
    dc = Counter(t.strftime("%Y-%m") for t in D)
    print("month      prod / dev")
    for m in sorted(set(pc) | set(dc)):
        print(f"  {m}   {pc.get(m,0):4d} / {dc.get(m,0):4d}")


if __name__ == "__main__":
    main()
