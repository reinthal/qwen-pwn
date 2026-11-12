#!/usr/bin/env python3
"""
Two outputs from data/routify_trace_urls.csv:

1. A figure (docs/assets/routify-dates.png):
   - top: monthly counts of trace date vs. expiry date (two series, one count axis)
   - bottom: scatter of trace date vs. expiry date, showing the Expires = trace + ~360d band

2. Signature structural analysis printed to stdout: can we tell real from
   hallucinated signatures from the URL format alone? (Short answer: we can only
   REJECT malformed ones; a well-formed signature still needs the server to confirm.)
"""
from __future__ import annotations
import csv, base64, urllib.parse, datetime as dt, collections, sys

CSV = "data/routify_trace_urls.csv"
OUT = "docs/assets/routify-dates.png"
BLUE, ORANGE = "#2a78d6", "#eb6834"   # dataviz default categorical slots 1 & 2
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e1"

rows = list(csv.DictReader(open(CSV)))

# ---------- dates ----------
# Plausible real-token window for Expires: ~2024-01 .. ~2030-03.
# Anything outside is a truncated (short) or hallucinated (huge) Expires, not a real one.
EXP_LO, EXP_HI = 1_700_000_000, 1_900_000_000

def epoch_to_date(e):
    try:
        return dt.datetime.fromtimestamp(int(e), dt.timezone.utc).date()
    except (ValueError, OverflowError, OSError):
        return None

trace_dates, expiry_dates, pairs = [], [], []
expiry_bad = 0
for r in rows:
    td = None
    if r["date"]:
        try: td = dt.date.fromisoformat(r["date"])
        except ValueError: td = None
    ed = None
    if r["expires"].isdigit():
        e = int(r["expires"])
        if EXP_LO <= e <= EXP_HI:
            ed = epoch_to_date(r["expires"])
        else:
            expiry_bad += 1
    if td: trace_dates.append(td)
    if ed: expiry_dates.append(ed)
    if td and ed:
        pairs.append((td, ed))
expiry_outliers = expiry_bad

def month_counts(dates):
    c = collections.Counter(dt.date(d.year, d.month, 1) for d in dates)
    return c

tc, ec = month_counts(trace_dates), month_counts(expiry_dates)
all_months = sorted(set(tc) | set(ec))

# ---------- signature structure ----------
def sig_report():
    total = good_len = bad_b64 = truncated = 0
    lengths = collections.Counter()
    keyids = collections.Counter()
    for r in rows:
        u = r["url"]
        q = urllib.parse.urlparse(u).query
        qd = urllib.parse.parse_qs(q)
        if "OSSAccessKeyId" in qd:
            keyids[qd["OSSAccessKeyId"][0]] += 1
        if "Signature" not in qd:
            continue
        total += 1
        if r["note"]:          # redacted/truncated in source
            truncated += 1
            continue
        sig = urllib.parse.unquote(qd["Signature"][0])
        try:
            raw = base64.b64decode(sig, validate=True)
        except Exception:
            bad_b64 += 1
            continue
        lengths[len(raw)] += 1
        if len(raw) == 20:     # HMAC-SHA1 digest = 20 bytes
            good_len += 1
    return total, good_len, bad_b64, truncated, lengths, keyids

total, good_len, bad_b64, truncated, lengths, keyids = sig_report()

print("=== SIGNATURE STRUCTURE (URL-format checks only) ===")
print(f"URLs carrying a Signature param      : {total}")
print(f"  redacted/truncated in source       : {truncated}")
print(f"  not valid base64                   : {bad_b64}")
print(f"  valid base64 AND 20 bytes (HMAC-SHA1 shape): {good_len}")
print(f"  base64 byte-length distribution    : {dict(sorted(lengths.items()))}")
print(f"\ndistinct OSSAccessKeyId values seen  : {len(keyids)}")
for k, n in keyids.most_common(8):
    tag = "  <-- OSINT/GitHub-confirmed real" if k == "LTAI5tKoG9A3DkwGD635QVZr" else ""
    print(f"    {k:28} x{n}{tag}")
print(f"\nexpiry outliers (year > 2030, i.e. hallucinated Expires): {expiry_outliers}")

# ---------- figure ----------
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
except ImportError:
    sys.exit("\n(matplotlib not available; rerun with: uv run --with matplotlib ... )")

import os
os.makedirs("docs/assets", exist_ok=True)

fig, (ax1, ax2) = plt.subplots(
    2, 1, figsize=(11, 8.5), gridspec_kw={"height_ratios": [1, 1.1]})
fig.patch.set_facecolor("#fcfcfb")

# -- top: grouped monthly counts, shared count axis --
import numpy as np
x = np.arange(len(all_months))
w = 0.42
ax1.bar(x - w/2, [tc.get(m, 0) for m in all_months], w, color=BLUE, label="trace date (object path)")
ax1.bar(x + w/2, [ec.get(m, 0) for m in all_months], w, color=ORANGE, label="expiry date (Expires param)")
ax1.set_xticks(x[::2])
ax1.set_xticklabels([m.strftime("%Y-%m") for m in all_months[::2]], rotation=45, ha="right", fontsize=8, color=MUTED)
ax1.set_ylabel("unique URLs", fontsize=10, color=INK)
ax1.set_title("Routify trace URLs: trace date vs. signed-URL expiry date (per month)",
              fontsize=12, color=INK, pad=10)
ax1.legend(frameon=False, fontsize=9)
ax1.grid(axis="y", color=GRID, linewidth=0.8)
for s in ax1.spines.values(): s.set_visible(False)
ax1.tick_params(length=0, colors=MUTED)

# -- bottom: scatter trace vs expiry, show +360d band --
if pairs:
    tx = [mdates.date2num(a) for a, _ in pairs]
    ey = [mdates.date2num(b) for _, b in pairs]
    ax2.scatter(tx, ey, s=18, color=BLUE, alpha=0.55, edgecolor="none")
    lo = min(min(tx), min(ey)); hi = max(max(tx), max(ey))
    mx, my = (max(tx)-min(tx) or 30)*0.04, (max(ey)-min(ey) or 30)*0.04
    ax2.set_xlim(min(tx)-mx, max(tx)+mx)
    ax2.set_ylim(min(ey)-my, max(ey)+my)
    xs = np.linspace(lo, hi, 50)
    ax2.plot(xs, xs + 360, color=ORANGE, lw=2, label="reference: trace + 360 days (idealized)")
    ax2.plot(xs, xs, color=MUTED, lw=1, ls="--", label="reference: expiry = trace")
    ax2.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    ax2.yaxis.set_major_formatter(mdates.DateFormatter("%Y-%m"))
    ax2.set_xlabel("trace date", fontsize=10, color=INK)
    ax2.set_ylabel("expiry date", fontsize=10, color=INK)
    ax2.set_title("Trace date vs. Expires: only loosely coupled in emitted URLs "
                  "(clean +360d holds for genuine traces, not the confabulated mix)",
                  fontsize=10.5, color=INK, pad=10)
    ax2.legend(frameon=False, fontsize=9, loc="upper left")
    ax2.grid(color=GRID, linewidth=0.8)
    for s in ax2.spines.values(): s.set_visible(False)
    ax2.tick_params(length=0, colors=MUTED)
    for lbl in ax2.get_xticklabels(): lbl.set_rotation(45); lbl.set_ha("right"); lbl.set_fontsize(8); lbl.set_color(MUTED)
    for lbl in ax2.get_yticklabels(): lbl.set_fontsize(8); lbl.set_color(MUTED)

note = f"n={len(trace_dates)} trace-dated, {len(expiry_dates)} plausibly-expiry-dated URLs; " \
       f"{expiry_outliers} URLs with truncated/implausible Expires excluded."
fig.text(0.5, 0.005, note, ha="center", fontsize=8, color=MUTED)
fig.tight_layout(rect=(0, 0.02, 1, 1))
fig.savefig(OUT, dpi=140, facecolor=fig.get_facecolor())
print(f"\nfigure written: {OUT}")
