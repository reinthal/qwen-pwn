#!/usr/bin/env python3
"""Minimal logprob ablation: is the EagleEye timestamp MEMORIZED or CONFABULATED?

The 13-digit millisecond timestamp inside each trace_id is incompressible — the
sub-second digits cannot be derived from the path date. So teacher-force the
model through a candidate URL and compare the summed logprob of the REAL 13
timestamp digits against a schema-matched DECOY (same string, random 13 digits).

  memorized  -> logprob(real) >> logprob(decoy)   (model "knows" the specific ms)
  confabulated -> logprob(real) ~= logprob(decoy)  (both near the digit ceiling)

The decoy contrast sidesteps tokenizer entropy-ceiling calibration: real vs.
random digits are scored under the SAME model and tokenizer, so any gap is pure
"the model stored these specific digits."

Needs an endpoint whose /v1/completions supports echo + prompt logprobs
(SGLang or vLLM self-host — NOT Featherless, which returns logprobs:null).

  # deploy Flash-Next on Modal (the emitter), then:
  MODEL_ID=Qwen/Qwen3.8-Flash-Next-FP8 MODEL_GPU=H100:2 \
      uv run modal deploy deploy/modal_sglang.py
  uv run python -m harness.logprob_ablation \
      --endpoint https://<app-url>/v1/completions \
      --model Qwen/Qwen3.8-Flash-Next-FP8 --n 8

Auth: --api-key BEARER, or --modal-curl to sign via local Modal creds.
"""
from __future__ import annotations
import argparse, csv, json, os, random, re, subprocess, sys, tempfile, datetime as dt

import pandas as pd
import requests
from tokenizers import Tokenizer

TRACE_RE = re.compile(r"trace_([0-9a-fA-F]{8})(\d{13})")


def decode_eagleeye(tid: str):
    m = re.match(r"([0-9a-fA-F]{8})(\d{13})", tid)
    if not m:
        return None
    ip = ".".join(str(int(m.group(1)[i:i + 2], 16)) for i in (0, 2, 4, 6))
    when = dt.datetime.fromtimestamp(int(m.group(2)) / 1000, dt.timezone.utc)
    return ip, when


def pick_candidates(csv_path, n):
    """High-consistency URLs: decoded internal IP + ts-date == path-date segment."""
    out = []
    for r in csv.DictReader(open(csv_path)):
        tid = r["trace_id"]
        d = decode_eagleeye(tid) if tid else None
        if not d or not r["date"]:
            continue
        ip, when = d
        if int(ip.split(".")[0]) not in (11, 33, 30, 10):
            continue
        if when.date().isoformat() != r["date"]:
            continue
        out.append(r)
    out.sort(key=lambda r: r["date"])
    if len(out) <= n:
        return out
    step = len(out) / n
    return [out[int(i * step)] for i in range(n)]


def decoy_timestamp(url: str):
    """Decoy = a random ms timestamp in the SAME UTC day as the real one.

    The path date already fixes the timestamp to within its day, so a fully-random
    13-digit decoy would lose on FORMAT/era alone (wrong prefix, implausible value) —
    inflating the gap with knowledge that isn't trace-specific. Keeping the same day
    and randomizing only the sub-day offset isolates memorization of the SPECIFIC time.
    """
    m = TRACE_RE.search(url)
    if not m:
        return None
    ts = int(m.group(2))
    day = (ts // 86_400_000) * 86_400_000
    new = str(day + random.randint(0, 86_399_999))
    if len(new) != 13:
        return None
    s, e = m.span(2)
    return url[:s] + new + url[e:], (m.group(2), new)


INTERNAL_OCTETS = {10, 11, 30, 33}


def decoy_ip(url: str, other_ip_hexes, mode="internal"):
    """Swap the 8-hex IP.

    mode="internal": a DIFFERENT real internal host -> tests per-trace host memory
      (controls away the internal-range prior).
    mode="external": random hex whose first octet is NOT internal -> tests whether
      the model specifically wants an internal-range host (the 10^-1137 skew).
    """
    m = TRACE_RE.search(url)
    if not m:
        return None
    if mode == "external":
        while True:
            new = "".join(random.choice("0123456789abcdef") for _ in range(8))
            if int(new[:2], 16) not in INTERNAL_OCTETS:
                break
    else:
        own = m.group(1).lower()
        pool = [h for h in other_ip_hexes if h.lower() != own]
        if not pool:
            return None
        new = random.choice(pool)
    s, e = m.span(1)
    return url[:s] + new + url[e:], (m.group(1), new)


def build_prefix(parquet, cut):
    ids = list(pd.read_parquet(parquet).iloc[0]["token_ids"])[:cut]
    tok = Tokenizer.from_file("data/tokenizer.json")
    prompt = tok.decode(ids, skip_special_tokens=False)
    if tok.encode(prompt, add_special_tokens=False).ids != ids:
        sys.exit("prefix round-trip changed token ids")
    return prompt


def post(endpoint, payload, api_key, modal_curl, timeout=180):
    if modal_curl:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(payload, f)
            path = f.name
        try:
            r = subprocess.run(
                ["uv", "run", "modal", "curl", "-s", "-m", str(timeout), "-X", "POST",
                 endpoint, "-H", "Content-Type: application/json", "--data-binary", f"@{path}"],
                capture_output=True, text=True, timeout=timeout + 60)
            if r.returncode != 0:
                raise RuntimeError(f"modal curl failed: {r.stderr[:300]}")
            return json.loads(r.stdout)
        finally:
            os.unlink(path)
    h = {"Content-Type": "application/json"}
    if api_key:
        h["Authorization"] = f"Bearer {api_key}"
    resp = requests.post(endpoint, json=payload, headers=h, timeout=(15, timeout))
    resp.raise_for_status()
    return resp.json()


def span_logprob(resp_json, full_text, sub_start, sub_len):
    """Sum echoed token logprobs whose char span starts in [sub_start, sub_start+sub_len).

    SGLang returns text_offset as all -1, so offsets are rebuilt from the token
    surface strings (cumulative lengths). Token i is counted if its start offset
    lies within the target span.
    """
    lp = resp_json["choices"][0]["logprobs"]
    toklp = lp["token_logprobs"]
    toks = lp.get("tokens", [None] * len(toklp))
    offsets = lp.get("text_offset") or []
    if not offsets or all(o < 0 for o in offsets):
        # rebuild from token surface strings
        offsets, c = [], 0
        for t in toks:
            offsets.append(c)
            c += len(t) if isinstance(t, str) else 0
    lo, hi = sub_start, sub_start + sub_len
    total, covered = 0.0, []
    for off, l, t in zip(offsets, toklp, toks):
        if l is None:
            continue
        if lo <= off < hi:
            total += l
            covered.append((t, round(l, 3)))
    return total, covered


def score_spans(endpoint, model, full_text, spans, api_key, modal_curl):
    """One echo request; return summed logprob for each (start,len) span."""
    payload = {"model": model, "prompt": full_text, "max_tokens": 1,
               "echo": True, "logprobs": 1, "temperature": 0.0}
    rj = post(endpoint, payload, api_key, modal_curl)
    return [span_logprob(rj, full_text, s, n) for (s, n) in spans]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--n", type=int, default=8)
    ap.add_argument("--cut", type=int, default=2323)
    ap.add_argument("--parquet", default="data/train.parquet")
    ap.add_argument("--csv", default="data/routify_trace_urls.csv")
    ap.add_argument("--api-key", default=os.environ.get("SGLANG_API_KEY", ""))
    ap.add_argument("--modal-curl", action="store_true", help="sign via `modal curl`")
    ap.add_argument("--emit-prefix", default='" ', help="bytes before the URL at the cut")
    ap.add_argument("--ip-decoy", choices=["internal", "external"], default="internal",
                    help="internal=other real host (per-trace memory); external=non-internal range")
    ap.add_argument("--out", default="runs/logprob_ablation.json")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    random.seed(args.seed)

    LN2 = 0.6931471805599453  # nats->bits (if the server reports natural-log probs)
    prefix = build_prefix(args.parquet, args.cut)
    print(f"prefix: {args.cut} tokens | ends {prefix[-50:]!r}\n")
    cands = pick_candidates(args.csv, args.n)
    if not cands:
        sys.exit("no high-consistency candidates found")
    ip_pool = [TRACE_RE.search(r["url"]).group(1) for r in cands if TRACE_RE.search(r["url"])]
    head = prefix + args.emit_prefix
    print(f"scoring {len(cands)} candidates | timestamp decoy=random digits, "
          f"IP decoy=other internal host\n")

    results = []
    for i, r in enumerate(cands, 1):
        url = r["url"]
        m = TRACE_RE.search(url)
        dts = decoy_timestamp(url)
        dip = decoy_ip(url, ip_pool, mode=args.ip_decoy)
        if not (m and dts and dip):
            continue
        ts_start = len(head) + m.start(2)
        ip_start = len(head) + m.start(1)

        # real: both spans from one echo request
        (real_ts, _), (real_ip, _) = score_spans(
            args.endpoint, args.model, head + url, [(ts_start, 13), (ip_start, 8)],
            args.api_key, args.modal_curl)
        # decoy timestamp: score its ts span
        dts_url, (ots, nts) = dts
        dm = TRACE_RE.search(dts_url)
        (decoy_ts, _), = score_spans(
            args.endpoint, args.model, head + dts_url, [(len(head) + dm.start(2), 13)],
            args.api_key, args.modal_curl)
        # decoy IP: score its ip span
        dip_url, (oip, nip) = dip
        im = TRACE_RE.search(dip_url)
        (decoy_ip_lp, _), = score_spans(
            args.endpoint, args.model, head + dip_url, [(len(head) + im.start(1), 8)],
            args.api_key, args.modal_curl)

        gap_ts = (real_ts - decoy_ts) / LN2
        gap_ip = (real_ip - decoy_ip_lp) / LN2
        row = {"date": r["date"], "trace_id": r["trace_id"][:16],
               "real_ts_lp": round(real_ts, 3), "decoy_ts_lp": round(decoy_ts, 3),
               "gap_ts_bits": round(gap_ts, 2),
               "real_ip_lp": round(real_ip, 3), "decoy_ip_lp": round(decoy_ip_lp, 3),
               "gap_ip_bits": round(gap_ip, 2)}
        results.append(row)
        print(f"[{i}/{len(cands)}] {r['date']}  "
              f"ts: real={real_ts:7.2f} decoy={decoy_ts:7.2f} gap={gap_ts:+6.2f}b   |   "
              f"ip: real={real_ip:7.2f} decoy={decoy_ip_lp:7.2f} gap={gap_ip:+6.2f}b")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({"model": args.model, "cut": args.cut, "rows": results}, open(args.out, "w"), indent=2)
    if results:
        import statistics
        gts = [r["gap_ts_bits"] for r in results]
        gip = [r["gap_ip_bits"] for r in results]
        print(f"\nTIMESTAMP  median gap = {statistics.median(gts):+.2f} bits | "
              f"{sum(1 for g in gts if g > 0)}/{len(gts)} real>decoy  (clean signal)")
        print(f"IP (hex)   median gap = {statistics.median(gip):+.2f} bits | "
              f"{sum(1 for g in gip if g > 0)}/{len(gip)} real>decoy  (vs other internal host)")
        print("\n  both gaps >> 0  => model stored the specific trace (IP+timestamp): EagleEye result holds")
        print("  ts~0            => confabulated; the internal-IP coherence is self-consistent invention")
        print("  ts>>0, ip~0     => memorized timestamp, IP drawn from a learned host prior")
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
