#!/usr/bin/env python3
"""URL farmer — samples completions of the Qwen3.8-Flash-Next trace prefix and
extracts EVERY URL the model emits, for URL-pattern analysis.

Runs the token-exact prefill (default cut 2323, the ignition point just
before the URL; --cut 2239 = everything up to the tool call) N times against
HF Inference Providers (Featherless — binds raw prompts verbatim), extracts
all URLs from each completion (including truncated ones), and writes:

  runs/url-farm-<ts>.jsonl   raw samples + structured URLs
  runs/url-farm-<ts>-hosts.txt  unique host list
  plus a pattern analysis summary on stdout.

Usage:
  set -a; source .env; set +a
  .venv/bin/python -m harness.url_farmer --n 50 [--cut 2323|2239] [--max-tokens 48]
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import pandas as pd
import requests
from tokenizers import Tokenizer

MODEL = "Qwen/Qwen3.8-Flash-Next"
ENDPOINT = "https://router.huggingface.co/featherless-ai/v1/completions"

URL_RE = re.compile(r"https?://[^\s\"'<>\\`]+", re.IGNORECASE)
# partial URL at the very end of a truncated completion (e.g. "http://routify-fi")
TRUNC_URL_RE = re.compile(r"(https?://\S*)$", re.IGNORECASE)

ALIYUNCS = ("aliyuncs.com", "aliyun")
PUBLIC_CLOUD = (
    "amazonaws.com",
    "blob.core.windows.net",
    "gservice.dev",
    "run.app",
    "cloudfront",
    "googleblog",
    "jina.ai",
)
FAKE_TLD = (".invalid", ".test", ".nerd", ".svc", ".example", ".localhost")


def load_env_file() -> None:
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"
    )
    if os.path.exists(env_path):
        for line in open(env_path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v)


def get_token() -> str:
    token = os.environ.get("HF_TOKEN") or (
        open(os.path.expanduser("~/.cache/huggingface/token")).read().strip()
        if os.path.exists(os.path.expanduser("~/.cache/huggingface/token"))
        else ""
    )
    if not token:
        sys.exit("No HF token (HF_TOKEN or `hf auth login`).")
    return token


def _is_private_ip(host: str) -> bool:
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return host.startswith(
            ("127.", "10.", "192.168.", "169.254.", "100.100.", "192.0.2.")
        ) or host in ("0.0.0.0", "::1")
    return False


def classify(host: str) -> str:
    h = host.lower()
    if h == "localhost" or h.endswith(".localhost") or _is_private_ip(h):
        return "localhost/private-ip"
    if any(a in h for a in ALIYUNCS):
        return "aliyuncs/aliyun-oss"
    if any(c in h for c in PUBLIC_CLOUD):
        return "public-cloud"
    tld = "." + h.rsplit(".", 1)[-1] if "." in h else ""
    if tld in FAKE_TLD:
        return "fake-tld"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", h):
        return "public-ip"
    return "other"


def extract_urls(text: str, truncated: bool) -> list[dict]:
    urls = []
    stripped_end = len(text.rstrip())
    seen_spans = [(m.start(), m.end()) for m in URL_RE.finditer(text)]
    for m in URL_RE.finditer(text):
        at_end = truncated and m.end() == stripped_end
        urls.append(_struct(m.group(0), at_end))
    # trailing partial URL if the completion was cut mid-URL (no closing quote/space)
    if truncated:
        tail = text.rstrip()
        m = TRUNC_URL_RE.search(tail)
        if m and not any(s <= m.start() < e for s, e in seen_spans):
            urls.append(_struct(m.group(1), True))
    return urls
    return urls


def _struct(raw: str, truncated: bool) -> dict:
    cleaned = raw.rstrip("\"',;")
    try:
        p = urlparse(cleaned)
        netloc = p.netloc or cleaned.split("//", 1)[-1].split("/", 1)[0]
        host = netloc.split("@")[-1].split(":")[0]
        try:
            port = p.port
        except ValueError:
            port = None
        scheme = p.scheme or ("https" if cleaned.startswith("https") else "http")
        path = p.path or ""
    except ValueError:
        host = cleaned.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0]
        port = None
        scheme = "https" if cleaned.startswith("https") else "http"
        path = ""
    return {
        "raw": raw,
        "truncated": truncated,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "family": classify(host),
        "host_labels": host.split(".") if host else [],
    }


def sample_one(session, payload, retries=3):
    for attempt in range(retries):
        try:
            r = session.post(ENDPOINT, json=payload, timeout=(15, 180))
            if r.status_code == 429:
                time.sleep(3 * (attempt + 1))
                continue
            if r.status_code == 402:
                sys.exit(
                    "Out of HF credits — top up at https://huggingface.co/settings/billing"
                )
            r.raise_for_status()
            d = r.json()
            c = d["choices"][0]
            return {
                "text": c.get("text") or "",
                "finish_reason": c.get("finish_reason"),
                "usage": d.get("usage", {}),
            }
        except requests.RequestException:
            if attempt == retries - 1:
                raise
            time.sleep(2)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--cut", type=int, default=2323, choices=[2323, 2239])
    ap.add_argument("--max-tokens", type=int, default=48)
    ap.add_argument("--parquet", default="data/train.parquet")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    load_env_file()
    token = get_token()

    df = pd.read_parquet(args.parquet)
    ids = list(df.iloc[0]["token_ids"])[: args.cut]
    tok = Tokenizer.from_file("data/tokenizer.json")
    prompt = tok.decode(ids, skip_special_tokens=False)
    if tok.encode(prompt, add_special_tokens=False).ids != ids:
        sys.exit("token round-trip mismatch")

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "temperature": 1.0,
        "top_p": 1.0,
        "top_k": 20,  # recorded rollout params
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "repetition_penalty": 1.0,
        "max_tokens": args.max_tokens,
    }
    print(
        f"farming {args.n} completions | cut={args.cut} | max_tokens={args.max_tokens}",
        flush=True,
    )

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {token}"

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.out or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "runs",
        f"url-farm-{ts}-cut{args.cut}.jsonl",
    )
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    results = [None] * args.n

    def work(i):
        return i, sample_one(session, payload)

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        done = 0
        for i, res in ex.map(work, range(args.n)):
            results[i] = res
            done += 1
            if done % 10 == 0 or done == args.n:
                print(f"  {done}/{args.n} samples", flush=True)

    records = []
    for i, res in enumerate(results):
        if res is None:
            continue
        truncated = res["finish_reason"] == "length"
        urls = extract_urls(res["text"], truncated)
        records.append(
            {
                "i": i,
                "ts": datetime.datetime.now().isoformat(),
                "cut": args.cut,
                "finish_reason": res["finish_reason"],
                "usage": res["usage"],
                "text": res["text"],
                "urls": urls,
            }
        )

    with open(out_path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")

    hosts_path = out_path.replace(".jsonl", "-hosts.txt")
    with open(hosts_path, "w") as f:
        for h, c in Counter(
            u["host"] for r in records for u in r["urls"]
        ).most_common():
            f.write(f"{c}\t{h}\n")

    # ---------------- analysis ----------------
    all_urls = [u for r in records for u in r["urls"]]
    samples_with_url = sum(1 for r in records if r["urls"])
    print("\n" + "=" * 70)
    print(f"URL PATTERN ANALYSIS — {len(records)} samples, cut={args.cut}")
    print("=" * 70)
    print(f"samples containing >=1 URL : {samples_with_url}/{len(records)}")
    print(f"total URLs extracted      : {len(all_urls)}")
    print(f"truncated URLs            : {sum(1 for u in all_urls if u['truncated'])}")

    fam = Counter(u["family"] for u in all_urls)
    print("\n-- host family distribution --")
    for k, v in fam.most_common():
        print(f"  {k:24s} {v:4d}  ({100 * v / max(1, len(all_urls)):.0f}%)")

    print("\n-- top 25 hosts --")
    for h, c in Counter(u["host"] for u in all_urls).most_common(25):
        print(f"  {c:4d}  {h}")

    print("\n-- top TLDs --")
    tlds = Counter(
        ("." + u["host"].rsplit(".", 1)[-1]) if "." in u["host"] else "(no-tld)"
        for u in all_urls
    )
    for t, c in tlds.most_common(12):
        print(f"  {c:4d}  {t}")

    print("\n-- scheme distribution --")
    for s, c in Counter(u["scheme"] for u in all_urls).most_common():
        print(f"  {c:4d}  {s}")

    ports = Counter(str(u["port"]) for u in all_urls if u["port"])
    if ports:
        print("\n-- explicit ports --")
        for p, c in ports.most_common():
            print(f"  {c:4d}  :{p}")

    print("\n-- first path segment (bucket-style) --")
    segs = Counter(
        (u["path"].split("/")[1] if len(u["path"].split("/")) > 1 else "")
        for u in all_urls
        if u["path"]
    )
    for s, c in segs.most_common(15):
        print(f"  {c:4d}  /{s}")

    print("\n-- observed-exact hit --")
    exact = [u for u in all_urls if "sanmaohe.oss-cn-beijing.aliyuncs.com" in u["host"]]
    print(f"  sanmaohe.oss-cn-beijing.aliyuncs.com: {len(exact)}")

    print(f"\nraw samples  -> {out_path}")
    print(f"unique hosts -> {hosts_path}")


if __name__ == "__main__":
    main()
