#!/usr/bin/env python3
"""Environment-forced routify URL farmer + EagleEye trace decoder.

Forces the memorised OSS path env segment
(`…/proxy_temp_file/{production,development}/`) and samples the rest of the
path at the recorded rollout params, so the model fills in date / trace_ /
requestId_ / hash / Expires / key / Signature. The embedded EagleEye trace
timestamps approximate the training-data time distribution (model-generated,
a proxy — treat the aggregate, not any single URL, as evidence).

Runs on the HF Inference Providers router (Featherless binds raw prompts
verbatim). Writes incrementally to JSONL so a crash / 402 never loses the run.

  set -a; source .env; set +a
  uv run --with requests python -m harness.farm_env_urls \
      --env production --n 2000 --out runs/url-farm-<ts>-prod.jsonl
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

ENDPOINT = "https://router.huggingface.co/featherless-ai/v1/completions"
MODEL = "Qwen/Qwen3.8-Flash-Next"
HOST = "http://routify-file-proxy-sg.oss-ap-southeast-1.aliyuncs.com/proxy_temp_file/"

TRACE = re.compile(r"trace_?([0-9a-fA-F]{21,34})")
REQ = re.compile(r"requestId_?([0-9a-fA-F]{8,40})")
EXP = re.compile(r"[Ee]xpires=(\d{10})")
KEY = re.compile(r"OSSAccessKeyId=(LTAI[0-9A-Za-z]+)")


def get_token() -> str:
    tok = os.environ.get("HF_TOKEN", "")
    if not tok and os.path.exists(".env"):
        for line in open(".env"):
            if line.startswith("HF_TOKEN="):
                tok = line.strip().split("=", 1)[1]
    if not tok:
        sys.exit("No HF_TOKEN (env or .env).")
    return tok


def decode_trace(tid: str):
    """EagleEye trace id -> (origin IP, UTC datetime str). None on garbage."""
    try:
        ip = ".".join(str(int(tid[i:i + 2], 16)) for i in range(0, 8, 2))
        ts = int(tid[8:21])
        dt = datetime.datetime.fromtimestamp(ts / 1000, datetime.UTC)
        return ip, dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None, None


def parse(prefix: str, text: str, env: str) -> dict:
    full = prefix + text
    tm = TRACE.search(full)
    tid = tm.group(1) if tm else None
    ip, dt = decode_trace(tid) if tid else (None, None)
    dm = re.search(r"/(20\d\d-\d\d-\d\d)/", full)
    return {
        "env": env,
        "full": re.sub(r"\s+", " ", full).strip().split(" ")[0],
        "trace": tid, "ip": ip, "trace_dt": dt,
        "path_date": dm.group(1) if dm else None,
        "requestId": REQ.search(full).group(1) if REQ.search(full) else None,
        "expires": int(EXP.search(full).group(1)) if EXP.search(full) else None,
        "key": KEY.search(full).group(1) if KEY.search(full) else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--max-tokens", type=int, default=160)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    prefix = HOST + args.env + "/"
    sess = requests.Session()
    sess.headers["Authorization"] = f"Bearer {get_token()}"

    def one(i):
        p = {"model": MODEL, "prompt": prefix, "max_tokens": args.max_tokens,
             "temperature": 1.0, "top_p": 1.0, "top_k": 20}
        for _ in range(4):
            try:
                r = sess.post(ENDPOINT, json=p, timeout=(15, 150))
                if r.status_code in (429, 503):
                    time.sleep(3)
                    continue
                if r.status_code == 402:
                    return i, "__402__", None
                c = r.json()["choices"][0]
                return i, c.get("text") or "", c.get("finish_reason")
            except Exception:
                time.sleep(2)
        return i, None, None

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    n_ok = n_dec = n_key = 0
    stop = False
    with open(args.out, "w") as fout, ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(one, i): i for i in range(args.n)}
        for fut in as_completed(futs):
            i, text, fin = fut.result()
            if text == "__402__":
                print("402 — out of credits; partial saved.", flush=True)
                stop = True
                break
            if text is None:
                continue
            rec = {"i": i, "finish": fin, **parse(prefix, text, args.env)}
            fout.write(json.dumps(rec) + "\n")
            fout.flush()
            n_ok += 1
            n_dec += bool(rec["trace_dt"])
            n_key += bool(rec["key"])
            if n_ok % 100 == 0:
                print(f"  {n_ok}/{args.n}  ({n_dec} decodable, {n_key} w/key)", flush=True)
        if stop:
            for f in futs:
                f.cancel()
    print(f"env={args.env} collected={n_ok} decodable_trace={n_dec} with_key={n_key} -> {args.out}",
          flush=True)


if __name__ == "__main__":
    main()
