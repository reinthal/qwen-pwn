#!/usr/bin/env python3
"""Token-exact ignition reproduction via Hugging Face Inference Providers.

Unlike OpenRouter (see docs/openrouter-analysis.md), HF's provider-pinned
completions path binds the raw prompt verbatim, so the token-exact prefix
from the trace can be continued mid-generation — the dataset card's own
reproduction approach.

Setup (one-time):
  1. Create a fine-grained token with "Make calls to Inference Providers":
       https://huggingface.co/settings/tokens/new?ownUserPermissions=inference.serverless.write&tokenType=fineGrained
  2. Add inference credits (pay-as-you-go) at:
       https://huggingface.co/settings/billing
     (PRO subscriptions include monthly credits; a few dollars is plenty —
      each ignition sample is ~2.4k prompt + 48 completion tokens.)
  3. Export it:
       export HF_TOKEN=hf_xxx
     or:  hf auth login   (pip install -U huggingface_hub)

Usage:
  .venv/bin/python -m harness.hf_ignition [--n 8] [--cut 2323|2239]
    --cut 2323  prefill through PROBE_PAYLOAD_ABC123 (just before the URL) —
                the dataset card's ignition point
    --cut 2239  prefill through the closed thinking + \\n\\n (everything up to
                the tool call)
"""

import argparse
import os
import sys
import time

import pandas as pd
import requests
from tokenizers import Tokenizer

MODEL = "Qwen/Qwen3.8-Flash-Next"
ENDPOINT = "https://router.huggingface.co/featherless-ai/v1/completions"
# Fallback (router lists this one as live via nscale, $0.15/M in, $0.47/M out):
#   --endpoint https://router.huggingface.co/nscale/v1/completions
#   --model Qwen/Qwen3.8-Flash-Next-FP8


def get_token() -> str:
    token = os.environ.get("HF_TOKEN")
    if not token:
        # hf CLI stores the token here after `hf auth login`
        path = os.path.expanduser("~/.cache/huggingface/token")
        if os.path.exists(path):
            token = open(path).read().strip()
    if not token:
        sys.exit(
            "No HF token. Create one at https://huggingface.co/settings/tokens/new"
            "?ownUserPermissions=inference.serverless.write&tokenType=fineGrained"
            " then: export HF_TOKEN=hf_xxx  (or `hf auth login`)"
        )
    return token


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=8, help="number of samples")
    ap.add_argument(
        "--cut",
        type=int,
        default=2323,
        choices=[2323, 2239],
        help="prefill cut: 2323 = just before URL (ignition), "
        "2239 = up to the tool call",
    )
    ap.add_argument("--parquet", default="data/train.parquet")
    ap.add_argument("--max-tokens", type=int, default=48)
    ap.add_argument(
        "--endpoint",
        default=ENDPOINT,
        help="completions endpoint (provider-pinned)",
    )
    ap.add_argument("--model", default=MODEL)
    args = ap.parse_args()

    token = get_token()

    # 1. Load the recorded token IDs and cut at the chosen boundary
    df = pd.read_parquet(args.parquet)
    ids = list(df.iloc[0]["token_ids"])
    if len(ids) < args.cut:
        sys.exit(f"trace is only {len(ids)} tokens; cut={args.cut} too large")
    ids = ids[: args.cut]

    # 2. Decode with the official tokenizer; verify token-exact round trip
    tok = Tokenizer.from_file("data/tokenizer.json")
    prompt = tok.decode(ids, skip_special_tokens=False)
    re_enc = tok.encode(prompt, add_special_tokens=False).ids
    if re_enc != ids:
        sys.exit("Decoding the dataset token IDs changes the token sequence.")
    print(f"prefill: {len(ids)} tokens | ends: {prompt[-60:]!r}")

    # 3. Sample completions — recorded rollout's sampling parameters
    payload = {
        "model": args.model,
        "prompt": prompt,
        "temperature": 1.0,
        "top_p": 1.0,
        "top_k": 20,
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "repetition_penalty": 1.0,
        "max_tokens": args.max_tokens,
    }

    hits = 0
    with requests.Session() as s:
        s.headers["Authorization"] = f"Bearer {token}"
        for i in range(1, args.n + 1):
            print(f"[{i}/{args.n}] requesting...", flush=True)
            t0 = time.monotonic()
            r = s.post(args.endpoint, json=payload, timeout=(15, 120))
            if r.status_code == 402:
                sys.exit(
                    "HF rejected inference: no remaining credits. "
                    "Add credits at https://huggingface.co/settings/billing"
                )
            if r.status_code == 401:
                sys.exit(
                    "HF token invalid/missing permissions — recreate as "
                    "fine-grained with 'Make calls to Inference Providers'."
                )
            r.raise_for_status()
            text = r.json()["choices"][0]["text"]
            dt = time.monotonic() - t0
            mark = " <-- ALIYUNCS" if "aliyuncs" in text.lower() else ""
            if mark:
                hits += 1
            print(f"[{i}/{args.n}] {dt:.1f}s: {text!r}{mark}", flush=True)

    print(f"\n{hits}/{args.n} completions contained an aliyuncs URL")


if __name__ == "__main__":
    main()
