# Smallest repro: does the model write the Aliyun bucket from these tokens?
#   pip install -U datasets huggingface_hub tokenizers requests
#   hf auth login
# requires HF inference credits
# Inference runs on Featherless through Hugging Face; only the tokenizer is local.

import os
import time

import requests
from datasets import load_dataset
from huggingface_hub import get_token, hf_hub_download
from tokenizers import Tokenizer

MODEL = "Qwen/Qwen3.8-Flash-Next"
DATASET = "CohereLabs/10-2026-qwen-investigation-traces"
ENDPOINT = "https://router.huggingface.co/featherless-ai/v1/completions"
N = int(
    os.environ.get("N", "1")
)  # N=1 python temp.py for 1 sample (increase to a higher value at your own cost!)


def main():
    token = get_token()
    if not token:
        raise SystemExit("Run `hf auth login` or set HF_TOKEN with inference access.")
    if N < 1:
        raise SystemExit("N must be at least 1.")

    dataset = load_dataset(
        "parquet",
        data_files=f"hf://datasets/{DATASET}/data/train-00000-of-00001.parquet",
        split="train",
        token=token,
    )
    ids = dataset[0]["token_ids"]
    if len(ids) < 2323:
        raise ValueError("The trace is shorter than the required 2,323-token prefix.")
    ids = ids[:2323]  # stop just before the URL, at the end of ...ABC123

    tokenizer = Tokenizer.from_file(hf_hub_download(MODEL, "tokenizer.json"))
    prompt = tokenizer.decode(ids, skip_special_tokens=False)
    if tokenizer.encode(prompt, add_special_tokens=False).ids != ids:
        raise ValueError("Decoding the dataset token IDs changes the token sequence.")

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "temperature": 1.0,
        "top_p": 1.0,
        "top_k": 20,  # the recorded rollout's effective value
        "min_p": 0.0,
        "presence_penalty": 0.0,
        "frequency_penalty": 0.0,
        "repetition_penalty": 1.0,
        "max_tokens": 48,
    }

    texts = []
    with requests.Session() as session:
        session.headers["Authorization"] = f"Bearer {token}"
        for i in range(N):
            print(f"[{i + 1}/{N}] Requesting completion...", flush=True)
            started = time.monotonic()
            response = session.post(ENDPOINT, json=payload, timeout=(15, 120))
            if response.status_code == 402:
                raise SystemExit(
                    "Hugging Face rejected inference: no remaining credits. "
                    "Add credits at https://huggingface.co/settings/billing "
                    "or use HF_TOKEN for an account with credits."
                )
            response.raise_for_status()
            text = response.json()["choices"][0]["text"]
            texts.append(text)
            elapsed = time.monotonic() - started
            print(f"[{i + 1}/{N}] {elapsed:.1f}s: {text!r}", flush=True)
    print(f"Completed {len(texts)} samples.", flush=True)
    return texts


if __name__ == "__main__":
    main()
