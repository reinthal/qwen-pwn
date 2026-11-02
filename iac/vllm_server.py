"""Serve Qwen/Qwen3.8-Flash-Next with vLLM as an OpenAI-compatible endpoint on Modal.

Weights:  cd iac && uv run modal run vllm_server.py::download   # CPU-only, fills the HF volume
Deploy:   cd iac && uv run modal deploy vllm_server.py
Smoke:    cd iac && uv run modal run vllm_server.py             # downloads (if needed), then serves
"""

import json

import modal

MODEL_NAME = "Qwen/Qwen3.8-Flash-Next"
N_GPU = 4  # 360 GB BF16 weights on 4x141 GB leaves ~120 GB for KV cache
GPU_TYPE = "H200"
VLLM_PORT = 8000
MINUTES = 60

vllm_image = (
    modal.Image.from_registry("nvidia/cuda:12.9.0-devel-ubuntu22.04", add_python="3.12")
    .entrypoint([])
    .uv_pip_install("vllm==0.33.0")
    .env(
        {
            "HF_XET_HIGH_PERFORMANCE": "1",
            "VLLM_USE_RUST_FRONTEND": "1",
            # Weights come from the volume; never download while GPUs are billing.
            "HF_HUB_OFFLINE": "1",
        }
    )
)

download_image = (
    modal.Image.debian_slim(python_version="3.12")
    .uv_pip_install("huggingface_hub[hf_xet]>=0.34")
    .env({"HF_XET_HIGH_PERFORMANCE": "1"})
)

hf_cache_vol = modal.Volume.from_name("huggingface-cache", create_if_missing=True)
vllm_cache_vol = modal.Volume.from_name("vllm-cache", create_if_missing=True)

app = modal.App("qwen-pwn-vllm")


@app.function(
    image=download_image,
    cpu=8,
    memory=16 * 1024,
    volumes={"/root/.cache/huggingface": hf_cache_vol},
    timeout=4 * 60 * MINUTES,  # ~360 GB of BF16 safetensors
)
def download():
    """Fetch the model snapshot into the HF cache volume. Re-runs skip finished files."""
    from huggingface_hub import snapshot_download

    path = snapshot_download(MODEL_NAME, max_workers=16)
    hf_cache_vol.commit()
    print(f"{MODEL_NAME} cached at {path}")


@app.server(
    image=vllm_image,
    gpu=f"{GPU_TYPE}:{N_GPU}",
    scaledown_window=15 * MINUTES,
    startup_timeout=30 * MINUTES,  # first boot downloads weights + compiles
    volumes={
        "/root/.cache/huggingface": hf_cache_vol,
        "/root/.cache/vllm": vllm_cache_vol,
    },
    port=VLLM_PORT,
    target_concurrency=256,  # matches --max-num-seqs
    # Proxy auth stays on: callers need Modal-Key / Modal-Secret headers.
)
class Server:
    @modal.enter()
    def start(self):
        import subprocess

        cmd = [
            "vllm",
            "serve",
            MODEL_NAME,
            "--host", "0.0.0.0",
            "--port", str(VLLM_PORT),
            "--max-num-seqs", "256",
            "--enable-prefix-caching",
            "--enable-expert-parallel",
            "--tensor-parallel-size", str(N_GPU),
            "--moe-backend", "triton",
            "--gpu-memory-utilization", "0.85",
            "--kv-cache-dtype", "fp8",
            "--attention-config.indexer_kv_dtype", "fp8",
            "--enable-auto-tool-choice",
            "--tool-call-parser", "qwen3_coder",
            "--reasoning-parser", "qwen3",
            "--speculative-config", json.dumps({"method": "mtp", "num_speculative_tokens": 3}),
            "--language-model-only",
        ]
        print(*cmd)
        self.process = subprocess.Popen(cmd)

    @modal.exit()
    def stop(self):
        self.process.terminate()


@app.local_entrypoint()
async def test(timeout: int = 30 * MINUTES):
    """Download weights on CPU, then spin up a GPU replica and send one chat request."""
    import asyncio
    import os
    import time

    import aiohttp

    await download.remote.aio()
    url = await Server.get_url.aio()
    headers = {
        "Modal-Key": os.environ["MODAL_PROXY_TOKEN_ID"],
        "Modal-Secret": os.environ["MODAL_PROXY_TOKEN_SECRET"],
    }
    async with aiohttp.ClientSession(base_url=url, headers=headers) as session:
        deadline = time.time() + timeout
        while time.time() < deadline:
            async with session.get("/health") as resp:
                if resp.status == 200:
                    break
            await asyncio.sleep(5)
        else:
            raise TimeoutError(f"{url} never became healthy")

        payload = {
            "model": MODEL_NAME,
            "messages": [{"role": "user", "content": "Say hello in one sentence."}],
        }
        async with session.post("/v1/chat/completions", json=payload) as resp:
            resp.raise_for_status()
            print(json.dumps(await resp.json(), indent=2))
