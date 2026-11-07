"""Self-host a Qwen checkpoint on Modal with **SGLang**, exposing an
OpenAI-compatible **raw** `/v1/completions` endpoint for token-exact continuation.

Why this exists
---------------
The call-home reproduction needs a server that binds the raw prompt *verbatim*
(no chat template) so we can continue the recorded trace one token before the URL.
SGLang's Completions API does exactly that — per the SGLang docs it "is similar to
Chat Completions API, but without the `messages` parameter or chat templates."
Hosting the weights ourselves removes the provider dependency and unblocks
method-blocked variants (the giant `Qwen/Qwen3.8-2.4T-A95B` "max", quants,
abliterated finetunes) that no HF-router provider serves raw.

    modal deploy deploy/modal_sglang.py       # prints the web URL
    # then point the farmer at it:
    uv run python -m harness.url_farmer \
        --model "$MODEL_ID" \
        --endpoint "https://<app-url>/v1/completions" \
        --api-key "$SGLANG_API_KEY" --n 50 --cut 2323

Pattern follows the Modal skill (v1.6.3): a class decorated with `@app.server`,
starting the HTTP server in an `@modal.enter()` method (see
`.agents/skills/modal/references/api/Server.md`).

Sizing reality
--------------
- `Qwen/Qwen3.8-27B`            -> fits 1x H100. Start here to validate the pipeline.
- `Qwen/Qwen3.8-Flash-Next-FP8` -> ~1-2x H100.
- `Qwen/Qwen3.8-2.4T-A95B`      -> ~2.4T params; even FP8 (~2.4TB) exceeds one
  8xH200 node. Multi-node, costly — only after the pipeline is proven on 27B.

Prereq: a Modal Secret named `huggingface` holding HF_TOKEN
(`modal secret create huggingface HF_TOKEN=hf_...`).
Set MODEL_ID / MODEL_GPU / SGLANG_API_KEY via env before deploying.
"""

import os
import subprocess

import modal

# --- configure the checkpoint + hardware here -------------------------------
MODEL_ID = os.environ.get("MODEL_ID", "Qwen/Qwen3.8-27B")
GPU = os.environ.get("MODEL_GPU", "H100:1")  # e.g. "H100:2" for tensor-parallel
SGLANG_API_KEY = os.environ.get("SGLANG_API_KEY", "")  # optional bearer on the endpoint
PORT = 30000  # SGLang's default server port
MINUTES = 60
# ----------------------------------------------------------------------------

app = modal.App("qwen-pwn-sglang")

# Weights cached in a Volume so cold starts don't re-download.
hf_cache = modal.Volume.from_name("qwen-pwn-hf-cache", create_if_missing=True)

# Use SGLang's official image (CUDA + sglang + flashinfer preinstalled).
sglang_image = (
    modal.Image.from_registry("lmsysorg/sglang:latest")
    .entrypoint([])  # clear the base image's entrypoint
    .env({"HF_HOME": "/root/.cache/huggingface", "HF_HUB_ENABLE_HF_TRANSFER": "1"})
)


@app.server(
    image=sglang_image,
    gpu=GPU,
    volumes={"/root/.cache/huggingface": hf_cache},
    secrets=[modal.Secret.from_name("huggingface")],
    scaledown_window=15 * MINUTES,
    startup_timeout=30 * MINUTES,  # big weights can take a while to download/load
    target_concurrency=16,
    port=PORT,
    unauthenticated=True,  # endpoint reachable with just the SGLang --api-key bearer
)
class Server:
    @modal.enter()
    def start(self):
        n_gpu = int(GPU.split(":")[1]) if ":" in GPU else 1
        cmd = [
            "python3",
            "-m",
            "sglang.launch_server",
            "--model-path",
            MODEL_ID,
            "--served-model-name",
            MODEL_ID,
            "--host",
            "0.0.0.0",
            "--port",
            str(PORT),
            "--tp",
            str(n_gpu),
        ]
        if SGLANG_API_KEY:
            cmd += ["--api-key", SGLANG_API_KEY]
        print("launching:", " ".join(cmd), flush=True)
        self.proc = subprocess.Popen(cmd)

    @modal.exit()
    def stop(self):
        if getattr(self, "proc", None):
            self.proc.terminate()


@app.local_entrypoint()
def main():
    print(f"Configured MODEL_ID={MODEL_ID} GPU={GPU} PORT={PORT}")
    print("Deploy with:  modal deploy deploy/modal_sglang.py")
    print("Then farm with --endpoint https://<app-url>/v1/completions")
