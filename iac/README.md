# iac — vLLM on Modal

Serves `Qwen/Qwen3.8-Flash-Next` on 4× H200 with vLLM (OpenAI-compatible API).

```sh
cd iac
uv sync
uv run modal run vllm_server.py::download   # CPU-only: pulls ~360 GB into the huggingface-cache volume
uv run modal deploy vllm_server.py          # prints the endpoint URL
```

The endpoint uses Modal proxy auth. Create a proxy token in the Modal dashboard and send
`Modal-Key` / `Modal-Secret` headers. The smoke test reads them from
`MODAL_PROXY_TOKEN_ID` / `MODAL_PROXY_TOKEN_SECRET`:

```sh
uv run modal run vllm_server.py
```

Run the download step before the first deploy: the GPU server sets `HF_HUB_OFFLINE=1`, so it
only loads from the volume and fails fast if the weights are missing. Weights and vLLM compile caches persist in the `huggingface-cache` and `vllm-cache` volumes.
Replicas scale to zero after 15 idle minutes.
