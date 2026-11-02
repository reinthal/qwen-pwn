# iac — vLLM on Modal

Serves `Qwen/Qwen3.8-Flash-Next` on 4× H200 with vLLM (OpenAI-compatible API).

```sh
cd iac
uv sync
uv run modal deploy vllm_server.py   # prints the endpoint URL
```

The endpoint uses Modal proxy auth. Create a proxy token in the Modal dashboard and send
`Modal-Key` / `Modal-Secret` headers. The smoke test reads them from
`MODAL_PROXY_TOKEN_ID` / `MODAL_PROXY_TOKEN_SECRET`:

```sh
uv run modal run vllm_server.py
```

Weights and vLLM compile caches persist in the `huggingface-cache` and `vllm-cache` volumes.
Replicas scale to zero after 15 idle minutes.
