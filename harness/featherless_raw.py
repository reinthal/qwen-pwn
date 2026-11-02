"""Inspect model provider for token-exact raw completions (no chat template).

The agent loop builds the ChatML prompt itself (see hf_agent.agent_loop) and
sends it verbatim to the HF/Featherless /v1/completions endpoint. Routing the
request through inspect's generate() turns every Qwen turn into a ModelEvent,
so the eval transcript shows each prompt and completion as it happens.

The prompt sent is RAW_PROMPT when set (the exact string the agent loop
built; the input messages are then display-only), else the text of the LAST
input message, sent as-is. The raw
completion text and finish_reason come back in ModelOutput.metadata
("raw_text", "finish_reason"), so callers never depend on how inspect parses
the content.

  get_model("featherless-raw/Qwen/Qwen3.8-Flash-Next")   # needs HF_TOKEN
"""

import os
import time
from contextvars import ContextVar

import httpx
from inspect_ai.model import (
    GenerateConfig,
    ModelAPI,
    ModelCall,
    ModelOutput,
    ModelUsage,
    modelapi,
)

# exact prompt for the current generate() call (set by the caller)
RAW_PROMPT: ContextVar[str | None] = ContextVar("featherless_raw_prompt", default=None)

ENDPOINT = "https://router.huggingface.co/featherless-ai/v1/completions"

# recorded rollout params not expressible in GenerateConfig
EXTRA_SAMPLING = {"min_p": 0.0, "repetition_penalty": 1.0}

TIMEOUT = httpx.Timeout(300.0, connect=15.0)
STOP_REASONS = {"stop": "stop", "length": "max_tokens"}


class FeatherlessRawAPI(ModelAPI):
    def __init__(
        self,
        model_name: str,
        base_url: str | None = None,
        api_key: str | None = None,
        config: GenerateConfig = GenerateConfig(),
        **model_args,
    ) -> None:
        super().__init__(
            model_name=model_name,
            base_url=base_url or ENDPOINT,
            api_key=api_key or os.environ.get("HF_TOKEN"),
            api_key_vars=["HF_TOKEN"],
            config=config,
        )
        if not self.api_key:
            raise RuntimeError("featherless-raw: HF_TOKEN is not set")

    async def generate(self, input, tools, tool_choice, config):
        prompt = RAW_PROMPT.get()
        if prompt is None:
            prompt = input[-1].text
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "temperature": 1.0 if config.temperature is None else config.temperature,
            "top_p": 1.0 if config.top_p is None else config.top_p,
            "top_k": 20 if config.top_k is None else config.top_k,
            "presence_penalty": config.presence_penalty or 0.0,
            "frequency_penalty": config.frequency_penalty or 0.0,
            "max_tokens": config.max_tokens or 2500,
            "stop": config.stop_seqs or ["<|im_end|>"],
            **EXTRA_SAMPLING,
        }
        start = time.monotonic()
        # a client per request: inspect caches model instances across evals,
        # and a shared client would stay bound to a closed event loop
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            r = await client.post(
                self.base_url,
                json=payload,
                headers={"Authorization": f"Bearer {self.api_key}"},
            )
        if r.status_code == 402:
            raise RuntimeError(
                "Out of HF credits — https://huggingface.co/settings/billing"
            )
        r.raise_for_status()
        d = r.json()
        choice = d["choices"][0]
        text = choice.get("text") or ""
        finish = choice.get("finish_reason")
        usage = d.get("usage") or {}

        output = ModelOutput.from_content(
            model=self.model_name,
            content=text,
            stop_reason=STOP_REASONS.get(finish, "unknown"),
        )
        output.usage = ModelUsage(
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
        )
        output.metadata = {"raw_text": text, "finish_reason": finish}
        # the exact prompt sent lives here (API tab): the ModelEvent input may
        # be a display-only rendering of it
        call = ModelCall.create(
            request=payload,
            response=d,
            time=time.monotonic() - start,
        )
        return output, call

    def should_retry(self, ex: Exception) -> bool:
        if isinstance(ex, httpx.HTTPStatusError):
            return ex.response.status_code in (429, 500, 502, 503, 504)
        return isinstance(ex, (httpx.TransportError, KeyError, ValueError))

    def connection_key(self) -> str:
        return "featherless-raw"


@modelapi(name="featherless-raw")
def featherless_raw():
    return FeatherlessRawAPI
