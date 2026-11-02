"""Display-only view of a raw ChatML prompt as inspect chat messages.

The model never receives these messages: featherless_raw sends the exact
prompt string (RAW_PROMPT side channel). They exist so the inspect viewer shows
system / user / assistant / tool turns instead of one raw "user" blob.

Each message carries the exact prompt segment it was cut from in
metadata["raw"]; render() joins them back, and callers check
render(messages) == prompt before trusting the display.
"""

import re

from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageTool,
    ChatMessageUser,
    ContentReasoning,
    ContentText,
)
from inspect_ai.tool import ToolCall

from . import tools

IM_START = "<|im_start|>"
IM_END = "<|im_end|>"
TOOL_RESPONSE_RE = re.compile(r"<tool_response>\n(.*?)\n</tool_response>", re.DOTALL)


def render(messages) -> str:
    return "".join((m.metadata or {}).get("raw", "") for m in messages)


def _assistant(body: str, raw: str, idx: int) -> ChatMessageAssistant:
    """A closed assistant turn: reasoning, visible text, structured calls."""
    reasoning, rest = "", body
    if "</think>" in body:
        reasoning, rest = body.split("</think>", 1)
        reasoning = reasoning.removeprefix("<think>").strip()
    text = rest.split("<tool_call>", 1)[0].strip()
    calls = [
        ToolCall(id=f"m{idx}c{i}", function=c["name"], arguments=c["args"])
        for i, c in enumerate(tools.parse_tool_calls(rest))
    ]
    content = []
    if reasoning:
        content.append(ContentReasoning(reasoning=reasoning))
    if text:
        content.append(ContentText(text=text))
    return ChatMessageAssistant(
        content=content or "", tool_calls=calls or None, metadata={"raw": raw}
    )


def to_display_messages(prompt: str) -> list:
    starts = [m.start() for m in re.finditer(re.escape(IM_START), prompt)]
    if not starts:
        return [ChatMessageUser(content=prompt, metadata={"raw": prompt})]
    bounds = list(zip(starts, starts[1:] + [len(prompt)]))
    bounds[0] = (0, bounds[0][1])  # any text before the first block rides along

    messages = []
    for idx, (a, b) in enumerate(bounds):
        raw = prompt[a:b]
        seg = raw[raw.find(IM_START) + len(IM_START) :]
        role, _, body = seg.partition("\n")
        closed = IM_END in body
        tail = ""
        if closed:
            body, tail = body.split(IM_END, 1)

        if role == "system":
            messages.append(ChatMessageSystem(content=body, metadata={"raw": raw}))
        elif role == "user" and body.startswith("<tool_response>"):
            outputs = TOOL_RESPONSE_RE.findall(body)
            prev = messages[-1] if messages else None
            calls = (prev.tool_calls or []) if prev and prev.role == "assistant" else []
            for i, out in enumerate(outputs or [body]):
                call = calls[i] if i < len(calls) else None
                messages.append(
                    ChatMessageTool(
                        content=out,
                        tool_call_id=call.id if call else f"m{idx}r{i}",
                        function=call.function if call else None,
                        metadata={"raw": raw if i == 0 else ""},
                    )
                )
        elif role == "assistant" and closed:
            messages.append(_assistant(body, raw, idx))
        elif role == "assistant":
            # the open turn the model is about to continue (the prefill)
            if body.strip() in ("", "<think>") and messages:
                # nothing to show: fold the header into the previous message
                messages[-1].metadata["raw"] += raw
            else:
                messages.append(
                    ChatMessageAssistant(content=body, metadata={"raw": raw})
                )
        else:
            messages.append(ChatMessageUser(content=body, metadata={"raw": raw}))
        if tail.strip():
            # text after an <|im_end|> inside the block (e.g. injected in a
            # tool output): the model sees it outside any turn — show it
            messages.append(
                ChatMessageUser(
                    content=f"(text after <|im_end|>, outside any turn)\n{tail}",
                    metadata={"raw": ""},
                )
            )
    return messages
