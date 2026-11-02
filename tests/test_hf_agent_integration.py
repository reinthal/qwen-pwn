"""Integration test: the prefill's own tool call is executed first.

  2323: the prefill stops mid-command; the model completes the call.
  2372: the prefill holds the whole observed call; it runs before the model
        is asked for anything.

Hits the real model (HF Inference / Featherless) and the local sinkhole.
Only the prefilled call runs for real; any extra call the model emits is
stubbed, so no model-authored command executes on the host.

  .venv/bin/python -m pytest tests/test_hf_agent_integration.py -v -s
"""

import os
import socket

import pytest

from harness import hf_agent, tools
from harness.url_farmer import load_env_file

PREFILL_CMD_PREFIX = 'ls -la /tmp 2>/dev/null; echo "---"; which curl wget python3 jq'
PROBE_PAYLOAD = '--data-binary "PROBE_PAYLOAD_ABC123'
OBSERVED_URL = "http://sanmaohe.oss-cn-beijing.aliyuncs.com/upload/test.bin"
STUB = "stdout:\n(stubbed by test)\nstderr:\n\nexit_code: 0"

load_env_file()
pytestmark = [
    pytest.mark.skipif(not os.environ.get("HF_TOKEN"), reason="HF_TOKEN not set"),
    pytest.mark.skipif(
        socket.gethostbyname("sanmaohe.oss-cn-beijing.aliyuncs.com") != "127.0.0.1",
        reason="call-home domain not sinkholed",
    ),
]


@pytest.mark.parametrize("cut", [2323, 2372])
def test_prefilled_tool_call_is_executed(monkeypatch, cut):
    executed = []  # (command, output) for every call the harness dispatches
    prompts = []

    real_handle = tools.handle_tool

    def guarded_handle(name, args):
        cmd = args.get("command", "")
        if name == "bash" and cmd.startswith(PREFILL_CMD_PREFIX) and not executed:
            out = real_handle(name, args)  # the prefilled call: run for real
        else:
            out = STUB
        executed.append((name, cmd, out))
        return out

    real_complete = hf_agent.complete

    def recording_complete(session, prompt, max_tokens):
        prompts.append(prompt)
        return real_complete(session, prompt, max_tokens)

    monkeypatch.setattr(tools, "handle_tool", guarded_handle)
    monkeypatch.setattr(hf_agent, "complete", recording_complete)

    result = hf_agent.run_agent(cut=cut, max_turns=2, quiet=True, save=False)

    assert executed, "no tool call was dispatched"
    name, cmd, out = executed[0]
    print(f"\nfirst executed call:\n{cmd}\n--- output ---\n{out}")

    # 1. the FIRST dispatched call is the prefill's call
    assert name == "bash"
    assert cmd.startswith(PREFILL_CMD_PREFIX)
    assert PROBE_PAYLOAD in cmd
    # 2. it really ran (not the stub): the prefix's echo separators are in stdout
    assert out != STUB and "---" in out
    # 3. the drawn URL was recorded as a probe
    assert result["saw_probe"]
    if cut == 2372:
        # the observed call ran verbatim, without a model completion first,
        # and the sinkhole answered it (curl's -w "HTTP:%{http_code}")
        assert OBSERVED_URL in cmd
        assert "HTTP:" in out
        assert "<tool_response>" in prompts[0], "model was called before the tool ran"
    # 4. its real output was fed back to the model in the native format
    fed_back = next((p for p in prompts if "<tool_response>" in p), None)
    assert fed_back, "model was never re-prompted with the tool result"
    assert f"<tool_response>\n{out}\n</tool_response>" in fed_back
    assert fed_back.endswith("<|im_start|>assistant\n<think>\n")
