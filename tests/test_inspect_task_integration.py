"""Integration test: the inspect eval records the agent's trajectory as events.

Runs one sample of harness/inspect_task.py in-process against the real model,
with the `local` sandbox and a mock judge. As in test_hf_agent_integration,
only the prefilled call executes for real; any other call is stubbed.

  .venv/bin/python -m pytest tests/test_inspect_task_integration.py -v -s
"""

import os
import socket

import pytest
from inspect_ai import eval as inspect_eval
from inspect_ai.log import read_eval_log

from harness import inspect_task
from harness.chatml import render
from harness.url_farmer import load_env_file

PREFILL_CMD_PREFIX = 'ls -la /tmp 2>/dev/null; echo "---"; which curl wget python3 jq'
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
def test_eval_records_trajectory_events(monkeypatch, tmp_path, cut):
    real_tool = inspect_task.sandbox_tool
    executed = []

    async def guarded_tool(name, args):
        cmd = args.get("command", "")
        if name == "bash" and cmd.startswith(PREFILL_CMD_PREFIX) and not executed:
            out = await real_tool(name, args)
        else:
            out = STUB
        executed.append((name, cmd, out))
        return out

    monkeypatch.setattr(inspect_task, "sandbox_tool", guarded_tool)

    [log] = inspect_eval(
        inspect_task.qwen_continue(
            n=1, cut=cut, max_turns=2, sandbox="local", judge="mockllm/model"
        ),
        log_dir=str(tmp_path),
        display="none",
    )
    assert log.status == "success", log.error
    sample = read_eval_log(log.location, resolve_attachments=True).samples[0]
    events = sample.events

    qwen_calls = [
        e for e in events if e.event == "model" and e.model == inspect_task.QWEN
    ]
    tool_events = [e for e in events if e.event == "tool"]
    turn_spans = [e.name for e in events if e.event == "span_begin" and e.name.startswith("turn ")]
    probes = [e for e in events if e.event == "info" and "call_home_probe" in (e.data or {})]
    print(f"\nqwen model events={len(qwen_calls)} tool events={len(tool_events)} "
          f"spans={turn_spans} probes={[p.data for p in probes]}")

    # each Qwen turn is a model event; 2372 runs the prefilled call before any
    assert qwen_calls, "no Qwen model events in the transcript"
    assert len(qwen_calls) == (1 if cut == 2372 else 2)
    # the first tool event is the prefilled bash call, executed for real
    first = tool_events[0]
    assert first.function == "bash"
    assert first.arguments["command"].startswith(PREFILL_CMD_PREFIX)
    assert executed[0][2] != STUB and "---" in executed[0][2]
    # turns are spans, the probe is an info event
    assert turn_spans[:2] == ["turn 1", "turn 2"]
    assert probes
    # the chat pane shows system prompt, objective, assistant turn, tool result
    roles = [m.role for m in sample.messages]
    assert roles[:4] == ["system", "user", "assistant", "tool"]
    # the exact prompt sent (API tab) carries the real tool output ...
    sent = qwen_calls[-1].call.request["prompt"]
    assert f"<tool_response>\n{executed[0][2]}\n</tool_response>" in sent
    # ... and the model event shows structured messages that rebuild it exactly
    for e in qwen_calls:
        assert render(e.input) == e.call.request["prompt"]
        assert [m.role for m in e.input[:2]] == ["system", "user"]
    assert not [e for e in events if e.event == "info" and "display_fallback" in (e.data or {})]
