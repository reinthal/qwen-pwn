"""Tool implementations for the qwen-pwn agent harness.

Executes the tools defined in the CTI-REALM system prompt:
  - bash / run_python: real subprocess execution (this is where the model's
    curl probe hits the sinkhole)
  - CTI tools: backed by ctidata.py
  - validate_output_json: JSON validation
"""

import json
import os
import re
import subprocess

from . import ctidata

MAX_OUTPUT = 8000  # chars per tool result


def _clip(s: str) -> str:
    if len(s) > MAX_OUTPUT:
        return s[:MAX_OUTPUT] + f"\n... [truncated, {len(s) - MAX_OUTPUT} chars]"
    return s


def run_bash(command: str, cwd=None, timeout=None) -> str:
    timeout = timeout or 60
    env = dict(os.environ)
    # make both system and nix curl trust the sinkhole TLS CA
    env["SSL_CERT_FILE"] = "/etc/ssl/certs/ca-certificates.crt"
    env["CURL_CA_BUNDLE"] = "/etc/ssl/certs/ca-certificates.crt"
    out: str
    err: str
    code: int
    try:
        p = subprocess.run(
            ["bash", "-c", command],
            cwd=cwd or "/tmp",
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        out = p.stdout
        err = p.stderr
        code = p.returncode
    except subprocess.TimeoutExpired:
        out, err, code = "", f"Command timed out after {timeout}s", -1
    result = f"stdout:\n{out}\nstderr:\n{err}\nexit_code: {code}"
    return _clip(result)


def run_python(code: str, timeout=None) -> str:
    timeout = timeout or 60
    env = dict(os.environ)
    env["SSL_CERT_FILE"] = "/etc/ssl/certs/ca-certificates.crt"
    out: str
    err: str
    ret: int
    try:
        p = subprocess.run(
            ["python3", "-c", code],
            cwd="/tmp",
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        out, err, ret = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired:
        out, err, ret = "", f"Python timed out after {timeout}s", -1
    result = f"stdout:\n{out}\nstderr:\n{err}\nexit_code: {ret}"
    return _clip(result)


def validate_output_json(json_output: str) -> str:
    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as e:
        return f"INVALID JSON: {e}"
    problems = []
    if not isinstance(data, dict):
        problems.append("top level must be an object")
    else:
        for req in ("title", "detection", "logsource"):
            if req not in data:
                problems.append(f"missing required field: {req}")
        if "detection" in data and not isinstance(data["detection"], dict):
            problems.append("detection must be an object")
        if (
            "detection" in data
            and isinstance(data["detection"], dict)
            and "condition" not in data["detection"]
        ):
            problems.append("detection missing 'condition'")
    if problems:
        return "VALIDATION FAILED: " + "; ".join(problems)
    return (
        "VALID: JSON structure OK (title, detection with condition, logsource present)"
    )


# name -> callable(kwargs dict) -> str
def handle_tool(name: str, args: dict) -> str:
    if name == "bash":
        return run_bash(
            args.get("command", ""), cwd=args.get("cwd"), timeout=args.get("timeout")
        )
    if name == "run_python":
        return run_python(args.get("code", ""), timeout=args.get("timeout"))
    if name == "search_sigma_rules":
        return ctidata.search_sigma_rules(
            keyword=args.get("keyword", ""),
            technique_id=args.get("technique_id", ""),
            platform=args.get("platform", ""),
            limit=args.get("limit", 5),
        )
    if name == "search_mitre_techniques":
        return ctidata.search_mitre_techniques(args.get("tactic", ""))
    if name == "list_kusto_tables":
        return ctidata.list_kusto_tables()
    if name == "get_table_schema":
        return ctidata.get_table_schema(args.get("table_name", ""))
    if name == "sample_table_data":
        return ctidata.sample_table_data(
            args.get("table_name", ""), args.get("rows", 5)
        )
    if name == "execute_kql_query":
        return ctidata.execute_kql_query(args.get("query", ""), args.get("limit", 10))
    if name == "list_cti_report_tags":
        return ctidata.list_cti_report_tags()
    if name == "get_cti_reports_by_tag":
        return ctidata.get_cti_reports_by_tag(args.get("tag", ""))
    if name == "validate_output_json":
        return validate_output_json(args.get("json_output", ""))
    return f"Unknown tool: {name}"


# --------------------------------------------------------------------------
# Qwen3.5/3.8 native tool-call parsing:  <function=NAME>...</function>
#   with <parameter=KEY>value</parameter> inside.
# Tolerated malformed variants seen in the wild:
#   B: opener written as <parameter=TOOLNAME> instead of <function=TOOLNAME>
#   C: unclosed tool call — <function=NAME><parameter=KEY>value ... (no closers)
# Plus a stray leading </think> token that leaks into content when reasoning
# is disabled.
# --------------------------------------------------------------------------

TOOLCALL_RE = re.compile(r"<function=(\w+)>(.*?)</function>", re.DOTALL)
PARAM_RE = re.compile(r"<parameter=(\w+)>(.*?)(?:</parameter>|$)", re.DOTALL)
OPENER_RE = re.compile(r"<(?:function|parameter)=(\w+)>")

KNOWN_TOOLS = {
    "search_sigma_rules",
    "search_mitre_techniques",
    "list_kusto_tables",
    "get_table_schema",
    "sample_table_data",
    "execute_kql_query",
    "list_cti_report_tags",
    "get_cti_reports_by_tag",
    "validate_output_json",
    "bash",
    "run_python",
}


def _normalize(content: str) -> str:
    # strip stray thinking tokens leaked when reasoning is disabled
    while True:
        stripped = content.lstrip()
        if stripped.startswith("</think>"):
            content = stripped[len("</think>") :].lstrip()
        elif stripped.startswith("<think>"):
            content = stripped[len("<think>") :].lstrip()
        else:
            return content


def parse_tool_calls(content: str) -> list[dict]:
    """Parse tool calls from model content, tolerating malformed variants."""
    content = _normalize(content)
    calls: list[dict] = []
    spans: list[tuple[int, int]] = []

    # A: standard <function=NAME>...</function>
    for m in TOOLCALL_RE.finditer(content):
        if m.group(1) not in KNOWN_TOOLS:
            continue
        calls.append(
            {"name": m.group(1), "args": _parse_params(m.group(2)), "raw": m.group(0)}
        )
        spans.append((m.start(), m.end()))

    # B/C: leftover openers (malformed or unclosed) not inside a standard call
    sibling_re = re.compile(
        r"<function=\w+>|<parameter=(?:" + "|".join(sorted(KNOWN_TOOLS)) + r")>"
    )
    for m in OPENER_RE.finditer(content):
        name = m.group(1)
        if name not in KNOWN_TOOLS:
            continue
        if any(s <= m.start() < e for s, e in spans):
            continue
        opener_end = m.end()
        rest = content[opener_end:]
        # trim at the next sibling TOOL opener (not at argument <parameter=KEY> tags)
        nxt = sibling_re.search(rest)
        if nxt:
            rest = rest[: nxt.start()]
        calls.append(
            {"name": name, "args": _parse_params(rest), "raw": m.group(0) + rest}
        )
        spans.append((m.start(), opener_end + len(rest)))

    return calls


def _parse_params(body: str) -> dict:
    args = {}
    for pm in PARAM_RE.finditer(body):
        key = pm.group(1)
        val = pm.group(2)
        # strip exactly one leading/trailing newline (Qwen format convention)
        if val.startswith("\n"):
            val = val[1:]
        if val.endswith("\n"):
            val = val[:-1]
        # numeric coercion for known int params
        if key in ("limit", "rows", "timeout") and val.strip().isdigit():
            args[key] = int(val.strip())
        else:
            args[key] = val
    return args


def xml_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_function_results(results: list[dict]) -> str:
    """Build the Qwen agentic <function_results> user message."""
    parts = ["<function_results>\n"]
    for r in results:
        parts.append("<result>\n")
        parts.append(f"<name>{r['name']}</name>\n")
        parts.append(f"<output>\n{xml_escape(r['output'])}\n</output>\n")
        parts.append("</result>\n")
    parts.append("</function_results>")
    return "".join(parts)
