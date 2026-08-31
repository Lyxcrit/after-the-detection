from pathlib import Path
import json

ROOT = Path(__file__).resolve().parent
APP = ROOT / "splunk" / "after_detection_hunt_009"

def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content.strip() + "\n", encoding="utf-8")

write(ROOT / "README.md", r'''# Hunt 009: Scheduled Task or Admin Automation?

**Difficulty:** Guided, moderate noise  
**Expected time:** 35–50 minutes  
**Starting point:** A new scheduled task appears on `HR-WS-22` under a Microsoft-looking path.

The task name is plausible: `\Microsoft\Windows\Update\TelemetryCheck`.

That is not enough to call it malicious.

The hunt is about deciding whether the task is legitimate administration, a naming collision with enterprise automation, or persistence. The analyst has to compare task metadata, creator, run-as account, command path, process ancestry, file trust, network behavior, and approved change records.

## Quick start

1. Start with `detection_results.csv`.
2. Inspect the task definition in `scheduled_task.csv`.
3. Follow the task into `endpoint_process.csv` and `endpoint_file.csv`.
4. Compare the suspicious task with the approved `\ACME\Patch\TelemetryCheck` task on `PATCH-01`.
5. Check `software_trust.csv` and `change_records.csv` before deciding.
6. State what proves persistence on `HR-WS-22`, and what does **not** prove propagation elsewhere.
7. Choose containment and estate-wide hunting actions.

## Data

Nine platform-portable CSV lookups contain 1,800 records each, for **16,200 total synthetic records**.
''')

write(ROOT / "attack-narrative.md", r'''# Attack Narrative

A user-context PowerShell process stages `C:\ProgramData\WinCache\check.ps1` on `HR-WS-22`, then creates `\Microsoft\Windows\Update\TelemetryCheck` to run the script as `SYSTEM`.

The task starts fourteen seconds later. `taskeng.exe` launches hidden PowerShell, which executes `telemetry.dll` through `rundll32.exe`, performs basic system discovery, and opens outbound TLS sessions to `203.0.113.55`.

Nearby activity is intentionally confusing. `PATCH-01` creates a similarly named `\ACME\Patch\TelemetryCheck` task that launches a trusted internal script as `ACME\svc_patch` and reports to `MGMT-01`. `HR-WS-22` also has a known `\ACME\Inventory\Daily` task.

The supplied evidence supports malicious scheduled-task persistence on `HR-WS-22`. It does not prove the suspicious task exists on another host, and the external TLS sessions do not by themselves establish command-and-control content or data theft.
''')

write(ROOT / "analyst-hunt-guide.md", '''# Analyst Hunt Guide

## 1. Read the task, not the name
Capture creator, task path, command, arguments, run-as identity, and timing.

## 2. Follow execution
Pivot from the task start to process ancestry and child processes.

## 3. Check payload trust
Compare the script and DLL with approved internal automation.

## 4. Compare the look-alike
Explain why the `PATCH-01` task is legitimate even though its name is similar.

## 5. Check operational context
Look for approved changes and known task roots.

## 6. Make the persistence decision
State exactly which evidence supports malicious persistence on `HR-WS-22`.

## 7. Bound the claim
Decide what still needs to be hunted across the estate rather than assuming propagation.
''')

write(ROOT / "investigation-worksheet.md", '''# Investigation Worksheet

| Entity / Task | Creator | Run-as | Command / Payload | Change record | Trust context | Decision | Confidence |
|---|---|---|---|---|---|---|---|
| HR-WS-22 / TelemetryCheck | | | | | | | |
| PATCH-01 / TelemetryCheck | | | | | | | |
| HR-WS-22 / ACME Inventory | | | | | | | |

## Process ancestry

## File and trust pivots

## Network context

## Persistence decision

## Estate-wide scope query

## Evidence gaps
''')

write(ROOT / "data-dictionary.md", '''# Data Dictionary

Nine platform-portable CSV lookups are included, each with exactly 1,800 records:

- `asset_inventory.csv`
- `change_records.csv`
- `detection_results.csv`
- `endpoint_file.csv`
- `endpoint_process.csv`
- `network_activity.csv`
- `response_activity.csv`
- `scheduled_task.csv`
- `software_trust.csv`

All event timestamps are UTC ISO 8601.
''')

write(ROOT / "sample-spl.md", r'''# Sample SPL

## Starting detections
```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search detection_id="ATD-009-*"
| sort 0 _time
```

## Compare scheduled tasks
```spl
| inputlookup scheduled_task.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search task_name="*TelemetryCheck*"
| sort 0 _time
| table _time host user task_name action task_command run_as note
```

## Follow HR-WS-22 process ancestry
```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="HR-WS-22"
| sort 0 _time
| table _time user parent_process_name process_name command_line note
```

## Check trust context
```spl
| inputlookup software_trust.csv
| search file_path="*TelemetryCheck*" OR file_path="*WinCache*"
| table _time host file_path signature_status publisher sha256 note
```

## Look for the persistence pattern elsewhere
```spl
| inputlookup scheduled_task.csv
| search task_name="\\Microsoft\\Windows\\Update\\TelemetryCheck"
| stats count values(task_command) values(run_as) by host
```
''')

write(ROOT / "response-plan.md", r'''# Response Plan / Expected Decision

`HR-WS-22` has high-confidence malicious scheduled-task persistence.

The decision is not based on the Microsoft-looking task name. It is based on the combined evidence:

- the task was created by `ACME\kpatel`
- it runs hidden PowerShell as `SYSTEM`
- the script lives under `C:\ProgramData\WinCache`
- the task launches an unsigned DLL through `rundll32.exe`
- the payload performs discovery and opens external TLS sessions
- there is no approved change matching the task

Preserve the task XML, script, DLL, hashes, and process/network evidence, disable the task, then isolate `HR-WS-22`.

Hunt the exact task path, script/DLL hashes, `WinCache` path, and external destination across the estate.

Do **not** claim persistence on another host until matching evidence is found. The legitimate `PATCH-01` task is a useful comparison, not proof of propagation.
''')

write(ROOT / "answer-key.json", json.dumps({
    "seed": 20260831,
    "lookup_count": 9,
    "rows_per_lookup": 1800,
    "total_records": 16200,
    "primary_host": "HR-WS-22",
    "suspicious_task": r"\Microsoft\Windows\Update\TelemetryCheck",
    "expected_decision": "High-confidence malicious scheduled-task persistence on HR-WS-22.",
    "benign_lookalikes": [r"PATCH-01 \ACME\Patch\TelemetryCheck", r"HR-WS-22 \ACME\Inventory\Daily"],
    "not_proven": ["same persistence on another host", "content of TLS sessions", "data theft or command-and-control semantics"]
}, indent=2))

write(ROOT / "validate_lab.py", r'''from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parent
NAMES = [
    "asset_inventory.csv","change_records.csv","detection_results.csv",
    "endpoint_file.csv","endpoint_process.csv","network_activity.csv",
    "response_activity.csv","scheduled_task.csv","software_trust.csv"
]
for name in NAMES:
    rows = list(csv.DictReader((ROOT/"data"/name).open(encoding="utf-8")))
    assert len(rows) == 1800, (name, len(rows))

tasks = list(csv.DictReader((ROOT/"data"/"scheduled_task.csv").open(encoding="utf-8")))
assert any(r["event_id"]=="TASK-INC-001" and r["host"]=="HR-WS-22" and r["run_as"]=="NT AUTHORITY\\SYSTEM" for r in tasks)
assert any(r["event_id"]=="TASK-BEN-001" and r["host"]=="PATCH-01" and r["classification"]=="benign" for r in tasks)

proc = list(csv.DictReader((ROOT/"data"/"endpoint_process.csv").open(encoding="utf-8")))
assert any(r["event_id"]=="PROC-INC-002" and r["process_name"]=="rundll32.exe" for r in proc)

trust = list(csv.DictReader((ROOT/"data"/"software_trust.csv").open(encoding="utf-8")))
assert any(r["event_id"]=="TRUST-INC-001" and r["signature_status"]=="unsigned" for r in trust)

print("PASS: 9 lookups, 1,800 rows each, 16,200 total records; suspicious and benign scheduled-task evidence present")
''')

write(ROOT / "validation-report.md", '''# Validation Report

- Deterministic seed: **20260831**
- Lookups: **9**
- Rows per lookup: **1,800**
- Total records: **16,200**
- Suspicious scheduled task on `HR-WS-22`: **present**
- Hidden PowerShell as `SYSTEM`: **present**
- Unsigned DLL execution: **present**
- External TLS sessions: **present**
- Approved patch-task look-alike: **present**
- Known inventory-task look-alike: **present**
- Change-record comparison: **present**
- Responder activity: **present**
- Explicit propagation/evidence gaps: **present**
''')

write(APP / "default" / "app.conf", '''[install]
is_configured = 0

[ui]
is_visible = 1
label = After the Detection - Hunt 009

[launcher]
author = WiseHawk Technologies
version = 1.0.0
description = Hunt 009 - Scheduled Task or Admin Automation?
''')
write(APP / "metadata" / "default.meta", '''[]
access = read : [ * ], write : [ admin ]
export = system
''')
write(APP / "default" / "data" / "ui" / "nav" / "default.xml", '<nav search_view="search"><view name="hunt_009_overview" default="true"/><view name="search"/></nav>')
write(APP / "default" / "data" / "ui" / "views" / "hunt_009_overview.xml", '''<form version="1.1" theme="dark">
<label>Hunt 009 — Scheduled Task or Admin Automation?</label>
<row><panel><table><search><query>| inputlookup detection_results.csv | search detection_id="ATD-009-*" | table _time severity title host user classification note</query></search></table></panel></row>
<row><panel><table><search><query>| inputlookup scheduled_task.csv | search task_name="*TelemetryCheck*" | table _time host user task_name action task_command run_as classification note</query></search></table></panel></row>
</form>''')
write(APP / "README.md", '''# Splunk Lab App

Copy `after_detection_hunt_009` into `$SPLUNK_HOME/etc/apps/` and restart Splunk. The app uses bundled CSV lookups and requires no index or add-on.
''')

print("Finalized Hunt 009 documentation and Splunk app files")
