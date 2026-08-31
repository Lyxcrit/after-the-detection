from pathlib import Path
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
