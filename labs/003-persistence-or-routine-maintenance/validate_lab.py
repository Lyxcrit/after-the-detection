#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent

REQUIRED = {
    "asset_inventory.csv": ["host","ip","role","os","owner","criticality","internet_facing","peer_group"],
    "web_access.csv": ["_time","host","src_ip","http_method","uri_path","status","user_agent","note"],
    "endpoint_process.csv": ["_time","host","user","process_name","process_id","parent_process_name","parent_process_id","command_line","session_type","signature_status","note"],
    "endpoint_file.csv": ["_time","host","user","action","file_path","file_name","sha256","source_process","source_process_id","signature_status","note"],
    "endpoint_service.csv": ["_time","host","user","event_id","service_name","display_name","image_path","start_type","action","source_process","source_process_id","signature_status","note"],
    "scheduled_task.csv": ["_time","host","task_name","task_path","user","action","process_name","process_id","note"],
    "network_activity.csv": ["_time","host","user","process_name","process_id","dest_domain","dest_ip","dest_port","protocol","uri","action","bytes_in","note"],
    "identity_auth.csv": ["_time","host","target_host","user","logon_type","src_ip","result","auth_package","session_context","note"],
    "detection_results.csv": ["_time","detection_id","title","host","user","process_name","parent_process_name","severity","status","reason"],
    "investigation_findings.csv": ["finding_id","finding_type","host","entity","evidence_summary","expected_decision","analyst_decision"],
}

errors = []
for filename, expected in REQUIRED.items():
    path = ROOT / "data" / filename
    if not path.is_file():
        errors.append(f"missing data/{filename}")
        continue
    rows = list(csv.reader(path.open(newline="", encoding="utf-8")))
    if not rows or rows[0] != expected:
        errors.append(f"header mismatch: data/{filename}")
    app_path = ROOT / "splunk" / "after_detection_hunt_003" / "lookups" / filename
    if not app_path.is_file():
        errors.append(f"missing Splunk lookup {app_path.relative_to(ROOT)}")

for required in [
    "README.md",
    "attack-narrative.md",
    "analyst-hunt-guide.md",
    "response-plan.md",
    "sample-spl.md",
    "splunk-ingest-guide.md",
    "splunk/after_detection_hunt_003/default/app.conf",
    "splunk/after_detection_hunt_003/default/savedsearches.conf",
]:
    if not (ROOT / required).is_file():
        errors.append(f"missing {required}")

if errors:
    print("FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("PASS")
print(f"Validated {len(REQUIRED)} CSV datasets and the Splunk lab app.")
