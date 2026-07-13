#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent

REQUIRED_DOCS = [
    "README.md",
    "threat-brief.md",
    "attack-narrative.md",
    "coverage-map.md",
    "data-dictionary.md",
    "splunk-ingest-guide.md",
    "sample-spl.md",
    "analyst-hunt-guide.md",
    "response-plan.md",
    "apt-falconer-showcase.md",
    "falconsearch-notes.md",
    "linkedin-content.md",
    "root-readme-snippet.md",
    "content-calendar.md",
]

EXPECTED_HEADERS = {
    "web_access.csv": ["_time","host","src_ip","http_method","uri_path","status","bytes_out","user_agent","note"],
    "asset_inventory.csv": ["host","ip","role","os","owner","criticality","internet_facing"],
    "endpoint_process.csv": ["_time","host","user","process_name","process_id","parent_process_name","parent_process_id","command_line","session_type","signature_status"],
    "endpoint_file.csv": ["_time","host","user","action","file_path","file_name","sha256","source_process","source_process_id","signature_status"],
    "network_activity.csv": ["_time","host","user","process_name","process_id","dest_domain","dest_ip","dest_port","protocol","uri","action","bytes_in"],
    "identity_auth.csv": ["_time","host","target_host","user","logon_type","src_ip","result","auth_package","session_context"],
    "detection_results.csv": ["_time","detection_id","title","host","user","process_name","parent_process_name","severity","status","reason"],
    "investigation_findings.csv": ["finding_id","finding_type","host","entity","evidence_summary","initial_confidence","analyst_decision"],
}

errors: list[str] = []

for doc in REQUIRED_DOCS:
    if not (ROOT / doc).is_file():
        errors.append(f"missing document: {doc}")

for filename, expected in EXPECTED_HEADERS.items():
    path = ROOT / "data" / filename
    if not path.is_file():
        errors.append(f"missing CSV: data/{filename}")
        continue

    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))

    if not rows:
        errors.append(f"empty CSV: data/{filename}")
        continue

    if rows[0] != expected:
        errors.append(
            f"header mismatch for data/{filename}: expected {expected}, got {rows[0]}"
        )

    width = len(rows[0])
    for number, row in enumerate(rows[1:], start=2):
        if len(row) != width:
            errors.append(
                f"row width mismatch in data/{filename} line {number}: "
                f"expected {width}, got {len(row)}"
            )

process_path = ROOT / "data" / "endpoint_process.csv"
file_path = ROOT / "data" / "endpoint_file.csv"

if process_path.is_file() and file_path.is_file():
    with process_path.open(newline="", encoding="utf-8") as handle:
        process_rows = list(csv.DictReader(handle))
    with file_path.open(newline="", encoding="utf-8") as handle:
        file_rows = list(csv.DictReader(handle))

    process_ids = {(row["host"], row["process_id"]) for row in process_rows}
    for row in file_rows:
        key = (row["host"], row["source_process_id"])
        if key not in process_ids:
            errors.append(
                f"file event references unknown process: {key} for {row['file_path']}"
            )

if errors:
    print("FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("PASS")
print(f"Validated {len(REQUIRED_DOCS)} documents and {len(EXPECTED_HEADERS)} CSV files.")
