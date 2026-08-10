from pathlib import Path
import csv
ROOT=Path(__file__).resolve().parent
names=["asset_inventory.csv","identity_auth.csv","network_activity.csv","endpoint_process.csv","endpoint_file.csv","detection_results.csv","investigation_findings.csv","response_activity.csv"]
for name in names:
    rows=list(csv.DictReader((ROOT/"data"/name).open(encoding="utf-8")))
    assert len(rows)==1500,(name,len(rows))
assert any(r["event_id"]=="AUTH-INC-001" for r in csv.DictReader((ROOT/"data"/"identity_auth.csv").open(encoding="utf-8")))
assert any(r["event_id"]=="AUTH-CTX-001" for r in csv.DictReader((ROOT/"data"/"identity_auth.csv").open(encoding="utf-8")))
print("PASS: 8 lookups, 1,500 rows each, 12,000 total records")
