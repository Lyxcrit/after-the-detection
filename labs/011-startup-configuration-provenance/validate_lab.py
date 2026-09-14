from pathlib import Path
import csv
ROOT=Path(__file__).resolve().parent
names=["detection_results.csv","startup_config.csv","startup_items.csv","endpoint_process.csv","endpoint_file.csv","software_trust.csv","policy_context.csv","network_activity.csv","response_activity.csv"]
for n in names:
    rows=list(csv.DictReader((ROOT/"data"/n).open(encoding="utf-8")))
    assert len(rows)==500,(n,len(rows))
cfg=list(csv.DictReader((ROOT/"data"/"startup_config.csv").open(encoding="utf-8")))
assert any(r["event_id"]=="CFG-INC-001" and r["host"]=="FIN-WS-09" for r in cfg)
assert any(r["event_id"]=="CFG-BEN-001" and r["provenance"]=="central policy" for r in cfg)
print("PASS: 9 lookups x 500 records = 4,500")
