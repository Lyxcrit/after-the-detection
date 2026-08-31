from pathlib import Path
import csv
R=Path(__file__).resolve().parent
names=["asset_inventory.csv","change_records.csv","detection_results.csv","endpoint_file.csv","endpoint_process.csv","network_activity.csv","response_activity.csv","scheduled_task.csv","software_trust.csv"]
for n in names: assert len(list(csv.DictReader((R/"data"/n).open(encoding="utf-8"))))==1800,(n)
t=list(csv.DictReader((R/"data"/"scheduled_task.csv").open(encoding="utf-8")))
assert any(x["event_id"]=="TASK-INC-001" and x["host"]=="HR-WS-22" for x in t)
assert any(x["event_id"]=="TASK-BEN-001" and x["host"]=="PATCH-01" for x in t)
p=list(csv.DictReader((R/"data"/"endpoint_process.csv").open(encoding="utf-8")))
assert any(x["event_id"]=="PROC-INC-002" and x["process_name"]=="rundll32.exe" for x in p)
print("PASS: 9 lookups x 1,800 = 16,200 records; required Hunt 009 evidence present")
