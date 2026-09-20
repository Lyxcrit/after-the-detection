from pathlib import Path
import csv
R=Path(__file__).resolve().parent
names=['detection_results.csv','scheduled_task.csv','endpoint_service.csv','startup_config.csv','endpoint_process.csv','endpoint_file.csv','software_trust.csv','network_activity.csv','change_records.csv','response_activity.csv']
for n in names:
 rows=list(csv.DictReader((R/'data'/n).open(encoding='utf-8'))); assert len(rows)==10000,(n,len(rows))
assert any(r['id']=='TASK-INC-1' for r in csv.DictReader((R/'data'/'scheduled_task.csv').open()))
assert any(r['id']=='SVC-INC-1' for r in csv.DictReader((R/'data'/'endpoint_service.csv').open()))
assert any(r['id']=='START-INC-1' for r in csv.DictReader((R/'data'/'startup_config.csv').open()))
print('PASS: 10 lookups x 10,000 records = 100,000')
