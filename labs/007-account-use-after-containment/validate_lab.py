from pathlib import Path
import csv
R=Path(__file__).resolve().parent
names=['asset_inventory.csv','identity_admin.csv','identity_auth.csv','network_activity.csv','endpoint_process.csv','endpoint_file.csv','detection_results.csv','investigation_findings.csv','response_activity.csv']
for n in names: assert len(list(csv.DictReader((R/'data'/n).open(encoding='utf-8'))))==1800,n
a=list(csv.DictReader((R/'data'/'identity_auth.csv').open(encoding='utf-8'))); assert any(x['event_id']=='AUTH-INC-002' and x['result']=='success' for x in a)
p=list(csv.DictReader((R/'data'/'endpoint_process.csv').open(encoding='utf-8'))); assert any(x['event_id']=='PROC-INC-001' and x['host']=='FILE-02' for x in p)
print('PASS: Hunt 007 - 9 lookups, 1,800 rows each, 16,200 records')
