from pathlib import Path
import csv
R=Path(__file__).resolve().parent
names=['detection_results.csv','endpoint_service.csv','endpoint_process.csv','endpoint_file.csv','software_trust.csv','network_activity.csv','change_records.csv','response_activity.csv']
for n in names:
    rows=list(csv.DictReader((R/'data'/n).open(encoding='utf-8')))
    assert len(rows)==500,(n,len(rows))
svc=list(csv.DictReader((R/'data'/'endpoint_service.csv').open(encoding='utf-8')))
assert any(x['event_id']=='SVC-INC-001' and x['service_name']=='WinSupportSvc' for x in svc)
assert any(x['event_id']=='SVC-BEN-001' and x['classification']=='benign' for x in svc)
proc=list(csv.DictReader((R/'data'/'endpoint_process.csv').open(encoding='utf-8')))
assert any(x['event_id']=='PROC-INC-001' and x['process_name']=='sc.exe' for x in proc)
assert any(x['event_id']=='PROC-BEN-001' and x['parent_process_name']=='CcmExec.exe' for x in proc)
print('PASS: 8 lookups x 500 = 4,000 records; malicious service and SCCM look-alike present')
