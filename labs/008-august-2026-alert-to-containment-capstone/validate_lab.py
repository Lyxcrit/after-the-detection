from pathlib import Path
import csv
R=Path(__file__).parent
names=['detection_results.csv','identity_auth.csv','endpoint_process.csv','endpoint_file.csv','network_activity.csv','identity_admin.csv','response_activity.csv','investigation_findings.csv']
for n in names:
    assert len(list(csv.DictReader((R/'data'/n).open())))==10000,n
print('PASS: 8 x 10,000 = 80,000 records')
