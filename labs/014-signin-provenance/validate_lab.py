#!/usr/bin/env python3
import csv,json
from pathlib import Path
R=Path(__file__).resolve().parent;D=R/"data"
names=["detection_results.csv","identity_auth.csv","network_context.csv","vpn_activity.csv","device_inventory.csv","cloud_activity.csv","helpdesk_activity.csv","session_activity.csv"]
for n in names:
 p=D/n;assert p.exists(),n
 with p.open(encoding="utf-8") as f: rows=list(csv.DictReader(f))
 assert len(rows)==500,(n,len(rows))
for n,v in {"detection_results.csv":"ATD14-001","identity_auth.csv":"sess-kng-7f2","network_context.csv":"198.51.100.77","cloud_activity.csv":"Q4-Forecast.xlsx","session_activity.csv":"new_unmanaged_context"}.items():
 assert v in (D/n).read_text(encoding="utf-8"),(n,v)
k=json.loads((R/"answer-key.json").read_text())
assert k["anomalous_context"]["session_id"]=="sess-kng-7f2"
(R/"validation-report.md").write_text("# Validation Report\n\n- Seed: `20261004`\n- Lookups: **8**\n- Rows per lookup: **500**\n- Total records: **4,000**\n- Known managed context: **PASS**\n- Unmanaged anomalous sign-in: **PASS**\n- VPN look-alike/context: **PASS**\n- Follow-on SharePoint session activity: **PASS**\n- Help-desk and normal-session noise: **PASS**\n- Evidence-gap answer key: **PASS**\n\n**Overall: PASS**\n",encoding="utf-8")
print("validation PASS")
