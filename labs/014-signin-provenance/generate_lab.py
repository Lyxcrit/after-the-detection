#!/usr/bin/env python3
import csv,random
from pathlib import Path
from datetime import datetime,timedelta,timezone
SEED=20261004; ROWS=500; random.seed(SEED)
ROOT=Path(__file__).resolve().parent; DATA=ROOT/"data"; DATA.mkdir(exist_ok=True)
base=datetime(2026,10,4,13,0,tzinfo=timezone.utc)
def ts(m,s=0): return (base+timedelta(minutes=m,seconds=s)).isoformat().replace("+00:00","Z")
def write(n,f,rows):
 assert len(rows)==ROWS,(n,len(rows))
 with (DATA/n).open("w",newline="",encoding="utf-8") as h:
  w=csv.DictWriter(h,fieldnames=f);w.writeheader();w.writerows(rows)
users=[r"ACME\knguyen",r"ACME\mrivera",r"ACME\lchen",r"ACME\rlee"]
hosts=["SALES-WS-18","FIN-WS-09","DEV-WS-12","MOBILE"]
# detections
f=["_time","detection_id","user","rule_name","severity","session_id"]
r=[{"_time":ts(i%240,i%59),"detection_id":f"ATD14-N{i:03d}","user":random.choice(users),"rule_name":"Routine identity analytic","severity":"low","session_id":f"sess-normal-{i:03d}"} for i in range(ROWS)]
r[220]={"_time":ts(192),"detection_id":"ATD14-001","user":r"ACME\knguyen","rule_name":"Successful Sign-In From New Unmanaged Context","severity":"high","session_id":"sess-kng-7f2"};write("detection_results.csv",f,r)
# auth
f=["_time","user","app","result","source_ip","device_name","device_state","os","auth_method","session_id"]
r=[{"_time":ts(i%240,i%53),"user":random.choice(users),"app":random.choice(["Microsoft 365","SharePoint","Teams"]),"result":"success","source_ip":random.choice(["203.0.113.10","203.0.113.22","192.0.2.44"]),"device_name":random.choice(hosts),"device_state":random.choice(["managed","managed","mobile"]),"os":random.choice(["Windows","iOS"]),"auth_method":"MFA","session_id":f"sess-normal-{i:03d}"} for i in range(ROWS)]
r[230]={"_time":ts(168),"user":r"ACME\knguyen","app":"Microsoft 365","result":"success","source_ip":"203.0.113.10","device_name":"SALES-WS-18","device_state":"managed","os":"Windows","auth_method":"MFA","session_id":"sess-kng-normal"}
r[231]={"_time":ts(192),"user":r"ACME\knguyen","app":"Microsoft 365","result":"success","source_ip":"198.51.100.77","device_name":"UNKNOWN-WIN","device_state":"unmanaged","os":"Windows","auth_method":"MFA","session_id":"sess-kng-7f2"};write("identity_auth.csv",f,r)
# network context
f=["_time","source_ip","context","owner","expected"]
r=[{"_time":ts(i%240,i%47),"source_ip":random.choice(["203.0.113.10","203.0.113.22","192.0.2.44"]),"context":random.choice(["corporate_egress","carrier","partner"]),"owner":"ACME","expected":"true"} for i in range(ROWS)]
r[240]={"_time":ts(192),"source_ip":"198.51.100.77","context":"unclassified_external","owner":"unknown","expected":"false"};write("network_context.csv",f,r)
# vpn
f=["_time","user","assigned_ip","vpn_gateway","result","device_name"]
r=[{"_time":ts(i%240,i%43),"user":random.choice(users),"assigned_ip":f"192.0.2.{20+i%80}","vpn_gateway":"vpn-east","result":"success","device_name":random.choice(hosts[:3])} for i in range(ROWS)]
r[250]={"_time":ts(150),"user":r"ACME\knguyen","assigned_ip":"192.0.2.61","vpn_gateway":"vpn-east","result":"disconnect","device_name":"SALES-WS-18"};write("vpn_activity.csv",f,r)
# device inventory
f=["_time","user","device_name","managed","compliant","platform","last_seen"]
r=[{"_time":ts(i%240,i%41),"user":random.choice(users),"device_name":random.choice(hosts[:3]),"managed":"true","compliant":"true","platform":"Windows","last_seen":ts(i%240)} for i in range(ROWS)]
r[260]={"_time":ts(167),"user":r"ACME\knguyen","device_name":"SALES-WS-18","managed":"true","compliant":"true","platform":"Windows","last_seen":ts(168)};write("device_inventory.csv",f,r)
# cloud
f=["_time","user","app","action","resource","session_id","source_ip"]
r=[{"_time":ts(i%240,i%37),"user":random.choice(users),"app":random.choice(["SharePoint","Teams","OneDrive"]),"action":random.choice(["read","list","sync"]),"resource":f"doc-{i%50}","session_id":f"sess-normal-{i:03d}","source_ip":random.choice(["203.0.113.10","192.0.2.44"])} for i in range(ROWS)]
r[270]={"_time":ts(195),"user":r"ACME\knguyen","app":"SharePoint","action":"read","resource":"Sales/Q4-Forecast.xlsx","session_id":"sess-kng-7f2","source_ip":"198.51.100.77"}
r[271]={"_time":ts(196),"user":r"ACME\knguyen","app":"SharePoint","action":"read","resource":"Sales/Customer-Renewals.xlsx","session_id":"sess-kng-7f2","source_ip":"198.51.100.77"};write("cloud_activity.csv",f,r)
# helpdesk
f=["_time","ticket","user","technician","action","approved","source"]
r=[{"_time":ts(i%240,i%31),"ticket":f"HD-{4000+i}","user":random.choice(users),"technician":r"ACME\helpdesk","action":random.choice(["password_reset","device_enrollment","mfa_support"]),"approved":"true","source":"HELPDESK-01"} for i in range(ROWS)]
r[280]={"_time":ts(188),"ticket":"HD-4481","user":r"ACME\mrivera","technician":r"ACME\helpdesk","action":"password_reset","approved":"true","source":"HELPDESK-01"};write("helpdesk_activity.csv",f,r)
# sessions
f=["_time","user","session_id","state","device_name","source_ip","reason"]
r=[{"_time":ts(i%240,i%29),"user":random.choice(users),"session_id":f"sess-normal-{i:03d}","state":random.choice(["active","refresh","closed"]),"device_name":random.choice(hosts),"source_ip":random.choice(["203.0.113.10","192.0.2.44"]),"reason":"normal"} for i in range(ROWS)]
r[290]={"_time":ts(195),"user":r"ACME\knguyen","session_id":"sess-kng-7f2","state":"active","device_name":"UNKNOWN-WIN","source_ip":"198.51.100.77","reason":"new_unmanaged_context"};write("session_activity.csv",f,r)
print("generated",ROWS*8,"records")
