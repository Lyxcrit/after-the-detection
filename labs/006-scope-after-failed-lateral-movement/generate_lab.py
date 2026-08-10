from pathlib import Path
from datetime import datetime, timedelta, timezone
import csv, random, hashlib, json, textwrap

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
APP = ROOT / "splunk" / "after_detection_hunt_006"
APP_LOOKUPS = APP / "lookups"
for p in [DATA, APP_LOOKUPS, APP/"default"/"data"/"ui"/"nav", APP/"default"/"data"/"ui"/"views", APP/"metadata"]:
    p.mkdir(parents=True, exist_ok=True)

SEED = 20260810
ROWS = 1500
rng = random.Random(SEED)
base = datetime(2026, 8, 11, 13, 0, tzinfo=timezone.utc)
t0 = base + timedelta(hours=2, minutes=23)
hosts = ["FIN-WS-14","APP-API-02","APP-API-03","JUMP-01","DEPLOY-01","FILE-02"]
users = ["ACME\\mrivera","ACME\\svc_deploy","ACME\\svc_backup","ACME\\jsmith","NT AUTHORITY\\SYSTEM"]

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")

def write_csv(name, rows):
    fields = list(rows[0].keys())
    for dest in [DATA/name, APP_LOOKUPS/name]:
        with dest.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)

auth=[]
for i in range(ROWS-4):
    auth.append({"event_id":f"AUTH-{i+1:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"src_host":rng.choice(hosts),"dest_host":rng.choice(hosts),"user":rng.choice(users),"protocol":rng.choice(["Kerberos","NTLM","WinRM","RDP"]),"result":rng.choice(["success","success","success","failure"]),"source_ip":f"10.50.{rng.randint(1,50)}.{rng.randint(2,240)}","classification":"benign","note":"routine authentication"})
auth += [
    {"event_id":"AUTH-INC-001","_time":iso(t0),"src_host":"FIN-WS-14","dest_host":"APP-API-02","user":"ACME\\mrivera","protocol":"WinRM","result":"failure","source_ip":"10.50.20.14","classification":"scope","note":"failed movement attempt"},
    {"event_id":"AUTH-INC-002","_time":iso(t0+timedelta(seconds=18)),"src_host":"FIN-WS-14","dest_host":"APP-API-03","user":"ACME\\mrivera","protocol":"WinRM","result":"failure","source_ip":"10.50.20.14","classification":"scope","note":"second failed movement attempt"},
    {"event_id":"AUTH-CTX-001","_time":iso(t0+timedelta(minutes=2)),"src_host":"DEPLOY-01","dest_host":"APP-API-02","user":"ACME\\svc_deploy","protocol":"WinRM","result":"success","source_ip":"10.50.10.25","classification":"benign","note":"approved deployment"},
    {"event_id":"AUTH-RESP-001","_time":iso(t0+timedelta(minutes=12)),"src_host":"JUMP-01","dest_host":"APP-API-02","user":"ACME\\jsmith","protocol":"RDP","result":"success","source_ip":"10.50.10.8","classification":"response","note":"authorized responder validation"}]
auth.sort(key=lambda x:x["_time"])
write_csv("identity_auth.csv",auth)

proc=[]
for i in range(ROWS-5):
    proc.append({"event_id":f"PROC-{i+1:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"host":rng.choice(hosts),"user":rng.choice(users),"parent_process_name":rng.choice(["services.exe","wsmprovhost.exe","explorer.exe","taskeng.exe"]),"process_name":rng.choice(["w3wp.exe","powershell.exe","backup-agent.exe","msiexec.exe"]),"process_id":str(rng.randint(1000,15000)),"command_line":"routine process","classification":"benign","note":"routine process"})
proc += [
    {"event_id":"PROC-INC-001","_time":iso(t0-timedelta(minutes=5)),"host":"FIN-WS-14","user":"ACME\\mrivera","parent_process_name":"powershell.exe","process_name":"rundll32.exe","process_id":"7712","command_line":"rundll32.exe C:\\ProgramData\\Cache\\stage.dll,Start","classification":"malicious","note":"known compromised source host"},
    {"event_id":"PROC-CTX-001","_time":iso(t0+timedelta(minutes=2,seconds=5)),"host":"APP-API-02","user":"ACME\\svc_deploy","parent_process_name":"wsmprovhost.exe","process_name":"powershell.exe","process_id":"9140","command_line":"powershell.exe -File C:\\Deploy\\Install-Agent.ps1","classification":"benign","note":"approved deployment"},
    {"event_id":"PROC-RESP-001","_time":iso(t0+timedelta(minutes=12,seconds=30)),"host":"APP-API-02","user":"ACME\\jsmith","parent_process_name":"explorer.exe","process_name":"cmd.exe","process_id":"9320","command_line":"cmd.exe /c whoami && netstat -ano","classification":"response","note":"responder triage"},
    {"event_id":"PROC-CTX-002","_time":iso(t0+timedelta(minutes=3)),"host":"APP-API-03","user":"NT AUTHORITY\\SYSTEM","parent_process_name":"services.exe","process_name":"w3wp.exe","process_id":"5104","command_line":"w3wp.exe -ap API3","classification":"benign","note":"normal app process"},
    {"event_id":"PROC-CTX-003","_time":iso(t0+timedelta(minutes=4)),"host":"APP-API-02","user":"NT AUTHORITY\\SYSTEM","parent_process_name":"services.exe","process_name":"backup-agent.exe","process_id":"5220","command_line":"backup-agent.exe --inventory","classification":"benign","note":"scheduled backup"}]
proc.sort(key=lambda x:x["_time"])
write_csv("endpoint_process.csv",proc)

net=[]
for i in range(ROWS-3):
    net.append({"event_id":f"NET-{i+1:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"src_host":rng.choice(hosts),"dest_host":rng.choice(hosts),"user":rng.choice(users),"process_name":rng.choice(["powershell.exe","w3wp.exe","backup-agent.exe"]),"dest_port":rng.choice(["443","445","5985"]),"action":"allowed","bytes_out":str(rng.randint(100,90000)),"classification":"benign","note":"routine network"})
net += [
    {"event_id":"NET-INC-001","_time":iso(t0),"src_host":"FIN-WS-14","dest_host":"APP-API-02","user":"ACME\\mrivera","process_name":"powershell.exe","dest_port":"5985","action":"blocked","bytes_out":"812","classification":"scope","note":"matches failed WinRM"},
    {"event_id":"NET-INC-002","_time":iso(t0+timedelta(seconds=18)),"src_host":"FIN-WS-14","dest_host":"APP-API-03","user":"ACME\\mrivera","process_name":"powershell.exe","dest_port":"5985","action":"blocked","bytes_out":"790","classification":"scope","note":"matches failed WinRM"},
    {"event_id":"NET-CTX-001","_time":iso(t0+timedelta(minutes=2)),"src_host":"DEPLOY-01","dest_host":"APP-API-02","user":"ACME\\svc_deploy","process_name":"powershell.exe","dest_port":"5985","action":"allowed","bytes_out":"12022","classification":"benign","note":"approved deployment"}]
net.sort(key=lambda x:x["_time"])
write_csv("network_activity.csv",net)

files=[]
for i in range(ROWS-3):
    files.append({"event_id":f"FILE-{i+1:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"host":rng.choice(hosts),"user":rng.choice(users),"action":rng.choice(["create","modify","read"]),"file_path":rng.choice(["C:\\Deploy\\agent.msi","C:\\Windows\\Temp\\app.log","C:\\Backup\\state.db"]),"source_process":rng.choice(["powershell.exe","msiexec.exe","backup-agent.exe"]),"classification":"benign","note":"routine file"})
files += [
    {"event_id":"FILE-CTX-001","_time":iso(t0+timedelta(minutes=2,seconds=12)),"host":"APP-API-02","user":"ACME\\svc_deploy","action":"create","file_path":"C:\\Deploy\\agent.msi","source_process":"powershell.exe","classification":"benign","note":"approved deployment artifact"},
    {"event_id":"FILE-RESP-001","_time":iso(t0+timedelta(minutes=13)),"host":"APP-API-02","user":"ACME\\jsmith","action":"create","file_path":"C:\\IR\\triage.txt","source_process":"cmd.exe","classification":"response","note":"responder collection"},
    {"event_id":"FILE-CTX-002","_time":iso(t0+timedelta(minutes=4)),"host":"APP-API-03","user":"NT AUTHORITY\\SYSTEM","action":"modify","file_path":"C:\\Windows\\Temp\\api3.log","source_process":"w3wp.exe","classification":"benign","note":"normal app logging"}]
files.sort(key=lambda x:x["_time"])
write_csv("endpoint_file.csv",files)

dets=[]
for i in range(ROWS-5):
    dets.append({"detection_id":f"ATD-006-{i+10:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"severity":rng.choice(["low","medium"]),"title":rng.choice(["Failed Remote Auth Review","PowerShell Review","New File Review"]),"host":rng.choice(hosts),"user":rng.choice(users),"expected_decision":"context","note":"background detection"})
dets += [
    {"detection_id":"ATD-006-001","_time":iso(t0),"severity":"high","title":"WinRM Attempt from Confirmed Compromised Host","host":"APP-API-02","user":"ACME\\mrivera","expected_decision":"scope","note":"failed auth; destination not confirmed compromised"},
    {"detection_id":"ATD-006-002","_time":iso(t0+timedelta(seconds=18)),"severity":"high","title":"Second WinRM Attempt from Confirmed Compromised Host","host":"APP-API-03","user":"ACME\\mrivera","expected_decision":"scope","note":"failed auth"},
    {"detection_id":"ATD-006-003","_time":iso(t0+timedelta(minutes=2)),"severity":"medium","title":"Successful WinRM to APP-API-02","host":"APP-API-02","user":"ACME\\svc_deploy","expected_decision":"context","note":"approved deployment"},
    {"detection_id":"ATD-006-004","_time":iso(t0+timedelta(minutes=12)),"severity":"medium","title":"Interactive Admin on Scoped Host","host":"APP-API-02","user":"ACME\\jsmith","expected_decision":"response","note":"authorized responder"},
    {"detection_id":"ATD-006-005","_time":iso(t0-timedelta(minutes=5)),"severity":"critical","title":"Known Compromise on FIN-WS-14","host":"FIN-WS-14","user":"ACME\\mrivera","expected_decision":"confirmed","note":"source host already confirmed"}]
dets.sort(key=lambda x:x["_time"])
write_csv("detection_results.csv",dets)

assets=[]
for i in range(ROWS):
    h=hosts[i%len(hosts)] if i<100 else f"LAB-ASSET-{i:04d}"
    assets.append({"asset_id":f"AST-{i+1:05d}","host":h,"role":"application server" if "APP-" in h else "workstation","owner":rng.choice(["Finance","App Team","IT Ops"]),"criticality":rng.choice(["medium","high"]),"expected_admin_sources":"DEPLOY-01;JUMP-01","note":"synthetic asset context"})
write_csv("asset_inventory.csv",assets)

findings=[]
for i in range(ROWS-6):
    findings.append({"finding_id":f"F-{i+100:05d}","host":rng.choice(hosts),"evidence":"routine context","expected_decision":"context","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"","note":"practice row"})
findings += [
    {"finding_id":"F-001","host":"FIN-WS-14","evidence":"known malicious rundll32 chain","expected_decision":"confirmed compromised","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"","note":"source host"},
    {"finding_id":"F-002","host":"APP-API-02","evidence":"failed WinRM from FIN-WS-14","expected_decision":"scope further","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"no successful auth from compromised source","note":"do not overstate"},
    {"finding_id":"F-003","host":"APP-API-03","evidence":"failed WinRM from FIN-WS-14","expected_decision":"scope further","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"no successful auth or remote process","note":"do not overstate"},
    {"finding_id":"F-004","host":"APP-API-02","evidence":"successful WinRM from DEPLOY-01 using svc_deploy","expected_decision":"approved activity","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"","note":"nearby but unrelated"},
    {"finding_id":"F-005","host":"APP-API-02","evidence":"responder RDP and triage after alert","expected_decision":"authorized response","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"","note":"response activity"},
    {"finding_id":"F-006","host":"APP-API-02","evidence":"no matching malicious process/file evidence","expected_decision":"not confirmed compromised","expected_confidence":"high","analyst_decision":"","analyst_confidence":"","evidence_gap":"more EDR/network retention could raise confidence","note":"scope boundary"}]
write_csv("investigation_findings.csv",findings)

resp=[]
for i in range(ROWS-3):
    resp.append({"event_id":f"RESP-{i+1:05d}","_time":iso(base+timedelta(seconds=rng.randint(0,6*86400))),"host":rng.choice(hosts),"user":"SOC-AUTOMATION","action":rng.choice(["review_alert","collect_logs","query_process"]),"classification":"response","note":"routine response"})
resp += [
    {"event_id":"RESP-INC-001","_time":iso(t0+timedelta(minutes=8)),"host":"FIN-WS-14","user":"SOC-AUTOMATION","action":"isolate_host","classification":"response","note":"confirmed source isolated"},
    {"event_id":"RESP-INC-002","_time":iso(t0+timedelta(minutes=10)),"host":"APP-API-02","user":"ACME\\jsmith","action":"scope_destination","classification":"response","note":"review without isolating"},
    {"event_id":"RESP-INC-003","_time":iso(t0+timedelta(minutes=10)),"host":"APP-API-03","user":"ACME\\jsmith","action":"scope_destination","classification":"response","note":"review without isolating"}]
resp.sort(key=lambda x:x["_time"])
write_csv("response_activity.csv",resp)

write_text(ROOT/"README.md", '''
# Hunt 006: Scope After Failed Lateral Movement

**Difficulty:** Guided, moderate noise  
**Expected time:** 25–40 minutes  
**Confirmed source host:** `FIN-WS-14`

`FIN-WS-14` is already confirmed compromised. It attempts WinRM to `APP-API-02` and `APP-API-03`; both authentications fail.

Nearby telemetry includes a successful approved deployment to `APP-API-02`, normal application activity, and responder access. Decide what belongs in confirmed scope and what only requires additional review.

## Quick start

1. Start with `detection_results.csv`.
2. Compare source, user, result, and timing in `identity_auth.csv`.
3. Correlate `network_activity.csv`.
4. Review processes and files on both destinations.
5. Separate deployment and responder activity.
6. Record a confidence decision for each host.

## Data

Eight platform-portable CSV lookups contain 1,500 records each, for 12,000 total synthetic events.
''')
write_text(ROOT/"attack-narrative.md", '''
# Attack Narrative

`FIN-WS-14` is confirmed compromised before the hunt begins. The compromised user's session attempts WinRM against `APP-API-02` and `APP-API-03`; both attempts fail.

Two minutes later, `APP-API-02` receives successful WinRM from `DEPLOY-01` using `ACME\\svc_deploy`, followed by an approved agent installation. Later, a responder connects from `JUMP-01`.

Do not merge unrelated successful sessions into the attacker's failed attempts just because they use the same destination and protocol.
''')
write_text(ROOT/"analyst-hunt-guide.md", '''
# Analyst Hunt Guide

1. Treat `FIN-WS-14` as confirmed compromised.
2. Identify destination, user, source, protocol, and result for the WinRM attempts.
3. Search destinations for successful authentication from the compromised source, remote processes, new files, or persistence.
4. Explain the successful deployment and later responder session.
5. Assign scope and confidence for each destination.
6. State what missing evidence would change the decision.
''')
write_text(ROOT/"investigation-worksheet.md", '''
# Investigation Worksheet

| Host | Evidence for compromise | Benign/contrary evidence | Decision | Confidence | Missing evidence |
|---|---|---|---|---|---|
| FIN-WS-14 | | | | | |
| APP-API-02 | | | | | |
| APP-API-03 | | | | | |

## Timeline
## Authentication comparison
## Process/file review
## Response activity
## Final scope statement
''')
write_text(ROOT/"data-dictionary.md", '''
# Data Dictionary

Eight platform-portable CSV lookups are included:

- `asset_inventory.csv`
- `identity_auth.csv`
- `network_activity.csv`
- `endpoint_process.csv`
- `endpoint_file.csv`
- `detection_results.csv`
- `investigation_findings.csv`
- `response_activity.csv`

All timestamps are UTC ISO 8601. Each lookup contains 1,500 rows.
''')
write_text(ROOT/"sample-spl.md", '''
# Sample SPL

## Starting detections

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search detection_id="ATD-006-*"
| sort 0 _time
```

## Authentication comparison

```spl
| inputlookup identity_auth.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search dest_host IN ("APP-API-02","APP-API-03")
| sort 0 _time
| table _time src_host dest_host user protocol result classification note
```
''')
write_text(ROOT/"response-plan.md", '''
# Response Plan / Expected Decision

`FIN-WS-14` is confirmed compromised and should be contained.

`APP-API-02` and `APP-API-03` require scoping because the compromised source attempted WinRM access. The supplied evidence does not confirm either destination as compromised.

The successful WinRM on `APP-API-02` comes from `DEPLOY-01` using `ACME\\svc_deploy` and is followed by the expected deployment process and artifact. Later activity comes from an authorized responder.

Do not isolate production application servers solely because a failed authentication originated from a compromised host.
''')
write_text(ROOT/"answer-key.json", json.dumps({"seed":SEED,"rows_per_lookup":ROWS,"lookup_count":8,"confirmed_compromised":["FIN-WS-14"],"scope_required_not_confirmed":["APP-API-02","APP-API-03"],"key_decision":"Failed WinRM from a confirmed compromised host is attempted movement, not proof of destination compromise."}, indent=2))
write_text(ROOT/"validate_lab.py", '''
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
''')
write_text(ROOT/"validation-report.md", f'''# Validation Report

- Deterministic seed: **{SEED}**
- Lookups: **8**
- Rows per lookup: **1,500**
- Total records: **12,000**
- Failed attacker WinRM attempts: **present**
- Approved deployment look-alike: **present**
- Responder activity: **present**
''')
write_text(APP/"default"/"app.conf", '''[install]
is_configured = 0
[ui]
is_visible = 1
label = After the Detection - Hunt 006
[launcher]
author = WiseHawk Technologies
version = 1.0.0
description = Hunt 006 - Scope After Failed Lateral Movement
''')
write_text(APP/"metadata"/"default.meta", '''[]
access = read : [ * ], write : [ admin ]
export = system
''')
write_text(APP/"default"/"data"/"ui"/"nav"/"default.xml", '''<nav search_view="search"><view name="hunt_006_overview" default="true"/><view name="search"/></nav>''')
write_text(APP/"default"/"data"/"ui"/"views"/"hunt_006_overview.xml", '''<form version="1.1" theme="dark"><label>Hunt 006 — Scope After Failed Lateral Movement</label><row><panel><table><search><query>| inputlookup detection_results.csv | search detection_id="ATD-006-*" | table _time severity title host user expected_decision note</query></search></table></panel></row></form>''')
write_text(APP/"README.md", '''# Splunk Lab App

Copy `after_detection_hunt_006` into `$SPLUNK_HOME/etc/apps/` and restart Splunk. The app uses bundled CSV lookups and requires no index or add-on.
''')
manifest=[]
for p in sorted(ROOT.rglob("*")):
    if p.is_file() and p.name != "manifest.json":
        manifest.append({"path":str(p.relative_to(ROOT)),"sha256":hashlib.sha256(p.read_bytes()).hexdigest(),"bytes":p.stat().st_size})
(ROOT/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
print("Generated Hunt 006 with 12,000 records")
