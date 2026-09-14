from pathlib import Path
from datetime import datetime, timedelta, timezone
import csv, random, json, textwrap

ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"
APP=ROOT/"splunk"/"after_detection_hunt_011"
LOOK=APP/"lookups"
SEED=20260914
ROWS=500
rng=random.Random(SEED)
base=datetime(2026,9,14,12,0,tzinfo=timezone.utc)
focus=base+timedelta(hours=2,minutes=18)
hosts=["FIN-WS-09","HR-WS-04","ENG-WS-17","JUMP-01","DC-01","MGMT-01"]
users=[r"ACME\\lchen",r"ACME\\jsmith",r"ACME\\mgarcia","SYSTEM"]

def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")
def nt(): return iso(base+timedelta(seconds=rng.randint(0,4*86400)))
def write_csv(name,special,noise):
    rows=[noise(i) for i in range(ROWS-len(special))]+special
    if "_time" in rows[0]: rows.sort(key=lambda r:r["_time"])
    DATA.mkdir(parents=True,exist_ok=True); LOOK.mkdir(parents=True,exist_ok=True)
    fields=list(rows[0])
    for dest in (DATA/name,LOOK/name):
        with dest.open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def wt(path,s):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(textwrap.dedent(s).strip()+"\n",encoding="utf-8")

write_csv("detection_results.csv",[
{"detection_id":"ATD11-001","_time":iso(focus),"severity":"medium","title":"New User Startup Item","host":"FIN-WS-09","user":r"ACME\\lchen","classification":"investigate","note":"new item requires provenance review"},
{"detection_id":"ATD11-002","_time":iso(focus+timedelta(minutes=12)),"severity":"high","title":"Startup Item Executes Untrusted Script","host":"FIN-WS-09","user":r"ACME\\lchen","classification":"investigate","note":"logon execution observed"},
{"detection_id":"ATD11-003","_time":iso(focus+timedelta(minutes=13)),"severity":"high","title":"Startup Process External TLS","host":"FIN-WS-09","user":r"ACME\\lchen","classification":"investigate","note":"external session from suspicious chain"},
{"detection_id":"ATD11-004","_time":iso(focus+timedelta(minutes=19)),"severity":"medium","title":"Responder Preserves Startup Configuration","host":"FIN-WS-09","user":r"ACME\\jsmith","classification":"response","note":"configuration preserved"},
{"detection_id":"ATD11-005","_time":iso(focus+timedelta(minutes=22)),"severity":"high","title":"Startup Scope Decision","host":"FIN-WS-09","user":r"ACME\\lchen","classification":"decision","note":"local user persistence supported; central policy compromise not supported"}],
lambda i:{"detection_id":f"ATD11-{i+100:04d}","_time":nt(),"severity":rng.choice(["low","medium"]),"title":rng.choice(["Startup Review","Policy Review","Application Startup Review"]),"host":rng.choice(hosts),"user":rng.choice(users),"classification":"context","note":"background"})

write_csv("startup_config.csv",[
{"event_id":"CFG-INC-001","_time":iso(focus),"host":"FIN-WS-09","user":r"ACME\\lchen","source_type":"User startup configuration","item_name":"OneDriveHealth","target_path":r"C:\\Users\\lchen\\AppData\\Roaming\\Microsoft\\OneDriveHealth\\sync.ps1","provenance":"local user state","classification":"investigate"},
{"event_id":"CFG-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=45)),"host":"FIN-WS-09","user":r"ACME\\lchen","source_type":"Enterprise logon policy","item_name":"MapDrives","target_path":r"SYSVOL\\scripts\\mapdrives.cmd","provenance":"central policy","classification":"benign"},
{"event_id":"CFG-BEN-002","_time":iso(focus+timedelta(minutes=12,seconds=5)),"host":"FIN-WS-09","user":r"ACME\\lchen","source_type":"Application startup","item_name":"Teams","target_path":"Microsoft Teams Update","provenance":"signed application","classification":"benign"},
{"event_id":"CFG-BEN-003","_time":iso(focus+timedelta(minutes=12,seconds=7)),"host":"FIN-WS-09","user":r"ACME\\lchen","source_type":"Startup folder","item_name":"DisplayProfile","target_path":"ACME DisplayProfile","provenance":"approved user utility","classification":"benign"}],
lambda i:{"event_id":f"CFG-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":rng.choice(users),"source_type":rng.choice(["Application startup","Enterprise logon policy","Startup folder"]),"item_name":rng.choice(["Teams","OneDrive","MapDrives","DisplayProfile"]),"target_path":"routine startup target","provenance":"approved","classification":"benign"})

write_csv("startup_items.csv",[
{"event_id":"ITEM-INC-001","_time":iso(focus+timedelta(minutes=12)),"host":"FIN-WS-09","user":r"ACME\\lchen","item_name":"OneDriveHealth","event":"started","managed_by":"local user state","classification":"investigate"},
{"event_id":"ITEM-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=45)),"host":"FIN-WS-09","user":r"ACME\\lchen","item_name":"MapDrives","event":"started","managed_by":"Group Policy","classification":"benign"},
{"event_id":"ITEM-BEN-002","_time":iso(focus+timedelta(minutes=12,seconds=5)),"host":"FIN-WS-09","user":r"ACME\\lchen","item_name":"Teams","event":"started","managed_by":"Microsoft application","classification":"benign"},
{"event_id":"ITEM-BEN-003","_time":iso(focus+timedelta(minutes=12,seconds=7)),"host":"FIN-WS-09","user":r"ACME\\lchen","item_name":"DisplayProfile","event":"started","managed_by":"IT approved","classification":"benign"}],
lambda i:{"event_id":f"ITEM-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":rng.choice(users),"item_name":rng.choice(["Teams","OneDrive","MapDrives","DisplayProfile"]),"event":"started","managed_by":"approved","classification":"benign"})

write_csv("endpoint_process.csv",[
{"event_id":"PROC-INC-001","_time":iso(focus+timedelta(minutes=12)),"host":"FIN-WS-09","user":r"ACME\\lchen","parent_process":"explorer.exe","process_name":"powershell.exe","command_line":"launch synthetic startup script","classification":"investigate"},
{"event_id":"PROC-INC-002","_time":iso(focus+timedelta(minutes=12,seconds=18)),"host":"FIN-WS-09","user":r"ACME\\lchen","parent_process":"powershell.exe","process_name":"rundll32.exe","command_line":"execute synthetic secondary artifact","classification":"investigate"},
{"event_id":"PROC-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=45)),"host":"FIN-WS-09","user":r"ACME\\lchen","parent_process":"userinit.exe","process_name":"cmd.exe","command_line":"enterprise drive mapping script","classification":"benign"},
{"event_id":"PROC-BEN-002","_time":iso(focus+timedelta(minutes=12,seconds=5)),"host":"FIN-WS-09","user":r"ACME\\lchen","parent_process":"explorer.exe","process_name":"Update.exe","command_line":"signed application updater","classification":"benign"},
{"event_id":"PROC-BEN-003","_time":iso(focus+timedelta(minutes=12,seconds=7)),"host":"FIN-WS-09","user":r"ACME\\lchen","parent_process":"explorer.exe","process_name":"profile.exe","command_line":"approved display utility","classification":"benign"}],
lambda i:{"event_id":f"PROC-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":rng.choice(users),"parent_process":"explorer.exe","process_name":rng.choice(["Teams.exe","OneDrive.exe","cmd.exe","profile.exe"]),"command_line":"routine process","classification":"benign"})

write_csv("endpoint_file.csv",[
{"event_id":"FILE-INC-001","_time":iso(focus-timedelta(seconds=25)),"host":"FIN-WS-09","user":r"ACME\\lchen","action":"create","file_path":r"C:\\Users\\lchen\\AppData\\Roaming\\Microsoft\\OneDriveHealth\\sync.ps1","source_process":"user-context process","classification":"investigate"},
{"event_id":"FILE-INC-002","_time":iso(focus-timedelta(seconds=20)),"host":"FIN-WS-09","user":r"ACME\\lchen","action":"create","file_path":r"C:\\Users\\lchen\\AppData\\Roaming\\Microsoft\\OneDriveHealth\\cache.dat","source_process":"user-context process","classification":"investigate"},
{"event_id":"FILE-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=45)),"host":"FIN-WS-09","user":r"ACME\\lchen","action":"read","file_path":r"SYSVOL\\scripts\\mapdrives.cmd","source_process":"cmd.exe","classification":"benign"},
{"event_id":"FILE-BEN-002","_time":iso(focus-timedelta(days=1)),"host":"FIN-WS-09","user":r"ACME\\lchen","action":"create","file_path":r"Startup\\DisplayProfile.lnk","source_process":"explorer.exe","classification":"benign"}],
lambda i:{"event_id":f"FILE-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":rng.choice(users),"action":rng.choice(["read","create","modify"]),"file_path":"routine user or enterprise file","source_process":"routine process","classification":"benign"})

write_csv("software_trust.csv",[
{"event_id":"TRUST-INC-001","_time":iso(focus-timedelta(seconds=18)),"host":"FIN-WS-09","file_path":r"OneDriveHealth\\sync.ps1","trust_status":"untrusted","publisher":"","classification":"investigate"},
{"event_id":"TRUST-INC-002","_time":iso(focus-timedelta(seconds=17)),"host":"FIN-WS-09","file_path":r"OneDriveHealth\\cache.dat","trust_status":"untrusted","publisher":"","classification":"investigate"},
{"event_id":"TRUST-BEN-001","_time":iso(focus-timedelta(hours=1)),"host":"FIN-WS-09","file_path":"Microsoft Teams Update","trust_status":"signed","publisher":"Microsoft Corporation","classification":"benign"},
{"event_id":"TRUST-BEN-002","_time":iso(focus-timedelta(days=1)),"host":"FIN-WS-09","file_path":"ACME DisplayProfile","trust_status":"trusted_internal","publisher":"ACME IT Automation","classification":"benign"}],
lambda i:{"event_id":f"TRUST-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"file_path":"known application","trust_status":rng.choice(["signed","trusted_internal"]),"publisher":"Known Publisher","classification":"benign"})

write_csv("policy_context.csv",[
{"event_id":"POL-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=40)),"host":"FIN-WS-09","user":r"ACME\\lchen","policy_name":"User Drive Mapping","source":"central policy","approved":"yes","classification":"benign"},
{"event_id":"POL-GAP-001","_time":iso(focus+timedelta(minutes=18)),"host":"FIN-WS-09","user":r"ACME\\lchen","policy_name":"No matching enterprise policy","source":"OneDriveHealth is local user configuration","approved":"no","classification":"investigate"},
{"event_id":"POL-SCOPE-001","_time":iso(focus+timedelta(minutes=22)),"host":"FIN-WS-09","user":r"ACME\\jsmith","policy_name":"Scope decision","source":"no evidence of enterprise policy modification","approved":"n/a","classification":"decision"}],
lambda i:{"event_id":f"POL-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":rng.choice(users),"policy_name":rng.choice(["Drive Mapping","Desktop Baseline","Browser Settings"]),"source":"central policy","approved":"yes","classification":"benign"})

write_csv("network_activity.csv",[
{"event_id":"NET-INC-001","_time":iso(focus+timedelta(minutes=12,seconds=30)),"src_host":"FIN-WS-09","dest_host":"203.0.113.77","user":r"ACME\\lchen","process_name":"powershell.exe","dest_port":"443","bytes_out":"3670","classification":"investigate"},
{"event_id":"NET-INC-002","_time":iso(focus+timedelta(minutes=13,seconds=15)),"src_host":"FIN-WS-09","dest_host":"203.0.113.77","user":r"ACME\\lchen","process_name":"rundll32.exe","dest_port":"443","bytes_out":"10920","classification":"investigate"},
{"event_id":"NET-BEN-001","_time":iso(focus+timedelta(minutes=11,seconds=45)),"src_host":"FIN-WS-09","dest_host":"DC-01","user":r"ACME\\lchen","process_name":"cmd.exe","dest_port":"445","bytes_out":"2210","classification":"benign"},
{"event_id":"NET-BEN-002","_time":iso(focus+timedelta(minutes=12,seconds=5)),"src_host":"FIN-WS-09","dest_host":"198.51.100.20","user":r"ACME\\lchen","process_name":"Teams.exe","dest_port":"443","bytes_out":"8290","classification":"benign"}],
lambda i:{"event_id":f"NET-{i+100:04d}","_time":nt(),"src_host":rng.choice(hosts),"dest_host":rng.choice(["MGMT-01","DC-01","198.51.100.20"]),"user":rng.choice(users),"process_name":rng.choice(["Teams.exe","OneDrive.exe","cmd.exe"]),"dest_port":rng.choice(["443","445","53"]),"bytes_out":str(rng.randint(100,30000)),"classification":"benign"})

write_csv("response_activity.csv",[
{"event_id":"RESP-INC-001","_time":iso(focus+timedelta(minutes=18)),"host":"FIN-WS-09","user":r"ACME\\jsmith","action":"compare local startup to enterprise policy","classification":"response","note":"provenance review"},
{"event_id":"RESP-INC-002","_time":iso(focus+timedelta(minutes=19)),"host":"FIN-WS-09","user":r"ACME\\jsmith","action":"preserve startup configuration","classification":"response","note":"preserve before change"},
{"event_id":"RESP-INC-003","_time":iso(focus+timedelta(minutes=20)),"host":"FIN-WS-09","user":r"ACME\\jsmith","action":"collect suspicious artifacts","classification":"response","note":"artifact preservation"},
{"event_id":"RESP-INC-004","_time":iso(focus+timedelta(minutes=21)),"host":"FIN-WS-09","user":r"ACME\\jsmith","action":"remove startup item and isolate","classification":"response","note":"contain endpoint"},
{"event_id":"RESP-INC-005","_time":iso(focus+timedelta(minutes=22)),"host":"FIN-WS-09","user":r"ACME\\jsmith","action":"scope item path and destination","classification":"response","note":"estate-wide scope"}],
lambda i:{"event_id":f"RESP-{i+100:04d}","_time":nt(),"host":rng.choice(hosts),"user":"SOC","action":"routine review","classification":"response","note":"background"})

wt(ROOT/"README.md","""# Hunt 011: Startup Configuration Provenance

**Difficulty:** Guided, moderate noise  
**Expected time:** 35–50 minutes

A new per-user startup item appears on `FIN-WS-09` for `ACME\\lchen`.

The same workstation also receives a legitimate enterprise logon script, has a signed Teams updater, and contains an approved user startup shortcut.

The analyst must determine whether each startup item is centrally managed, user-specific but benign, or malicious.

## Data
Nine portable CSV lookups contain 500 records each: **4,500 synthetic records total**.
""")
wt(ROOT/"attack-narrative.md","""# Attack Narrative

`OneDriveHealth` appears as new user startup configuration on `FIN-WS-09`. The target is an untrusted script under the user's roaming profile. At the next interactive logon, `explorer.exe` launches PowerShell, which starts a second untrusted artifact and produces outbound TLS to `203.0.113.77`.

The host also has three benign look-alikes: a centrally managed drive-mapping script, a signed Teams updater, and an approved DisplayProfile startup shortcut.

The supplied evidence supports high-confidence malicious user-context startup persistence on `FIN-WS-09`. It does not support enterprise-policy compromise, propagation to another host, or a claim about TLS payload content.
""")
wt(ROOT/"analyst-hunt-guide.md","""# Analyst Hunt Guide

1. Identify the startup item's source, user, target and provenance.
2. Separate local user state from centrally managed policy.
3. Follow execution into process and file telemetry.
4. Compare artifact trust.
5. Explain the three benign look-alikes.
6. State the persistence decision and confidence.
7. Hunt the exact item/path/artifacts elsewhere without assuming propagation.
""")
wt(ROOT/"investigation-worksheet.md","""# Investigation Worksheet

| Item | Host / User | Source | Target | Provenance | Decision | Confidence |
|---|---|---|---|---|---|---|
| OneDriveHealth | | | | | | |
| MapDrives | | | | | | |
| Teams | | | | | | |
| DisplayProfile | | | | | | |

## Timeline
## Process / file pivots
## Local vs centrally managed determination
## Scope
## Evidence gaps
## Response
""")
wt(ROOT/"data-dictionary.md","""# Data Dictionary

Nine platform-portable CSV lookups are included, each with exactly 500 records: detection results, startup configuration, startup items, endpoint process, endpoint file, software trust, policy context, network activity, and response activity. All timestamps are UTC ISO 8601.
""")
wt(ROOT/"sample-spl.md","""# Sample SPL

```spl
| inputlookup detection_results.csv
| search detection_id="ATD11-*"
| sort 0 _time
```

```spl
| inputlookup startup_config.csv
| search host="FIN-WS-09"
| sort 0 _time
| table _time user source_type item_name target_path provenance classification
```

```spl
| inputlookup endpoint_process.csv
| search host="FIN-WS-09"
| sort 0 _time
| table _time user parent_process process_name command_line classification
```

```spl
| inputlookup policy_context.csv
| search host="FIN-WS-09"
| table _time user policy_name source approved classification
```
""")
wt(ROOT/"response-plan.md","""# Response Plan

Preserve the suspicious startup configuration, script, secondary artifact, process ancestry, and current network evidence. Remove the malicious startup item after preservation and isolate `FIN-WS-09`.

Hunt the exact item name, path, artifacts, and `203.0.113.77` elsewhere. Do not remove the centrally managed logon script, signed Teams updater, or approved DisplayProfile shortcut based on the supplied evidence.

Do not claim enterprise-policy compromise, propagation, or TLS payload content without additional evidence.
""")
wt(ROOT/"answer-key.json",json.dumps({
"seed":SEED,"lookups":9,"rows_per_lookup":ROWS,"total_records":4500,
"expected_decision":"High-confidence malicious user-context startup persistence on FIN-WS-09.",
"benign_lookalikes":["MapDrives enterprise logon policy","signed Teams updater","approved DisplayProfile startup shortcut"],
"not_proven":["enterprise policy compromise","same persistence on another host","TLS payload content or data theft"]
},indent=2))
wt(ROOT/"validation-report.md","""# Validation Report

- Seed: **20260914**
- Lookups: **9**
- Rows per lookup: **500**
- Total records: **4,500**
- Suspicious user startup item: **present**
- Centrally managed logon look-alike: **present**
- Signed updater look-alike: **present**
- Approved user shortcut look-alike: **present**
- Process/file/network pivots: **present**
- Responder activity: **present**
- Scope/evidence gaps: **explicit**
""")
wt(ROOT/"validate_lab.py","""from pathlib import Path
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
""")

wt(APP/"README.md","""# Splunk Lab App
Copy `after_detection_hunt_011` into `$SPLUNK_HOME/etc/apps/` and restart Splunk. Bundled CSV lookups require no index.
""")
wt(APP/"default"/"app.conf","""[install]
is_configured = 0
[ui]
is_visible = 1
label = After the Detection - Hunt 011
[launcher]
author = WiseHawk Technologies
version = 1.0.0
description = Hunt 011 - Startup Configuration Provenance
""")
wt(APP/"metadata"/"default.meta","""[]
access = read : [ * ], write : [ admin ]
export = system
""")
wt(APP/"default"/"data"/"ui"/"nav"/"default.xml",'<nav search_view="search"><view name="hunt_011_overview" default="true"/><view name="search"/></nav>')
wt(APP/"default"/"data"/"ui"/"views"/"hunt_011_overview.xml",'<form version="1.1" theme="dark"><label>Hunt 011 — Startup Configuration Provenance</label><row><panel><table><search><query>| inputlookup detection_results.csv | search detection_id="ATD11-*"</query></search></table></panel></row></form>')
