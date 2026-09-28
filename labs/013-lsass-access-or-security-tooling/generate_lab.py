#!/usr/bin/env python3
import csv, random
from pathlib import Path
from datetime import datetime, timedelta, timezone

SEED=20260928
ROWS=500
random.seed(SEED)
ROOT=Path(__file__).resolve().parent
DATA=ROOT/"data"
DATA.mkdir(exist_ok=True)
base=datetime(2026,9,28,13,0,tzinfo=timezone.utc)

def ts(mins,secs=0): return (base+timedelta(minutes=mins,seconds=secs)).isoformat().replace("+00:00","Z")
def write(name, fields, rows):
    assert len(rows)==ROWS, (name,len(rows))
    with (DATA/name).open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

hosts=["DEV-WS-03","DEV-WS-07","DEV-WS-12","DEV-WS-18","FILE-DEV-03","BUILD-02","IR-JUMP-01"]
users=[r"ACME\\jpatel",r"ACME\\rlee",r"ACME\\svc_build",r"ACME\\jsmith"]

# detections
fields=["_time","detection_id","host","user","rule_name","severity"]
rows=[{"_time":ts(i%240,i%60),"detection_id":f"ATD-013-N{i:03d}","host":random.choice(hosts),"user":random.choice(users),"rule_name":"Routine endpoint analytic","severity":"low"} for i in range(ROWS)]
rows[210]={"_time":ts(66),"detection_id":"ATD-013-001","host":"DEV-WS-12","user":r"ACME\jpatel","rule_name":"Suspicious LSASS Access via Comsvcs","severity":"high"}
rows[211]={"_time":ts(74),"detection_id":"ATD-013-002","host":"DEV-WS-12","user":r"ACME\jpatel","rule_name":"Authentication from Credential-Access Host","severity":"medium"}
write("detection_results.csv",fields,rows)

fields=["_time","host","user","process_name","parent_process","command_line","pid"]
procs=["chrome.exe","code.exe","git.exe","cmd.exe","powershell.exe","msbuild.exe","python.exe"]
rows=[{"_time":ts(i%240,i%59),"host":random.choice(hosts[:6]),"user":random.choice(users[:3]),"process_name":random.choice(procs),"parent_process":"explorer.exe","command_line":"routine developer activity","pid":str(3000+i)} for i in range(ROWS)]
rows[220]={"_time":ts(65),"host":"DEV-WS-12","user":r"ACME\jpatel","process_name":"powershell.exe","parent_process":"explorer.exe","command_line":"powershell.exe -NoP -W Hidden -File C:\\Users\\jpatel\\AppData\\Local\\Temp\\diag.ps1","pid":"6124"}
rows[221]={"_time":ts(66),"host":"DEV-WS-12","user":r"ACME\jpatel","process_name":"rundll32.exe","parent_process":"powershell.exe","command_line":"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 744 C:\\ProgramData\\Diag\\lsass.dmp full","pid":"6210"}
rows[222]={"_time":ts(69),"host":"DEV-WS-12","user":r"ACME\jpatel","process_name":"powershell.exe","parent_process":"powershell.exe","command_line":"Compress-Archive C:\\ProgramData\\Diag\\lsass.dmp C:\\ProgramData\\Diag\\diag-0928.zip","pid":"6288"}
write("endpoint_process.csv",fields,rows)

fields=["_time","host","source_process","target_process","access_mask","signer","trusted","parent_process"]
rows=[{"_time":ts(i%240,i%57),"host":random.choice(hosts[:4]),"source_process":"SenseIR.exe","target_process":"lsass.exe","access_mask":"0x1410","signer":"Microsoft Windows Publisher","trusted":"true","parent_process":"services.exe"} for i in range(ROWS)]
rows[230]={"_time":ts(66,5),"host":"DEV-WS-12","source_process":"rundll32.exe","target_process":"lsass.exe","access_mask":"0x1fffff","signer":"Microsoft Windows","trusted":"context-mismatch","parent_process":"powershell.exe"}
rows[231]={"_time":ts(41),"host":"DEV-WS-07","source_process":"SenseIR.exe","target_process":"lsass.exe","access_mask":"0x1410","signer":"Microsoft Windows Publisher","trusted":"true","parent_process":"services.exe"}
write("process_access.csv",fields,rows)

fields=["_time","host","user","action","path","process_name"]
paths=[r"C:\Users\Public\notes.txt",r"C:\ProgramData\Build\build.log",r"C:\Temp\app.dmp"]
rows=[{"_time":ts(i%240,i%53),"host":random.choice(hosts[:6]),"user":random.choice(users[:3]),"action":random.choice(["create","read","modify"]),"path":random.choice(paths),"process_name":random.choice(procs)} for i in range(ROWS)]
rows[240]={"_time":ts(66,12),"host":"DEV-WS-12","user":r"ACME\jpatel","action":"create","path":r"C:\ProgramData\Diag\lsass.dmp","process_name":"rundll32.exe"}
rows[241]={"_time":ts(69,20),"host":"DEV-WS-12","user":r"ACME\jpatel","action":"create","path":r"C:\ProgramData\Diag\diag-0928.zip","process_name":"powershell.exe"}
rows[242]={"_time":ts(50),"host":"DEV-WS-07","user":r"ACME\rlee","action":"create","path":r"C:\ProgramData\Diagnostics\appcrash.dmp","process_name":"WerFault.exe"}
write("file_activity.csv",fields,rows)

fields=["_time","src_host","dest_host","user","protocol","result","logon_type"]
rows=[{"_time":ts(i%240,i%51),"src_host":random.choice(hosts[:4]),"dest_host":random.choice(["FILE-DEV-03","BUILD-02"]),"user":random.choice(users[:3]),"protocol":random.choice(["Kerberos","NTLM"]),"result":"success","logon_type":"3"} for i in range(ROWS)]
rows[250]={"_time":ts(74),"src_host":"DEV-WS-12","dest_host":"FILE-DEV-03","user":r"ACME\jpatel","protocol":"Kerberos","result":"success","logon_type":"3"}
write("identity_auth.csv",fields,rows)

fields=["_time","src_host","dest_host","dest_ip","dest_port","protocol","bytes_out"]
rows=[{"_time":ts(i%240,i%47),"src_host":random.choice(hosts[:4]),"dest_host":random.choice(["FILE-DEV-03","BUILD-02","github.com"]),"dest_ip":random.choice(["10.30.4.23","10.30.8.12","140.82.114.4"]),"dest_port":random.choice(["443","445"]), "protocol":"tcp","bytes_out":str(random.randint(300,9000))} for i in range(ROWS)]
rows[260]={"_time":ts(74,8),"src_host":"DEV-WS-12","dest_host":"FILE-DEV-03","dest_ip":"10.30.4.23","dest_port":"445","protocol":"tcp","bytes_out":"1832"}
write("network_activity.csv",fields,rows)

fields=["_time","host","product","process_name","publisher","approved"]
products=[("Microsoft Defender for Endpoint","SenseIR.exe","Microsoft Corporation","true"),("Visual Studio Code","Code.exe","Microsoft Corporation","true"),("ACME Diagnostics","acmediag.exe","ACME IT","true")]
rows=[]
for i in range(ROWS):
    p=random.choice(products); rows.append({"_time":ts(i%240,i%43),"host":random.choice(hosts[:4]),"product":p[0],"process_name":p[1],"publisher":p[2],"approved":p[3]})
rows[270]={"_time":ts(40),"host":"DEV-WS-12","product":"Microsoft Defender for Endpoint","process_name":"SenseIR.exe","publisher":"Microsoft Corporation","approved":"true"}
write("software_inventory.csv",fields,rows)

fields=["_time","host","user","source_host","action","details"]
rows=[{"_time":ts(180+i%50,i%41),"host":random.choice(["DEV-WS-12","FILE-DEV-03"]),"user":r"ACME\jsmith","source_host":"IR-JUMP-01","action":"triage","details":random.choice(["whoami","quser","netstat -ano","Get-Process"])} for i in range(ROWS)]
rows[280]={"_time":ts(96),"host":"DEV-WS-12","user":r"ACME\jsmith","source_host":"IR-JUMP-01","action":"collect","details":"Acquire volatile process and network state"}
write("responder_activity.csv",fields,rows)

print("generated",8*ROWS,"records")
