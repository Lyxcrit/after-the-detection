from pathlib import Path
from datetime import datetime,timedelta,timezone
import csv,random,hashlib

R=Path(__file__).resolve().parent
D=R/'data'; L=R/'splunk'/'after_detection_hunt_010'/'lookups'
SEED=20260907; N=500; rng=random.Random(SEED)
base=datetime(2026,9,7,12,0,tzinfo=timezone.utc); t0=base+timedelta(hours=2,minutes=18)
hosts=['ENG-WS-17','APP-06','SCCM-01','JUMP-01','FILE-03','DC-01','OPS-WS-08']
users=[r'ACME\adavis',r'ACME\svc_sccm',r'ACME\jsmith',r'ACME\mturner',r'NT AUTHORITY\SYSTEM']

def ts(d): return d.strftime('%Y-%m-%dT%H:%M:%SZ')
def noise_time(): return ts(base+timedelta(seconds=rng.randint(0,4*86400)))
def write(name,rows):
    D.mkdir(parents=True,exist_ok=True); L.mkdir(parents=True,exist_ok=True)
    fields=list(rows[0])
    for p in (D/name,L/name):
        with p.open('w',newline='',encoding='utf-8') as f:
            w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)
def pad(rows,maker):
    rows=list(rows)
    while len(rows)<N: rows.append(maker(len(rows)))
    rows.sort(key=lambda x:x.get('_time',''))
    return rows

rows=[
{'detection_id':'ATD-010-001','_time':ts(t0),'severity':'medium','title':'New Auto-Start Service Installed','host':'ENG-WS-17','user':r'ACME\adavis','classification':'investigate','note':'support-sounding service installed'},
{'detection_id':'ATD-010-002','_time':ts(t0+timedelta(seconds=12)),'severity':'high','title':'Unsigned Service Binary Started','host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','classification':'investigate','note':'service starts from ProgramData'},
{'detection_id':'ATD-010-003','_time':ts(t0+timedelta(seconds=41)),'severity':'high','title':'New Service Opens External TLS','host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','classification':'investigate','note':'supportsvc.exe connects externally'},
{'detection_id':'ATD-010-004','_time':ts(t0+timedelta(minutes=7)),'severity':'medium','title':'Endpoint Management Installs Service','host':'APP-06','user':r'ACME\svc_sccm','classification':'benign','note':'approved SCCM deployment'},
{'detection_id':'ATD-010-005','_time':ts(t0+timedelta(minutes=14)),'severity':'medium','title':'Responder Disables Service','host':'ENG-WS-17','user':r'ACME\jsmith','classification':'response','note':'service preserved then disabled'},
{'detection_id':'ATD-010-006','_time':ts(t0+timedelta(minutes=17)),'severity':'high','title':'Service Persistence Scope Review','host':'ENG-WS-17','user':r'ACME\adavis','classification':'decision','note':'persistence confirmed on ENG-WS-17; propagation unproven'}]
write('detection_results.csv',pad(rows,lambda i:{'detection_id':f'ATD-010-{i+100:05d}','_time':noise_time(),'severity':rng.choice(['low','medium']),'title':rng.choice(['Service Change Review','Software Deployment Review','Unsigned Binary Review']),'host':rng.choice(hosts),'user':rng.choice(users),'classification':'context','note':'background detection'}))

rows=[
{'event_id':'SVC-INC-001','_time':ts(t0),'host':'ENG-WS-17','actor':r'ACME\adavis','service_name':'WinSupportSvc','display_name':'Windows Support Service','action':'installed','image_path':r'C:\ProgramData\WinSupport\supportsvc.exe -service','start_type':'auto','service_account':'LocalSystem','classification':'investigate','note':'plausible display name; unusual path'},
{'event_id':'SVC-INC-002','_time':ts(t0+timedelta(seconds=12)),'host':'ENG-WS-17','actor':r'NT AUTHORITY\SYSTEM','service_name':'WinSupportSvc','display_name':'Windows Support Service','action':'started','image_path':r'C:\ProgramData\WinSupport\supportsvc.exe -service','start_type':'auto','service_account':'LocalSystem','classification':'investigate','note':'new service starts'},
{'event_id':'SVC-BEN-001','_time':ts(t0+timedelta(minutes=7)),'host':'APP-06','actor':r'ACME\svc_sccm','service_name':'ACMESupportAgent','display_name':'ACME Support Agent','action':'installed','image_path':r'C:\Program Files\ACME\Support\agent.exe --service','start_type':'auto','service_account':'LocalSystem','classification':'benign','note':'approved endpoint support deployment'},
{'event_id':'SVC-BEN-002','_time':ts(t0+timedelta(minutes=7,seconds=14)),'host':'APP-06','actor':r'NT AUTHORITY\SYSTEM','service_name':'ACMESupportAgent','display_name':'ACME Support Agent','action':'started','image_path':r'C:\Program Files\ACME\Support\agent.exe --service','start_type':'auto','service_account':'LocalSystem','classification':'benign','note':'approved support agent starts'},
{'event_id':'SVC-CTX-001','_time':ts(t0-timedelta(minutes=22)),'host':'ENG-WS-17','actor':r'ACME\svc_sccm','service_name':'CcmExec','display_name':'SMS Agent Host','action':'started','image_path':r'C:\Windows\CCM\CcmExec.exe','start_type':'auto','service_account':'LocalSystem','classification':'benign','note':'known endpoint-management service'},
{'event_id':'SVC-RESP-001','_time':ts(t0+timedelta(minutes=14)),'host':'ENG-WS-17','actor':r'ACME\jsmith','service_name':'WinSupportSvc','display_name':'Windows Support Service','action':'disabled','image_path':r'C:\ProgramData\WinSupport\supportsvc.exe -service','start_type':'disabled','service_account':'LocalSystem','classification':'response','note':'responder disables persistence'}]
write('endpoint_service.csv',pad(rows,lambda i:{'event_id':f'SVC-{i:05d}','_time':noise_time(),'host':rng.choice(hosts),'actor':rng.choice(users),'service_name':rng.choice(['Spooler','CcmExec','ACMEInventory','WinDefend','W32Time']),'display_name':rng.choice(['Print Spooler','SMS Agent Host','ACME Inventory','Windows Defender','Windows Time']),'action':rng.choice(['started','stopped','queried','configuration_read']),'image_path':rng.choice([r'C:\Windows\System32\svchost.exe',r'C:\Windows\CCM\CcmExec.exe',r'C:\Program Files\ACME\Inventory\inventorysvc.exe']),'start_type':rng.choice(['auto','demand']),'service_account':rng.choice(['LocalSystem','NetworkService']),'classification':'benign','note':'routine service activity'}))

rows=[
{'event_id':'PROC-INC-001','_time':ts(t0-timedelta(seconds=18)),'host':'ENG-WS-17','user':r'ACME\adavis','parent_process_name':'powershell.exe','process_name':'sc.exe','command_line':r'sc.exe create WinSupportSvc binPath= "C:\ProgramData\WinSupport\supportsvc.exe -service" start= auto obj= LocalSystem','classification':'investigate','note':'user creates service'},
{'event_id':'PROC-INC-002','_time':ts(t0+timedelta(seconds=12)),'host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','parent_process_name':'services.exe','process_name':'supportsvc.exe','command_line':r'C:\ProgramData\WinSupport\supportsvc.exe -service','classification':'investigate','note':'service binary launched by SCM'},
{'event_id':'PROC-INC-003','_time':ts(t0+timedelta(seconds=28)),'host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','parent_process_name':'supportsvc.exe','process_name':'powershell.exe','command_line':r'powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\WinSupport\collect.ps1','classification':'investigate','note':'service launches follow-on PowerShell'},
{'event_id':'PROC-INC-004','_time':ts(t0+timedelta(seconds=55)),'host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','parent_process_name':'powershell.exe','process_name':'cmd.exe','command_line':r'cmd.exe /c whoami /all > C:\ProgramData\WinSupport\who.txt','classification':'investigate','note':'identity discovery'},
{'event_id':'PROC-BEN-001','_time':ts(t0+timedelta(minutes=6,seconds=42)),'host':'APP-06','user':r'ACME\svc_sccm','parent_process_name':'CcmExec.exe','process_name':'msiexec.exe','command_line':r'msiexec.exe /i ACME-Support-Agent-4.2.msi /qn','classification':'benign','note':'SCCM starts approved installer'},
{'event_id':'PROC-BEN-002','_time':ts(t0+timedelta(minutes=7,seconds=14)),'host':'APP-06','user':r'NT AUTHORITY\SYSTEM','parent_process_name':'services.exe','process_name':'agent.exe','command_line':r'C:\Program Files\ACME\Support\agent.exe --service','classification':'benign','note':'approved support agent starts'},
{'event_id':'PROC-RESP-001','_time':ts(t0+timedelta(minutes=12)),'host':'ENG-WS-17','user':r'ACME\jsmith','parent_process_name':'cmd.exe','process_name':'sc.exe','command_line':'sc.exe qc WinSupportSvc','classification':'response','note':'responder captures configuration'},
{'event_id':'PROC-RESP-002','_time':ts(t0+timedelta(minutes=14)),'host':'ENG-WS-17','user':r'ACME\jsmith','parent_process_name':'cmd.exe','process_name':'sc.exe','command_line':'sc.exe config WinSupportSvc start= disabled','classification':'response','note':'responder disables service'}]
write('endpoint_process.csv',pad(rows,lambda i:{'event_id':f'PROC-{i:05d}','_time':noise_time(),'host':rng.choice(hosts),'user':rng.choice(users),'parent_process_name':rng.choice(['services.exe','explorer.exe','CcmExec.exe','svchost.exe']),'process_name':rng.choice(['powershell.exe','cmd.exe','msiexec.exe','inventorysvc.exe','agent.exe']),'command_line':'routine process execution','classification':'benign','note':'routine process'}))

rows=[
{'event_id':'FILE-INC-001','_time':ts(t0-timedelta(seconds=37)),'host':'ENG-WS-17','user':r'ACME\adavis','action':'create','file_path':r'C:\ProgramData\WinSupport\supportsvc.exe','source_process':'powershell.exe','classification':'investigate','note':'service binary staged before creation'},
{'event_id':'FILE-INC-002','_time':ts(t0-timedelta(seconds=31)),'host':'ENG-WS-17','user':r'ACME\adavis','action':'create','file_path':r'C:\ProgramData\WinSupport\collect.ps1','source_process':'powershell.exe','classification':'investigate','note':'follow-on script staged'},
{'event_id':'FILE-INC-003','_time':ts(t0+timedelta(seconds=56)),'host':'ENG-WS-17','user':r'NT AUTHORITY\SYSTEM','action':'create','file_path':r'C:\ProgramData\WinSupport\who.txt','source_process':'cmd.exe','classification':'investigate','note':'discovery output'},
{'event_id':'FILE-BEN-001','_time':ts(t0+timedelta(minutes=6,seconds=35)),'host':'APP-06','user':r'ACME\svc_sccm','action':'create','file_path':r'C:\Program Files\ACME\Support\agent.exe','source_process':'msiexec.exe','classification':'benign','note':'approved MSI installs signed service binary'},
{'event_id':'FILE-RESP-001','_time':ts(t0+timedelta(minutes=12,seconds=20)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'read','file_path':r'C:\ProgramData\WinSupport\supportsvc.exe','source_process':'powershell.exe','classification':'response','note':'responder hashes service binary'}]
write('endpoint_file.csv',pad(rows,lambda i:{'event_id':f'FILE-{i:05d}','_time':noise_time(),'host':rng.choice(hosts),'user':rng.choice(users),'action':rng.choice(['read','create','modify']),'file_path':rng.choice([r'C:\Windows\Temp\setup.log',r'C:\Windows\CCM\Logs\AppEnforce.log',r'C:\Program Files\ACME\Inventory\state.db']),'source_process':rng.choice(['CcmExec.exe','msiexec.exe','inventorysvc.exe','powershell.exe']),'classification':'benign','note':'routine file activity'}))

bad=hashlib.sha256(b'hunt010-supportsvc').hexdigest(); script=hashlib.sha256(b'hunt010-collect').hexdigest(); good=hashlib.sha256(b'acme-support-agent-4.2').hexdigest()
rows=[
{'event_id':'TRUST-INC-001','_time':ts(t0-timedelta(seconds=34)),'host':'ENG-WS-17','file_path':r'C:\ProgramData\WinSupport\supportsvc.exe','sha256':bad,'signature_status':'unsigned','publisher':'','reputation':'unknown','classification':'investigate','note':'not approved internal software'},
{'event_id':'TRUST-INC-002','_time':ts(t0-timedelta(seconds=29)),'host':'ENG-WS-17','file_path':r'C:\ProgramData\WinSupport\collect.ps1','sha256':script,'signature_status':'unsigned','publisher':'','reputation':'unknown','classification':'investigate','note':'not approved automation'},
{'event_id':'TRUST-BEN-001','_time':ts(t0+timedelta(minutes=6,seconds=36)),'host':'APP-06','file_path':r'C:\Program Files\ACME\Support\agent.exe','sha256':good,'signature_status':'trusted_internal','publisher':'ACME IT Automation','reputation':'approved','classification':'benign','note':'approved endpoint support agent'},
{'event_id':'TRUST-CTX-001','_time':ts(t0-timedelta(minutes=22,seconds=4)),'host':'ENG-WS-17','file_path':r'C:\Windows\CCM\CcmExec.exe','sha256':hashlib.sha256(b'ccmexec').hexdigest(),'signature_status':'signed','publisher':'Microsoft Corporation','reputation':'approved','classification':'benign','note':'known SCCM client'}]
write('software_trust.csv',pad(rows,lambda i:{'event_id':f'TRUST-{i:05d}','_time':noise_time(),'host':rng.choice(hosts),'file_path':rng.choice([r'C:\Windows\System32\svchost.exe',r'C:\Windows\CCM\CcmExec.exe',r'C:\Program Files\ACME\Inventory\inventorysvc.exe']),'sha256':hashlib.sha256(f'benign-{i}'.encode()).hexdigest(),'signature_status':rng.choice(['signed','signed','trusted_internal']),'publisher':rng.choice(['Microsoft Corporation','ACME IT Automation']),'reputation':'approved','classification':'benign','note':'routine trust context'}))

rows=[
{'event_id':'NET-INC-001','_time':ts(t0+timedelta(seconds=41)),'src_host':'ENG-WS-17','dest_host':'198.51.100.44','user':r'NT AUTHORITY\SYSTEM','process_name':'supportsvc.exe','dest_port':'443','action':'allowed','bytes_out':'3210','classification':'investigate','note':'new service contacts external host'},
{'event_id':'NET-INC-002','_time':ts(t0+timedelta(minutes=2,seconds=15)),'src_host':'ENG-WS-17','dest_host':'198.51.100.44','user':r'NT AUTHORITY\SYSTEM','process_name':'supportsvc.exe','dest_port':'443','action':'allowed','bytes_out':'7820','classification':'investigate','note':'second TLS session; content unknown'},
{'event_id':'NET-BEN-001','_time':ts(t0+timedelta(minutes=7,seconds=45)),'src_host':'APP-06','dest_host':'SCCM-01','user':r'NT AUTHORITY\SYSTEM','process_name':'agent.exe','dest_port':'443','action':'allowed','bytes_out':'11640','classification':'benign','note':'support agent checks in to management server'},
{'event_id':'NET-CTX-001','_time':ts(t0-timedelta(minutes=21,seconds=55)),'src_host':'ENG-WS-17','dest_host':'SCCM-01','user':r'NT AUTHORITY\SYSTEM','process_name':'CcmExec.exe','dest_port':'443','action':'allowed','bytes_out':'9100','classification':'benign','note':'known SCCM traffic'},
{'event_id':'NET-RESP-001','_time':ts(t0+timedelta(minutes=11,seconds=30)),'src_host':'JUMP-01','dest_host':'ENG-WS-17','user':r'ACME\jsmith','process_name':'mstsc.exe','dest_port':'3389','action':'allowed','bytes_out':'16000','classification':'response','note':'authorized responder'}]
write('network_activity.csv',pad(rows,lambda i:{'event_id':f'NET-{i:05d}','_time':noise_time(),'src_host':rng.choice(hosts),'dest_host':rng.choice(hosts+['198.51.100.44']),'user':rng.choice(users),'process_name':rng.choice(['CcmExec.exe','agent.exe','powershell.exe','System']),'dest_port':rng.choice(['443','445','53','5985']),'action':'allowed','bytes_out':str(rng.randint(100,65000)),'classification':'benign','note':'routine network activity'}))

rows=[
{'change_id':'CHG-GAP-001','_time':ts(t0),'host':'ENG-WS-17','owner':'','change_type':'none_found','approved':'no','package':'WinSupportSvc','deployment_source':'','classification':'investigate','note':'no approved change matches service'},
{'change_id':'CHG-BEN-001','_time':ts(t0+timedelta(minutes=6)),'host':'APP-06','owner':'Endpoint Team','change_type':'software_deployment','approved':'yes','package':'ACME Support Agent 4.2','deployment_source':'SCCM-01','classification':'benign','note':'approved support-agent rollout'},
{'change_id':'CHG-CTX-001','_time':ts(t0-timedelta(hours=1)),'host':'ENG-WS-17','owner':'Endpoint Team','change_type':'inventory_cycle','approved':'yes','package':'Monthly endpoint inventory','deployment_source':'SCCM-01','classification':'benign','note':'documents routine management activity'},
{'change_id':'CHG-RESP-001','_time':ts(t0+timedelta(minutes=10)),'host':'ENG-WS-17','owner':'SOC','change_type':'incident_response','approved':'yes','package':'IR containment ENG-WS-17','deployment_source':'JUMP-01','classification':'response','note':'response change opened'}]
write('change_records.csv',pad(rows,lambda i:{'change_id':f'CHG-{i+1000:05d}','_time':noise_time(),'host':rng.choice(hosts),'owner':rng.choice(['Endpoint Team','Infrastructure','Workplace Engineering']),'change_type':rng.choice(['software_deployment','patch_cycle','inventory_cycle']),'approved':'yes','package':rng.choice(['Monthly Patch','ACME Inventory','Endpoint Health Agent']),'deployment_source':'SCCM-01','classification':'benign','note':'routine approved change'}))

rows=[
{'event_id':'RESP-010-001','_time':ts(t0+timedelta(minutes=11)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'capture_service_configuration','classification':'response','note':'preserve service config'},
{'event_id':'RESP-010-002','_time':ts(t0+timedelta(minutes=12)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'hash_service_artifacts','classification':'response','note':'hash service artifacts'},
{'event_id':'RESP-010-003','_time':ts(t0+timedelta(minutes=14)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'disable_service','classification':'response','note':'prevent persistence from re-running'},
{'event_id':'RESP-010-004','_time':ts(t0+timedelta(minutes=15)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'isolate_host','classification':'response','note':'contain confirmed service persistence'},
{'event_id':'RESP-010-005','_time':ts(t0+timedelta(minutes=17)),'host':'ENG-WS-17','user':r'ACME\jsmith','action':'hunt_service_hash_path_destination','classification':'response','note':'scope exact indicators across estate'}]
write('response_activity.csv',pad(rows,lambda i:{'event_id':f'RESP-{i:05d}','_time':noise_time(),'host':rng.choice(hosts),'user':'SOC-AUTOMATION','action':rng.choice(['review_alert','collect_logs','query_service','check_change']),'classification':'response','note':'routine response workflow'}))

print(f'Generated Hunt 010: 8 lookups x {N} = {8*N:,} records (seed {SEED})')
