from pathlib import Path
from datetime import datetime,timedelta,timezone
import csv,random
SEED=20260824; N=10000; R=random.Random(SEED); ROOT=Path(__file__).parent; DATA=ROOT/'data'; LOOK=ROOT/'splunk'/'after_detection_capstone_008'/'lookups'
DATA.mkdir(exist_ok=True); LOOK.mkdir(parents=True,exist_ok=True)
BASE=datetime(2026,8,24,15,17,tzinfo=timezone.utc); H=['ADMIN-WS-07','FIN-WS-14','APP-API-02','APP-API-03','FILE-02','DEPLOY-01','JUMP-01','BACKUP-01','DC-01']; U=['ACME\\mrivera','ACME\\svc_deploy','ACME\\svc_backup','ACME\\jsmith','NT AUTHORITY\\SYSTEM']
def ts(m=0): return (BASE+timedelta(minutes=m)).strftime('%Y-%m-%dT%H:%M:%SZ')
def save(name,fields,special,noise):
 rows=[noise(i) for i in range(N-len(special))]+special
 for p in (DATA/name,LOOK/name):
  with p.open('w',newline='',encoding='utf-8') as f:
   w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
save('detection_results.csv',['id','_time','host','user','title','class','note'],[
 {'id':'CAP-001','_time':ts(),'host':H[0],'user':U[0],'title':'PowerShell download','class':'incident','note':'ambiguous start'},
 {'id':'CAP-002','_time':ts(11),'host':H[2],'user':U[0],'title':'Failed WinRM','class':'scope','note':'attempt only'},
 {'id':'CAP-003','_time':ts(12),'host':H[3],'user':U[0],'title':'Failed WinRM','class':'scope','note':'attempt only'},
 {'id':'CAP-004','_time':ts(21),'host':H[1],'user':U[0],'title':'Successful SMB','class':'incident','note':'movement'},
 {'id':'CAP-005','_time':ts(34),'host':H[4],'user':U[0],'title':'Post-reset success','class':'incident','note':'new host'},
 {'id':'CAP-006','_time':ts(47),'host':H[4],'user':U[0],'title':'Outbound TLS','class':'gap','note':'exfiltration unproven'}],lambda i:{'id':f'D{i:05}','_time':ts(R.randint(-1440,4320)),'host':R.choice(H),'user':R.choice(U),'title':'Background review','class':'noise','note':'routine'})
save('identity_auth.csv',['id','_time','src','dest','user','protocol','result','class','note'],[
 {'id':'A1','_time':ts(11),'src':H[0],'dest':H[2],'user':U[0],'protocol':'WinRM','result':'failure','class':'scope','note':'failed movement'},
 {'id':'A2','_time':ts(12),'src':H[0],'dest':H[3],'user':U[0],'protocol':'WinRM','result':'failure','class':'scope','note':'failed movement'},
 {'id':'A3','_time':ts(13),'src':H[5],'dest':H[2],'user':U[1],'protocol':'WinRM','result':'success','class':'benign','note':'deployment'},
 {'id':'A4','_time':ts(21),'src':H[0],'dest':H[1],'user':U[0],'protocol':'SMB','result':'success','class':'incident','note':'movement'},
 {'id':'A5','_time':ts(31),'src':H[1],'dest':H[8],'user':U[0],'protocol':'Kerberos','result':'failure','class':'contained','note':'after reset'},
 {'id':'A6','_time':ts(34),'src':H[4],'dest':H[8],'user':U[0],'protocol':'Kerberos','result':'success','class':'incident','note':'after reset'},
 {'id':'A7','_time':ts(36),'src':H[7],'dest':H[4],'user':U[2],'protocol':'SMB','result':'success','class':'benign','note':'backup'},
 {'id':'A8','_time':ts(42),'src':H[6],'dest':H[4],'user':U[3],'protocol':'RDP','result':'success','class':'response','note':'responder'}],lambda i:{'id':f'A{i+100:05}','_time':ts(R.randint(-1440,4320)),'src':R.choice(H),'dest':R.choice(H),'user':R.choice(U),'protocol':R.choice(['Kerberos','SMB','RDP']),'result':R.choice(['success','success','failure']),'class':'benign','note':'routine'})
save('endpoint_process.csv',['id','_time','host','user','parent','process','cmd','class','note'],[
 {'id':'P1','_time':ts(1),'host':H[0],'user':U[0],'parent':'explorer.exe','process':'powershell.exe','cmd':'iwr https://download.example/admin.zip','class':'incident','note':'download'},
 {'id':'P2','_time':ts(4),'host':H[0],'user':U[0],'parent':'rundll32.exe','process':'lsass-reader.exe','cmd':'lsass-reader.exe --dump','class':'incident','note':'credential access'},
 {'id':'P3','_time':ts(22),'host':H[1],'user':U[0],'parent':'explorer.exe','process':'cmd.exe','cmd':'whoami && net use','class':'incident','note':'execution'},
 {'id':'P4','_time':ts(34.2),'host':H[4],'user':U[0],'parent':'explorer.exe','process':'cmd.exe','cmd':'copy D:\\Shares\\Finance\\Q3.xlsx C:\\Users\\Public\\Q3.xlsx','class':'incident','note':'file copy'},
 {'id':'P5','_time':ts(34.5),'host':H[4],'user':U[0],'parent':'cmd.exe','process':'powershell.exe','cmd':'Get-FileHash C:\\Users\\Public\\Q3.xlsx','class':'incident','note':'follow-on'},
 {'id':'P6','_time':ts(36.2),'host':H[4],'user':U[2],'parent':'services.exe','process':'backup-agent.exe','cmd':'--job nightly-finance','class':'benign','note':'backup'},
 {'id':'P7','_time':ts(42.2),'host':H[4],'user':U[3],'parent':'explorer.exe','process':'cmd.exe','cmd':'whoami && quser && netstat -ano','class':'response','note':'triage'}],lambda i:{'id':f'P{i+100:05}','_time':ts(R.randint(-1440,4320)),'host':R.choice(H),'user':R.choice(U),'parent':'services.exe','process':R.choice(['powershell.exe','cmd.exe','w3wp.exe']),'cmd':'routine','class':'benign','note':'routine'})
save('endpoint_file.csv',['id','_time','host','user','action','path','process','class','note'],[
 {'id':'F1','_time':ts(1.1),'host':H[0],'user':U[0],'action':'create','path':'C:\\ProgramData\\admin.zip','process':'powershell.exe','class':'incident','note':'artifact'},
 {'id':'F2','_time':ts(23),'host':H[1],'user':U[0],'action':'create','path':'C:\\ProgramData\\stage.ps1','process':'cmd.exe','class':'incident','note':'staging'},
 {'id':'F3','_time':ts(34.3),'host':H[4],'user':U[0],'action':'read','path':'D:\\Shares\\Finance\\Q3.xlsx','process':'cmd.exe','class':'incident','note':'finance read'},
 {'id':'F4','_time':ts(34.4),'host':H[4],'user':U[0],'action':'create','path':'C:\\Users\\Public\\Q3.xlsx','process':'cmd.exe','class':'incident','note':'copy'},
 {'id':'F5','_time':ts(36.3),'host':H[4],'user':U[2],'action':'read','path':'D:\\Shares\\Finance\\Q3.xlsx','process':'backup-agent.exe','class':'benign','note':'backup'},
 {'id':'F6','_time':ts(42.3),'host':H[4],'user':U[3],'action':'create','path':'C:\\IR\\triage.txt','process':'cmd.exe','class':'response','note':'triage'}],lambda i:{'id':f'F{i+100:05}','_time':ts(R.randint(-1440,4320)),'host':R.choice(H),'user':R.choice(U),'action':R.choice(['read','create','modify']),'path':'C:\\Windows\\Temp\\app.log','process':'routine.exe','class':'benign','note':'routine'})
save('network_activity.csv',['id','_time','src','dest','user','port','action','bytes','class','note'],[
 {'id':'N1','_time':ts(11),'src':H[0],'dest':H[2],'user':U[0],'port':'5985','action':'blocked','bytes':'812','class':'scope','note':'failed WinRM'},
 {'id':'N2','_time':ts(21),'src':H[0],'dest':H[1],'user':U[0],'port':'445','action':'allowed','bytes':'8210','class':'incident','note':'movement'},
 {'id':'N3','_time':ts(34),'src':H[4],'dest':H[8],'user':U[0],'port':'88','action':'allowed','bytes':'1290','class':'incident','note':'Kerberos'},
 {'id':'N4','_time':ts(36),'src':H[7],'dest':H[4],'user':U[2],'port':'445','action':'allowed','bytes':'74221','class':'benign','note':'backup'},
 {'id':'N5','_time':ts(42),'src':H[6],'dest':H[4],'user':U[3],'port':'3389','action':'allowed','bytes':'19002','class':'response','note':'responder'},
 {'id':'N6','_time':ts(47),'src':H[4],'dest':'198.51.100.20','user':U[0],'port':'443','action':'allowed','bytes':'18321','class':'gap','note':'outbound TLS; payload unknown'}],lambda i:{'id':f'N{i+100:05}','_time':ts(R.randint(-1440,4320)),'src':R.choice(H),'dest':R.choice(H),'user':R.choice(U),'port':str(R.choice([443,445,88])),'action':'allowed','bytes':str(R.randint(100,90000)),'class':'benign','note':'routine'})
save('identity_admin.csv',['id','_time','actor','user','action','result','class','note'],[
 {'id':'I1','_time':ts(27),'actor':'helpdesk1','user':U[0],'action':'password_reset','result':'success','class':'response','note':'reset'},
 {'id':'I2','_time':ts(28),'actor':'SOC-AUTOMATION','user':U[0],'action':'revoke_sessions','result':'partial','class':'response','note':'partial revocation'},
 {'id':'I3','_time':ts(38),'actor':'jsmith','user':U[0],'action':'disable_account','result':'success','class':'response','note':'after FILE-02 activity'}],lambda i:{'id':f'I{i+100:05}','_time':ts(R.randint(-1440,4320)),'actor':'helpdesk1','user':R.choice(U),'action':'review','result':'success','class':'benign','note':'routine'})
save('response_activity.csv',['id','_time','host','user','action','class','note'],[
 {'id':'R1','_time':ts(9),'host':H[0],'user':'SOC','action':'isolate','class':'response','note':'confirmed source'},
 {'id':'R2','_time':ts(15),'host':H[2],'user':'jsmith','action':'scope_only','class':'response','note':'not confirmed'},
 {'id':'R3','_time':ts(26),'host':H[1],'user':'SOC','action':'isolate','class':'response','note':'confirmed second host'},
 {'id':'R4','_time':ts(41),'host':H[4],'user':'jsmith','action':'collect_volatile','class':'response','note':'shared server'},
 {'id':'R5','_time':ts(44),'host':H[4],'user':'jsmith','action':'restrict_network','class':'response','note':'contain after collection'}],lambda i:{'id':f'R{i+100:05}','_time':ts(R.randint(-1440,4320)),'host':R.choice(H),'user':'SOC','action':'review','class':'response','note':'routine'})
save('investigation_findings.csv',['id','entity','evidence','decision','confidence','gap'],[
 {'id':'X1','entity':H[0],'evidence':'download + credential access','decision':'confirmed compromised','confidence':'high','gap':''},
 {'id':'X2','entity':H[2],'evidence':'failed WinRM','decision':'scope, not confirmed','confidence':'high','gap':'no attacker success'},
 {'id':'X3','entity':H[3],'evidence':'failed WinRM','decision':'scope, not confirmed','confidence':'high','gap':'no attacker success'},
 {'id':'X4','entity':H[1],'evidence':'successful SMB + execution','decision':'confirmed compromised','confidence':'high','gap':''},
 {'id':'X5','entity':H[4],'evidence':'post-reset success + execution + Q3 copy','decision':'contain','confidence':'high','gap':'initial access path'},
 {'id':'X6','entity':H[4],'evidence':'outbound TLS after Q3 read','decision':'investigate exfiltration','confidence':'medium','gap':'no file-to-session linkage'}],lambda i:{'id':f'X{i+100:05}','entity':R.choice(H),'evidence':'routine context','decision':'context','confidence':'high','gap':''})
print('Generated 8 x 10,000 = 80,000 records')
