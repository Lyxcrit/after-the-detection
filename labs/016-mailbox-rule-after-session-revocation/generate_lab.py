#!/usr/bin/env python3
"""Deterministic synthetic mailbox-rule investigation. Standard library only."""
import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
APP = ROOT / 'splunk' / 'after_detection_hunt_016' / 'lookups'
BASE = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
USERS = ['ACME\\jortiz','ACME\\hpatel','ACME\\ssmith','ACME\\knguyen','ACME\\lgarcia','ACME\\ewong','ACME\\dchen','ACME\\rlee','ACME\\mroberts','ACME\\tadams','ACME\\bcarter','ACME\\npatel']
TRUSTED = [f'203.0.113.{20+i}' for i in range(12)]
SCHEMA = {
 'identity_signins.csv': ['event_id','_time','user','session_id','source_ip','device_id','managed','mfa_result','result'],
 'network_context.csv': ['event_id','_time','source_ip','network_class','owner','approved_egress','notes'],
 'mailbox_inventory.csv': ['event_id','_time','user','mailbox_id','department','external_forward_exception'],
 'mailbox_rules.csv': ['event_id','_time','rule_id','user','mailbox_id','session_id','source_ip','rule_action','match_subject','forward_to','enabled','approved','change_ticket'],
 'mailbox_audit.csv': ['event_id','_time','operation','rule_id','user','session_id','source_ip','actor','result'],
 'message_trace.csv': ['event_id','_time','message_id','rule_id','user','mailbox_id','event_type','destination','status','rule_applied','subject_tag'],
 'responder_actions.csv': ['event_id','_time','ticket_id','user','session_id','rule_id','action','result','actor'],
 'detection_results.csv': ['event_id','_time','detection_id','user','session_id','rule_id','reason','severity','status'],
}

def ts(minutes):
 return (BASE+timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ')

def mbx(user):
 return 'mbx-'+user.split('\\')[-1]

def row(kind, ident, minute, **kwargs):
 return dict(event_id=f'{kind}-{ident}', _time=ts(minute), **kwargs)

records = {name: [] for name in SCHEMA}
def add(name, kind, ident, minute, **kwargs):
 records[name].append(row(kind, ident, minute, **kwargs))

for i, ip in enumerate(TRUSTED):
 add('network_context.csv','net',f'{i:03}',0,source_ip=ip,network_class='corporate_egress',owner='ACME network',approved_egress='true',notes='managed endpoint/VPN egress')
add('network_context.csv','net','suspect',0,source_ip='198.51.100.74',network_class='unclassified_external',owner='unknown',approved_egress='false',notes='no matching approved VPN/helpdesk context')
add('network_context.csv','net','partner',0,source_ip='198.51.100.20',network_class='approved_partner',owner='partner',approved_egress='true',notes='known partner network')
for i in range(236):
 add('network_context.csv','net',f'extra-{i:03}',0,source_ip=f'192.0.2.{i+1}',network_class='observed_background',owner='unattributed',approved_egress='false',notes='background inventory; not necessarily suspicious')

for i in range(150):
 user = USERS[i] if i < 12 else ('ACME\\socadmin' if i == 12 else f'ACME\\user{i:03}')
 add('mailbox_inventory.csv','mbx',f'{i:03}',0,user=user,mailbox_id=mbx(user),department='Finance' if i%4==0 else 'Operations',external_forward_exception='true' if i in (1,5) else 'false')

for i in range(597):
 user=USERS[i%len(USERS)]
 add('identity_signins.csv','signin',f'ben-{i:03}',(i*7)%220,user=user,session_id=f'sess-ben-{i:03}',source_ip=TRUSTED[i%12],device_id=f'ACME-WS-{i%36:02}',managed='true',mfa_result='satisfied',result='success')
add('identity_signins.csv','signin','jo-managed',64,user=USERS[0],session_id='sess-jo-managed-01',source_ip=TRUSTED[0],device_id='FIN-WS-22',managed='true',mfa_result='satisfied',result='success')
add('identity_signins.csv','signin','jo-new',79,user=USERS[0],session_id='sess-jo-new-01',source_ip='198.51.100.74',device_id='UNKNOWN-WIN',managed='false',mfa_result='satisfied',result='success')
add('identity_signins.csv','signin','admin',101,user='ACME\\socadmin',session_id='sess-admin-01',source_ip=TRUSTED[2],device_id='SOC-ADMIN-02',managed='true',mfa_result='satisfied',result='success')

for i in range(318):
 user=USERS[i%len(USERS)]
 action='move' if i%7==0 else 'forward'
 destination='' if action=='move' else ('partner-finance@partner.example' if i%17==0 else 'operations-archive@acme.example')
 add('mailbox_rules.csv','rule',f'ben-{i:03}',(i*7)%220+1,rule_id=f'rule-ben-{i:03}',user=user,mailbox_id=mbx(user),session_id=f'sess-ben-{i:03}',source_ip=TRUSTED[i%12],rule_action=action,match_subject='invoice' if i%5==0 else 'operations',forward_to=destination,enabled='true',approved='true',change_ticket=f'CHG-{1000+i}')
 add('mailbox_audit.csv','audit',f'ben-{i:03}',(i*7)%220+1,operation='New-InboxRule',rule_id=f'rule-ben-{i:03}',user=user,session_id=f'sess-ben-{i:03}',source_ip=TRUSTED[i%12],actor=user,result='success')
for i in range(130):
 user=USERS[i%12]
 add('mailbox_audit.csv','audit',f'edit-{i:03}',(i*7)%220+2,operation='Set-InboxRule',rule_id=f'rule-ben-{i:03}',user=user,session_id=f'sess-ben-{i:03}',source_ip=TRUSTED[i%12],actor=user,result='success')

RULE='rule-jo-invoices-77'
for ident,minute,enabled in [('created',82,'true'),('disabled',104,'false')]:
 add('mailbox_rules.csv','rule',f'jo-{ident}',minute,rule_id=RULE,user=USERS[0],mailbox_id=mbx(USERS[0]),session_id='sess-jo-new-01',source_ip='198.51.100.74',rule_action='forward',match_subject='invoice',forward_to='invoice-review@outside.example',enabled=enabled,approved='false',change_ticket='')
add('mailbox_audit.csv','audit','jo-create',82,operation='New-InboxRule',rule_id=RULE,user=USERS[0],session_id='sess-jo-new-01',source_ip='198.51.100.74',actor=USERS[0],result='success')
add('mailbox_audit.csv','audit','jo-disable',104,operation='Disable-InboxRule',rule_id=RULE,user=USERS[0],session_id='sess-admin-01',source_ip=TRUSTED[2],actor='ACME\\socadmin',result='success')

for i in range(894):
 r=i%318
 user=USERS[r%12]
 action='move' if r%7==0 else 'forward'
 destination=mbx(user) if action=='move' else ('partner-finance@partner.example' if r%17==0 else 'operations-archive@acme.example')
 add('message_trace.csv','trace',f'ben-{i:03}',(i*11)%220+3,message_id=f'msg-ben-{i:03}',rule_id=f'rule-ben-{r:03}',user=user,mailbox_id=mbx(user),event_type='inbox_delivery' if action=='move' else 'forward_delivery',destination=destination,status='delivered',rule_applied='false' if action=='move' else 'true',subject_tag='invoice' if r%5==0 else 'operations')
for ident,minute,msg,event_type,dest,applied in [
 ('jo-01-inbox',85,'msg-jo-01','inbox_delivery',mbx(USERS[0]),'false'),
 ('jo-01-forward',85,'msg-jo-01','forward_delivery','invoice-review@outside.example','true'),
 ('jo-02-forward',88,'msg-jo-02','forward_delivery','invoice-review@outside.example','true'),
 ('jo-03-forward',96,'msg-jo-03','forward_delivery','invoice-review@outside.example','true'),
 ('jo-04-inbox',109,'msg-jo-04','inbox_delivery',mbx(USERS[0]),'false'),
 ('jo-05-inbox',116,'msg-jo-05','inbox_delivery',mbx(USERS[0]),'false')]:
 add('message_trace.csv','trace',ident,minute,message_id=msg,rule_id=RULE,user=USERS[0],mailbox_id=mbx(USERS[0]),event_type=event_type,destination=dest,status='delivered',rule_applied=applied,subject_tag='invoice')

for i in range(97):
 user=USERS[i%12]
 add('responder_actions.csv','response',f'ben-{i:03}',(i*9)%220+3,ticket_id=f'SOC-{2000+i}',user=user,session_id=f'sess-ben-{i:03}',rule_id=f'rule-ben-{i:03}',action='review_rule',result='completed',actor='ACME\\socadmin')
for ident,minute,action in [('session',91,'revoke_interactive_session'),('rule',104,'disable_inbox_rule'),('password',110,'reset_password')]:
 add('responder_actions.csv','response',f'jo-{ident}',minute,ticket_id='SOC-016-77',user=USERS[0],session_id='sess-jo-new-01',rule_id=RULE,action=action,result='completed',actor='ACME\\socadmin')
for i in range(179):
 user=USERS[i%12]
 add('detection_results.csv','detect',f'ben-{i:03}',(i*13)%220+2,detection_id=f'ATD16-BEN-{i:03}',user=user,session_id=f'sess-ben-{i:03}',rule_id=f'rule-ben-{i:03}',reason='mailbox rule change review',severity='low',status='triaged')
add('detection_results.csv','detect','primary',87,detection_id='ATD16-001',user=USERS[0],session_id='sess-jo-new-01',rule_id=RULE,reason='unapproved external forward after unexplained sign-in',severity='high',status='open')

for name, rows in records.items():
 fields=SCHEMA[name]
 assert all(set(x)==set(fields) for x in rows), name
 rows.sort(key=lambda r:(r['_time'],r['event_id']))
 for folder in (DATA, APP):
  folder.mkdir(parents=True,exist_ok=True)
  with (folder/name).open('w',newline='',encoding='utf-8') as f:
   writer=csv.DictWriter(f,fieldnames=fields,lineterminator='\n')
   writer.writeheader()
   writer.writerows(rows)
 print(f'{name}: {len(rows)} records')
print('Hunt 016 generated (deterministic).')
