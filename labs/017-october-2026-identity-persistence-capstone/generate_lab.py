#!/usr/bin/env python3
"""Deterministic, synthetic October identity persistence capstone; Python stdlib only."""
import csv
import datetime as dt
import pathlib
import random
import shutil

HERE = pathlib.Path(__file__).resolve().parent
DATA = HERE / 'data'
APP = HERE / 'splunk' / 'after_detection_capstone_017' / 'lookups'
SEED = 20261026
ROWS = 10000
UTC = dt.timezone.utc
BASE = dt.datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
R = random.Random(SEED)

def stamp(minute):
    return (BASE + dt.timedelta(minutes=minute)).strftime('%Y-%m-%dT%H:%M:%SZ')

def write(name, fields, records):
    assert len(records) == ROWS, (name, len(records))
    DATA.mkdir(parents=True, exist_ok=True)
    APP.mkdir(parents=True, exist_ok=True)
    target = DATA / (name + '.csv')
    with target.open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=fields, lineterminator='\n')
        w.writeheader()
        w.writerows(records)
    shutil.copyfile(target, APP / target.name)

USERS = ['ACME\\knguyen', 'ACME\\mrivera', 'ACME\\jortiz'] + [f'ACME\\user{i:03}' for i in range(1, 148)]
DEVICES = ['SALES-WS-18', 'UNKNOWN-WIN', 'FIN-WS-22', 'APP-SRV-04'] + [f'CORP-WS-{i:03}' for i in range(1, 247)]
IPS = ['203.0.113.12', '198.51.100.74', '198.51.100.146', '203.0.113.45'] + [f'10.{i//240+12}.{(i//16)%15}.{i%240+10}' for i in range(246)]
APPS = ['app-qrs-779', 'app-approved-002'] + [f'app-{i:04}' for i in range(2, 198)]
GRANTS = ['grant-qrs-779'] + [f'grant-{i:05}' for i in range(1, 10000)]
TOKENS = ['tok-qrs-779-1', 'tok-interactive-017'] + [f'tok-{i:05}' for i in range(2, 10000)]
RULES = ['rule-kn-invoices-017', 'rule-partner-approved'] + [f'rule-{i:05}' for i in range(2, 10000)]
SESSIONS = ['sess-kn-normal', 'sess-kn-new-017'] + [f'sess-{i:05}' for i in range(2, 10000)]

network = []
for i in range(ROWS):
    ip = IPS[i % len(IPS)]
    approved = ip.startswith('10.') or ip in ('203.0.113.12', '203.0.113.45')
    network.append(dict(event_id=f'NET-{i:05}', timestamp=stamp(i % 600), source_ip=ip, source_type='corporate_vpn' if approved else 'unclassified_external', geo='US-VA' if approved else 'unverified', approved_egress=str(approved).lower(), ticket='NET-APPROVED' if approved else ''))
write('network_context', ['event_id','timestamp','source_ip','source_type','geo','approved_egress','ticket'], network)

devices = []
for i in range(ROWS):
    device = DEVICES[i % len(DEVICES)]
    managed = device != 'UNKNOWN-WIN'
    devices.append(dict(event_id=f'DEV-{i:05}',timestamp=stamp(i % 600),device_id=device,hostname=device,managed=str(managed).lower(),trust='compliant' if managed else 'unknown',owner='ACME\\knguyen' if device in ('SALES-WS-18','UNKNOWN-WIN') else USERS[(i % len(DEVICES)) % len(USERS)],role='workstation' if 'WS' in device or 'WIN' in device else 'automation'))
write('device_inventory',['event_id','timestamp','device_id','hostname','managed','trust','owner','role'],devices)

signins = []
for i in range(ROWS):
    user=USERS[i % len(USERS)]; sess=SESSIONS[i]; device=DEVICES[(i*7+5)%len(DEVICES)]; ip=IPS[(i*11+5)%len(IPS)]
    signins.append(dict(event_id=f'AUTH-{i:05}',timestamp=stamp(i % 600),user=user,session_id=sess,source_ip=ip,device_id=device,auth_result='success' if i%17 else 'failure',mfa_result='satisfied' if i%17 else 'not_applicable',client='browser'))
signins[0].update(timestamp=stamp(228),user='ACME\\knguyen',session_id='sess-kn-normal',source_ip='203.0.113.12',device_id='SALES-WS-18',auth_result='success',mfa_result='satisfied')
signins[1].update(timestamp=stamp(252),user='ACME\\knguyen',session_id='sess-kn-new-017',source_ip='198.51.100.74',device_id='UNKNOWN-WIN',auth_result='success',mfa_result='satisfied')
write('identity_signins',['event_id','timestamp','user','session_id','source_ip','device_id','auth_result','mfa_result','client'],signins)

grants=[]
for i in range(ROWS):
    user=USERS[i%len(USERS)]; approved=i%9!=0
    grants.append(dict(event_id=f'GRANT-{i:05}',timestamp=stamp(i%600),grant_id=GRANTS[i],app_id=APPS[i%len(APPS)],user=user,scopes='User.Read' if approved else 'Mail.Read offline_access',consent_actor=user,approval='approved' if approved else 'unreviewed',status='active'))
grants[1].update(timestamp=stamp(0),grant_id='grant-00001',app_id='app-approved-002',user='ACME\\knguyen',scopes='Files.Read',consent_actor='ACME\\soc-admin',approval='approved',status='active')
grants[0].update(timestamp=stamp(256),grant_id='grant-qrs-779',app_id='app-qrs-779',user='ACME\\knguyen',scopes='Mail.Read offline_access',consent_actor='ACME\\knguyen',approval='unreviewed',status='active')
write('oauth_grants',['event_id','timestamp','grant_id','app_id','user','scopes','consent_actor','approval','status'],grants)

tokens=[]
for i in range(ROWS):
    grant=grants[i]
    tokens.append(dict(event_id=f'TOKEN-{i:05}',timestamp=stamp(i%600),token_id=TOKENS[i],grant_id=grant['grant_id'],app_id=grant['app_id'],user=grant['user'],session_id=SESSIONS[i],action='issue',result='success',expires_at=stamp((i%600)+60)))
tokens[0].update(timestamp=stamp(257),token_id='tok-qrs-779-1',grant_id='grant-qrs-779',app_id='app-qrs-779',user='ACME\\knguyen',session_id='sess-kn-new-017',expires_at=stamp(317))
tokens[1].update(timestamp=stamp(253),token_id='tok-interactive-017',grant_id='grant-00001',app_id='app-approved-002',user='ACME\\knguyen',session_id='sess-kn-new-017',expires_at=stamp(313))
write('token_events',['event_id','timestamp','token_id','grant_id','app_id','user','session_id','action','result','expires_at'],tokens)

graph=[]
for i in range(ROWS):
    token=tokens[i%len(tokens)]
    graph.append(dict(event_id=f'GRAPH-{i:05}',timestamp=stamp(i%600),request_id=f'req-{i:05}',token_id=token['token_id'],app_id=token['app_id'],user=token['user'],resource='Graph',operation='User.Read' if i%5 else 'Mail.Read',result='success' if i%31 else 'denied',bytes_returned=R.randrange(400,12000)))
for i,minute,token,operation,result,bytes_ in [(0,254,'tok-interactive-017','SharePoint.Files.Read','success',8120),(1,258,'tok-qrs-779-1','Mail.Read','success',9300),(2,261,'tok-qrs-779-1','Mail.Read','success',12100),(3,265,'tok-qrs-779-1','Mail.Read','success',8500),(4,271,'tok-qrs-779-1','Mail.Read','denied',0)]:
    graph[i].update(timestamp=stamp(minute),token_id=token,app_id='app-approved-002' if i==0 else 'app-qrs-779',user='ACME\\knguyen',resource='SharePoint' if i==0 else 'Graph',operation=operation,result=result,bytes_returned=bytes_)
write('graph_activity',['event_id','timestamp','request_id','token_id','app_id','user','resource','operation','result','bytes_returned'],graph)

rules=[]
for i in range(ROWS):
    user=USERS[i%len(USERS)]; approved=i%11!=0
    rules.append(dict(event_id=f'RULE-{i:05}',timestamp=stamp(i%600),rule_id=RULES[i],user=user,subject_match='invoice' if i%3 else 'report',forward_to=f'partner{i%23}.example' if approved else 'external-review.example',approved_change='CHG-2026-APPROVED' if approved else '',enabled='true' if i%13 else 'false',snapshot='baseline'))
rules[0].update(timestamp=stamp(259),rule_id='rule-kn-invoices-017',user='ACME\\knguyen',subject_match='invoice',forward_to='invoice-review@outside.example',approved_change='',enabled='true',snapshot='after_create')
rules[1].update(timestamp=stamp(274),rule_id='rule-kn-invoices-017',user='ACME\\knguyen',subject_match='invoice',forward_to='invoice-review@outside.example',approved_change='',enabled='false',snapshot='after_disable')
rules[2].update(timestamp=stamp(258),rule_id='rule-partner-approved',user='ACME\\mrivera',subject_match='invoice',forward_to='accounts@approved-partner.example',approved_change='CHG-2048',enabled='true',snapshot='baseline')
write('mailbox_rules',['event_id','timestamp','rule_id','user','subject_match','forward_to','approved_change','enabled','snapshot'],rules)

audit=[]
for i in range(ROWS):
    rule=rules[i]
    audit.append(dict(event_id=f'AUDIT-{i:05}',timestamp=stamp(i%600),user=rule['user'],rule_id=rule['rule_id'],session_id=SESSIONS[i],operation='Set-InboxRule' if i%3 else 'Get-InboxRule',actor=rule['user'],source_ip=IPS[(i*11+5)%len(IPS)],result='success',change_ticket=rule['approved_change']))
audit[0].update(timestamp=stamp(259),user='ACME\\knguyen',rule_id='rule-kn-invoices-017',session_id='sess-kn-new-017',operation='New-InboxRule',actor='ACME\\knguyen',source_ip='198.51.100.74',result='success',change_ticket='')
audit[1].update(timestamp=stamp(274),user='ACME\\knguyen',rule_id='rule-kn-invoices-017',session_id='sess-soc-admin',operation='Disable-InboxRule',actor='ACME\\soc-admin',source_ip='203.0.113.12',result='success',change_ticket='INC-017')
write('mailbox_audit',['event_id','timestamp','user','rule_id','session_id','operation','actor','source_ip','result','change_ticket'],audit)

trace=[]
for i in range(ROWS):
    rule=rules[i]
    trace.append(dict(event_id=f'MAIL-{i:05}',timestamp=stamp(i%600),message_id=f'msg-{i:05}',user=rule['user'],rule_id=rule['rule_id'],destination='internal@acme.example' if i%4 else rule['forward_to'],action='delivered' if i%4 else 'forward',result='delivered',subject_class='invoice' if i%3 else 'routine'))
for i,minute,msg,action,dest in [(0,260,'msg-kn-001','forward','invoice-review@outside.example'),(1,264,'msg-kn-002','forward','invoice-review@outside.example'),(2,276,'msg-kn-003','delivered','ACME\\knguyen'),(3,280,'msg-kn-004','delivered','ACME\\knguyen')]:
    trace[i].update(timestamp=stamp(minute),message_id=msg,user='ACME\\knguyen',rule_id='rule-kn-invoices-017' if i<2 else '',destination=dest,action=action,result='delivered',subject_class='invoice')
write('message_trace',['event_id','timestamp','message_id','user','rule_id','destination','action','result','subject_class'],trace)

actions=[]
for i in range(ROWS):
    actions.append(dict(event_id=f'RESP-{i:05}',timestamp=stamp(i%600),ticket=f'INC-{i:05}',user=USERS[i%len(USERS)],entity_type='session' if i%2 else 'account',entity_id=SESSIONS[i],action='review_session' if i%2 else 'review_account',result='completed',operator='ACME\\soc-analyst',notes='routine_triage'))
for i,minute,etype,eid,act,note in [(0,262,'session','sess-kn-new-017','revoke_interactive_session','Does not remove OAuth grants or inbox rules'),(1,268,'oauth_app','app-qrs-779','disable_app_and_remove_consent','Check resource token enforcement'),(2,269,'token','tok-qrs-779-1','revoke_refresh_tokens','Existing access token may remain valid until enforced'),(3,274,'mail_rule','rule-kn-invoices-017','disable_rule','Confirm mailbox state and subsequent trace'),(4,279,'account','ACME\\knguyen','reset_password','Does not undo prior resource access'),(5,282,'mailbox','ACME\\knguyen','verify_forwarding','No later forward observed in bounded dataset')]:
    actions[i].update(timestamp=stamp(minute),ticket='INC-017',user='ACME\\knguyen',entity_type=etype,entity_id=eid,action=act,result='completed',operator='ACME\\soc-analyst',notes=note)
write('responder_actions',['event_id','timestamp','ticket','user','entity_type','entity_id','action','result','operator','notes'],actions)

detections=[]
for i in range(ROWS):
    detections.append(dict(event_id=f'DET-{i:05}',timestamp=stamp(i%600),detection_id=f'ATD17-N-{i:05}',user=USERS[i%len(USERS)],signal='external_forward_review' if i%3 else 'unusual_signin',entity_id=SESSIONS[i],severity='medium' if i%7 else 'low',status='open',evidence='Needs correlation with approved changes'))
for i,minute,signal,entity in [(0,252,'unmanaged_successful_signin','sess-kn-new-017'),(1,256,'unapproved_oauth_consent','grant-qrs-779'),(2,259,'unapproved_external_forward','rule-kn-invoices-017'),(3,265,'resource_access_after_session_revocation','tok-qrs-779-1')]:
    detections[i].update(timestamp=stamp(minute),detection_id=f'ATD17-00{i+1}',user='ACME\\knguyen',signal=signal,entity_id=entity,severity='high',status='investigate',evidence='Correlate identity, grant, token, mailbox, and response timeline')
write('detection_results',['event_id','timestamp','detection_id','user','signal','entity_id','severity','status','evidence'],detections)

print('Generated 11 CSV lookups x 10,000 records = 110,000 synthetic records (seed 20261026).')
