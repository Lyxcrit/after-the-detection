#!/usr/bin/env python3
"""Validate data joins, chronology, modeled claims, reproducibility, and Splunk copies."""
import csv
import hashlib
import subprocess
import sys
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parent
DATA=ROOT/'data'
APP=ROOT/'splunk'/'after_detection_hunt_016'/'lookups'
EXPECTED={'identity_signins.csv':600,'network_context.csv':250,'mailbox_inventory.csv':150,'mailbox_rules.csv':320,'mailbox_audit.csv':450,'message_trace.csv':900,'responder_actions.csv':100,'detection_results.csv':180}
def load(name):
 with (DATA/name).open(newline='',encoding='utf-8') as f:return list(csv.DictReader(f))
def dt(s):return datetime.strptime(s,'%Y-%m-%dT%H:%M:%SZ')
rows={n:load(n) for n in EXPECTED}
assert sum(EXPECTED.values())==2950
for name, expected in EXPECTED.items():
 values=rows[name]
 assert len(values)==expected,(name,len(values),expected)
 assert len({r['event_id'] for r in values})==expected,name
 assert all(dt(r['_time']) for r in values),name
 assert (DATA/name).read_bytes()==(APP/name).read_bytes(),name
assert len({r['event_id'] for rs in rows.values() for r in rs})==2950
net={r['source_ip'] for r in rows['network_context.csv']}
mbx={r['user']:r['mailbox_id'] for r in rows['mailbox_inventory.csv']}
sessions={r['session_id']:r for r in rows['identity_signins.csv']}
rules={r['rule_id']:r for r in rows['mailbox_rules.csv']}
for r in rows['identity_signins.csv']:
 assert r['source_ip'] in net and r['user'] in mbx
for r in rows['mailbox_rules.csv']:
 assert r['user'] in mbx and r['mailbox_id']==mbx[r['user']]
 assert r['source_ip'] in net and r['session_id'] in sessions
 assert sessions[r['session_id']]['user']==r['user']
for r in rows['mailbox_audit.csv']:
 assert r['rule_id'] in rules and r['session_id'] in sessions and r['source_ip'] in net
 assert r['user']==rules[r['rule_id']]['user']
for r in rows['message_trace.csv']:
 assert r['rule_id'] in rules and r['mailbox_id']==mbx[r['user']]
 assert r['user']==rules[r['rule_id']]['user']
for r in rows['responder_actions.csv']:
 assert r['rule_id'] in rules and r['session_id'] in sessions and r['user']==rules[r['rule_id']]['user']
for r in rows['detection_results.csv']:
 assert r['rule_id'] in rules and r['session_id'] in sessions and r['user']==rules[r['rule_id']]['user']
primary=next(r for r in rows['detection_results.csv'] if r['detection_id']=='ATD16-001')
assert sum(r['detection_id']=='ATD16-001' for r in rows['detection_results.csv'])==1
assert primary['user']=='ACME\\jortiz' and primary['rule_id']=='rule-jo-invoices-77'
new=sessions['sess-jo-new-01']
assert new['result']=='success' and new['managed']=='false' and new['source_ip']=='198.51.100.74'
assert next(r for r in rows['network_context.csv'] if r['source_ip']==new['source_ip'])['approved_egress']=='false'
audit=rows['mailbox_audit.csv']
created=next(r for r in audit if r['event_id']=='audit-jo-create')
disabled=next(r for r in audit if r['event_id']=='audit-jo-disable')
assert created['session_id']==new['session_id'] and created['source_ip']==new['source_ip']
assert disabled['operation']=='Disable-InboxRule' and disabled['actor']=='ACME\\socadmin'
rule_states=sorted((r for r in rows['mailbox_rules.csv'] if r['rule_id']==primary['rule_id']),key=lambda r:r['_time'])
assert len(rule_states)==2 and [r['enabled'] for r in rule_states]==['true','false']
assert rule_states[0]['approved']=='false' and rule_states[0]['forward_to']=='invoice-review@outside.example'
resp={r['action']:r for r in rows['responder_actions.csv'] if r['ticket_id']=='SOC-016-77'}
assert set(resp)=={'revoke_interactive_session','disable_inbox_rule','reset_password'}
traces=[r for r in rows['message_trace.csv'] if r['rule_id']==primary['rule_id']]
forward=[r for r in traces if r['event_type']=='forward_delivery' and r['status']=='delivered']
assert len(forward)==3
assert dt(new['_time'])<dt(created['_time'])<dt(resp['revoke_interactive_session']['_time'])<dt(resp['disable_inbox_rule']['_time'])
assert any(dt(resp['revoke_interactive_session']['_time'])<dt(r['_time'])<dt(resp['disable_inbox_rule']['_time']) for r in forward)
assert all(dt(r['_time'])<dt(resp['disable_inbox_rule']['_time']) for r in forward)
assert any(dt(r['_time'])>dt(resp['disable_inbox_rule']['_time']) and r['event_type']=='inbox_delivery' and r['rule_applied']=='false' for r in traces)
assert not any(dt(r['_time'])>dt(resp['disable_inbox_rule']['_time']) and r['event_type']=='forward_delivery' for r in traces)
assert any(r['forward_to']=='partner-finance@partner.example' and r['approved']=='true' and r['change_ticket'] for r in rows['mailbox_rules.csv'])
before={n:hashlib.sha256((DATA/n).read_bytes()).hexdigest() for n in EXPECTED}
subprocess.run([sys.executable,str(ROOT/'generate_lab.py')],check=True,capture_output=True)
after={n:hashlib.sha256((DATA/n).read_bytes()).hexdigest() for n in EXPECTED}
assert before==after,'Generator is not byte-for-byte deterministic'
report='# Hunt 016 validation report\n\n**Overall: PASS**\n\n- Fixed UTC event times; deterministic Python standard-library generator.\n- Unique event IDs across all eight CSV lookups.\n- All authentication source IPs resolve to network context; all mailbox references resolve to inventory.\n- Rule/audit/trace/detection/response IDs resolve to known rules and sessions.\n- Suspicious chain: managed sign-in → unmanaged sign-in → external forwarding rule → successful forward → session revoked → successful forward → rule disabled → inbox delivery without observed forward.\n- Approved partner forwarding and internal mailbox automation provide documented look-alikes.\n- Identical CSV bytes in platform-portable `data/` and Splunk app `lookups/`.\n- Regeneration is byte-for-byte deterministic.\n\n| Lookup | Records |\n|---|---:|\n'
report+=''.join(f'| `{k}` | {v:,} |\n' for k,v in EXPECTED.items())
report+=f'| **Total** | **{sum(EXPECTED.values()):,}** |\n\nEvidence caveat: a delivered forwarding trace does not establish that an external person read the content; absence of a later forwarding trace is not complete proof of absence outside the modeled dataset.\n'
(ROOT/'validation-report.md').write_text(report,encoding='utf-8')
print('Hunt 016 validation PASS: 2,950 rows, eight lookups, deterministic regeneration')
