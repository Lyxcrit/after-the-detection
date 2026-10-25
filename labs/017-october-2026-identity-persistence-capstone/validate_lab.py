#!/usr/bin/env python3
"""Independent structural, evidence, and deterministic-rebuild checks."""
import csv
import hashlib
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE=pathlib.Path(__file__).resolve().parent
DATA=HERE/'data'
APP=HERE/'splunk'/'after_detection_capstone_017'/'lookups'
NAMES=['identity_signins','device_inventory','network_context','oauth_grants','token_events','graph_activity','mailbox_rules','mailbox_audit','message_trace','responder_actions','detection_results']

def load(name):
    with (DATA/(name+'.csv')).open(newline='',encoding='utf-8') as f:
        return list(csv.DictReader(f))

def one(rows,**criteria):
    found=[r for r in rows if all(r[k]==v for k,v in criteria.items())]
    assert len(found)==1,(criteria,len(found))
    return found[0]

def check():
    d={name:load(name) for name in NAMES}
    for name,rows in d.items():
        assert len(rows)==10000,(name,len(rows))
        assert len({r['event_id'] for r in rows})==10000,name
        assert (DATA/(name+'.csv')).read_bytes()==(APP/(name+'.csv')).read_bytes(),name
    users={r['user'] for r in d['identity_signins']}
    sessions={r['session_id'] for r in d['identity_signins']}
    sources={r['source_ip'] for r in d['network_context']}
    devices={r['device_id'] for r in d['device_inventory']}
    grants={r['grant_id'] for r in d['oauth_grants']}
    tokens={r['token_id'] for r in d['token_events']}
    rules={r['rule_id'] for r in d['mailbox_rules']}
    assert all(r['source_ip'] in sources and r['device_id'] in devices for r in d['identity_signins'])
    assert all(r['grant_id'] in grants and r['session_id'] in sessions for r in d['token_events'])
    assert all(r['token_id'] in tokens for r in d['graph_activity'])
    assert all(r['rule_id'] in rules for r in d['mailbox_audit'])
    assert all(r['rule_id'] in rules for r in d['message_trace'] if r['rule_id'])
    assert all(r['user'] in users for r in d['oauth_grants'])
    a=one(d['identity_signins'],session_id='sess-kn-new-017')
    assert a['timestamp']=='2026-10-23T16:12:00Z' and a['source_ip']=='198.51.100.74' and a['mfa_result']=='satisfied'
    assert one(d['oauth_grants'],grant_id='grant-qrs-779')['timestamp']=='2026-10-23T16:16:00Z'
    assert one(d['oauth_grants'],grant_id='grant-00001')['timestamp'] < one(d['token_events'],token_id='tok-interactive-017')['timestamp'] < one(d['graph_activity'],request_id='req-00000')['timestamp']
    assert one(d['token_events'],token_id='tok-interactive-017')['grant_id']=='grant-00001'
    assert one(d['graph_activity'],request_id='req-00000')['app_id']=='app-approved-002'
    case_tokens={r['token_id']:r for r in d['token_events'] if r['token_id'] in ('tok-interactive-017','tok-qrs-779-1')}
    for i in range(5):
        g=one(d['graph_activity'],request_id=f'req-{i:05}')
        t=case_tokens[g['token_id']]
        assert g['app_id']==t['app_id'] and g['user']==t['user'] and t['timestamp'] <= g['timestamp']
        grant=one(d['oauth_grants'],grant_id=t['grant_id'])
        assert grant['app_id']==t['app_id'] and grant['user']==t['user'] and grant['timestamp'] <= t['timestamp']
    assert one(d['mailbox_audit'],operation='New-InboxRule')['timestamp']=='2026-10-23T16:19:00Z'
    assert one(d['responder_actions'],ticket='INC-017',action='revoke_interactive_session')['timestamp']=='2026-10-23T16:22:00Z'
    post_graph=one(d['graph_activity'],request_id='req-00003')
    assert post_graph['timestamp']=='2026-10-23T16:25:00Z' and post_graph['result']=='success'
    assert one(d['graph_activity'],request_id='req-00004')['result']=='denied'
    forwards=[r for r in d['message_trace'] if r['rule_id']=='rule-kn-invoices-017' and r['action']=='forward' and r['result']=='delivered']
    assert len(forwards)==2 and {r['message_id'] for r in forwards}=={'msg-kn-001','msg-kn-002'}
    assert one(d['mailbox_rules'],rule_id='rule-kn-invoices-017',snapshot='after_disable')['enabled']=='false'
    assert one(d['mailbox_audit'],operation='Disable-InboxRule')['timestamp']=='2026-10-23T16:34:00Z'
    assert not [r for r in forwards if r['timestamp']>='2026-10-23T16:34:00Z']
    assert one(d['mailbox_rules'],rule_id='rule-partner-approved')['approved_change']=='CHG-2048'
    assert len([r for r in d['responder_actions'] if r['ticket']=='INC-017'])==6
    with tempfile.TemporaryDirectory() as tmp:
        root=pathlib.Path(tmp)
        shutil.copy2(HERE/'generate_lab.py',root/'generate_lab.py')
        subprocess.run([sys.executable,str(root/'generate_lab.py')],check=True,capture_output=True,text=True)
        for name in NAMES:
            fn=name+'.csv'
            assert hashlib.sha256((DATA/fn).read_bytes()).digest()==hashlib.sha256((root/'data'/fn).read_bytes()).digest(),f'non-deterministic {fn}'
    print('PASS: 11 lookups x 10,000 = 110,000 rows; keys, evidence, mirrored Splunk lookups, and byte-for-byte deterministic regeneration.')

if __name__=='__main__':
    check()
