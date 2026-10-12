#!/usr/bin/env python3
"""Deterministic synthetic identity/OAuth investigation dataset. Python stdlib only."""
import csv
import hashlib
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / 'data'
DATA.mkdir(exist_ok=True)
SEED = 20261012
RNG = random.Random(SEED)
START = datetime(2026, 10, 9, 7, 0, tzinfo=timezone.utc)
USERS = [f'ACME\\{name}' for name in ('mrivera', 'knguyen', 'lchen', 'rlee', 'ajones', 'tdavis', 'cpark', 'sng', 'jlopez', 'abrown')]
APP_IDS = [f'app-approved-{i:03d}' for i in range(119)]
APP_SUSPECT = 'app-qrs-779'
APPS = APP_IDS + [APP_SUSPECT]
NORMAL_IPS = ['203.0.113.18', '203.0.113.22', '203.0.113.35', '192.0.2.60']
SUSPECT_IP = '198.51.100.146'
USER = 'ACME\\mrivera'
SESSION = 'sess-mriv-new-824'
GRANT = 'grant-qrs-779'
TOKEN = 'tok-qrs-779-1'


def time_at(minute, seconds=0):
    return (START + timedelta(minutes=minute, seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def rows(name, fields, records):
    assert all(set(r) == set(fields) for r in records), name
    path = DATA / name
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(sorted(records, key=lambda r: (r['_time'], r['event_id'])))
    return len(records)


def noise_time():
    return time_at(RNG.randrange(0, 480), RNG.randrange(0, 60))


# Known app inventory; a suspicious user-consented app is deliberately not pre-approved.
inventory = []
for i, app in enumerate(APP_IDS):
    inventory.append(dict(event_id=f'inv-{i:04d}', _time=time_at(i), app_id=app,
        display_name=f'Approved Business Connector {i:03d}', publisher='ACME IT',
        approval_state='approved', app_type='enterprise', risk_tier='low'))
inventory.append(dict(event_id='inv-qrs-779', _time=time_at(120), app_id=APP_SUSPECT,
    display_name='Quarterly Reports Sync', publisher='Unverified',
    approval_state='unapproved', app_type='multi-tenant', risk_tier='unknown'))

# All noise grant IDs resolve to known app IDs, with plausible self-service/admin consent.
grants = []
for i in range(349):
    app = APP_IDS[i % len(APP_IDS)]
    grants.append(dict(event_id=f'grant-event-{i:04d}', _time=noise_time(),
        grant_id=f'grant-approved-{i:04d}', user=USERS[i % len(USERS)], app_id=app,
        consent_type='admin' if i % 3 == 0 else 'user',
        scopes='User.Read Calendars.Read' if i % 2 else 'User.Read',
        result='success', source_ip=NORMAL_IPS[i % len(NORMAL_IPS)],
        session_id=f'sess-normal-{i:04d}', admin_approved='true' if i % 3 == 0 else 'false'))
grants.append(dict(event_id='grant-event-qrs', _time=time_at(146), grant_id=GRANT,
    user=USER, app_id=APP_SUSPECT, consent_type='user', scopes='Mail.Read offline_access',
    result='success', source_ip=SUSPECT_IP, session_id=SESSION, admin_approved='false'))

signins = []
for i in range(648):
    user = USERS[i % len(USERS)]
    signins.append(dict(event_id=f'signin-{i:04d}', _time=noise_time(), user=user,
        source_ip=NORMAL_IPS[i % len(NORMAL_IPS)], device='FIN-WS-09' if user == USER else f'CORP-WS-{i%50:02d}',
        managed='true', result='success' if i % 17 else 'failure',
        auth_method='MFA', session_id=f'sess-normal-{i:04d}', app='Microsoft 365'))
signins.extend([
    dict(event_id='signin-mriv-known', _time=time_at(134), user=USER,
        source_ip='203.0.113.18', device='FIN-WS-09', managed='true',
        result='success', auth_method='MFA', session_id='sess-mriv-known', app='Microsoft 365'),
    dict(event_id='signin-mriv-new', _time=time_at(144), user=USER,
        source_ip=SUSPECT_IP, device='UNKNOWN-WIN', managed='false',
        result='success', auth_method='MFA', session_id=SESSION, app='Microsoft 365')])

# Tokens always resolve to a grant; graph activity always resolves to an issued token.
tokens = []
for i in range(599):
    grant = grants[i % 349]
    tokens.append(dict(event_id=f'token-event-{i:04d}', _time=noise_time(),
        token_id=f'tok-approved-{i:04d}', grant_id=grant['grant_id'],
        app_id=grant['app_id'], user=grant['user'], token_type='access',
        issuance='initial', result='issued', expires_at=time_at(520)))
tokens.append(dict(event_id='token-event-qrs', _time=time_at(148),
    token_id=TOKEN, grant_id=GRANT, app_id=APP_SUSPECT, user=USER,
    token_type='access', issuance='initial', result='issued', expires_at=time_at(208)))

graph = []
for i in range(896):
    tok = tokens[i % 599]
    graph.append(dict(event_id=f'graph-{i:04d}', _time=noise_time(),
        user=tok['user'], app_id=tok['app_id'], token_id=tok['token_id'],
        operation='GET /me/calendar/events' if i % 3 else 'GET /me',
        resource_id=f'calendar-{i%55:03d}', status='200',
        bytes_returned=str(200 + i % 3000), source_ip=NORMAL_IPS[i % len(NORMAL_IPS)]))
graph.extend([
    dict(event_id='graph-qrs-1', _time=time_at(149), user=USER, app_id=APP_SUSPECT,
        token_id=TOKEN, operation='GET /me/messages', resource_id='mailbox-mrivera-msg-001',
        status='200', bytes_returned='1812', source_ip=SUSPECT_IP),
    dict(event_id='graph-qrs-2', _time=time_at(151), user=USER, app_id=APP_SUSPECT,
        token_id=TOKEN, operation='GET /me/messages', resource_id='mailbox-mrivera-msg-002',
        status='200', bytes_returned='2448', source_ip=SUSPECT_IP),
    dict(event_id='graph-qrs-3', _time=time_at(156), user=USER, app_id=APP_SUSPECT,
        token_id=TOKEN, operation='GET /me/messages', resource_id='mailbox-mrivera-msg-003',
        status='200', bytes_returned='2051', source_ip=SUSPECT_IP),
    dict(event_id='graph-qrs-denied', _time=time_at(164), user=USER, app_id=APP_SUSPECT,
        token_id=TOKEN, operation='GET /me/messages', resource_id='mailbox-mrivera-msg-004',
        status='403', bytes_returned='0', source_ip=SUSPECT_IP)])

network = []
for i in range(249):
    ip = NORMAL_IPS[i % len(NORMAL_IPS)]
    network.append(dict(event_id=f'network-{i:04d}', _time=noise_time(),
        source_ip=ip, context='corporate-egress' if ip.startswith('203.') else 'vpn-egress',
        owner='ACME', approved='true', notes='known routing context'))
network.append(dict(event_id='network-suspect', _time=time_at(144), source_ip=SUSPECT_IP,
    context='unclassified-external', owner='unknown', approved='false',
    notes='not found in known VPN/corporate egress list'))

response = []
for i in range(77):
    response.append(dict(event_id=f'response-{i:04d}', _time=noise_time(),
        ticket=f'IR-2026-{4000+i}', actor='ACME\\soc-operator', user=USERS[i % len(USERS)],
        target_id=f'sess-normal-{i:04d}', action='review-session', result='completed',
        reason='routine-identity-triage'))
response.extend([
    dict(event_id='response-qrs-session', _time=time_at(152), ticket='IR-2026-4779',
        actor='ACME\\soc-operator', user=USER, target_id=SESSION,
        action='revoke-interactive-session', result='completed', reason='unexplained-source-and-consent'),
    dict(event_id='response-qrs-consent', _time=time_at(161), ticket='IR-2026-4779',
        actor='ACME\\identity-admin', user=USER, target_id=GRANT,
        action='remove-oauth-consent-and-disable-app', result='completed', reason='unapproved-app-with-mail-access'),
    dict(event_id='response-qrs-token', _time=time_at(162), ticket='IR-2026-4779',
        actor='ACME\\identity-admin', user=USER, target_id=TOKEN,
        action='revoke-user-refresh-tokens', result='completed', reason='contain-delegated-access')])

detections = []
for i in range(149):
    detections.append(dict(event_id=f'detection-{i:04d}', _time=noise_time(),
        detection_id=f'ATD15-N{i:04d}', user=USERS[i % len(USERS)],
        app_id=APP_IDS[i % len(APP_IDS)], grant_id=f'grant-approved-{i:04d}',
        severity='low', analytic='OAuth consent observed', disposition='context-only'))
detections.append(dict(event_id='detection-qrs', _time=time_at(147),
    detection_id='ATD15-001', user=USER, app_id=APP_SUSPECT, grant_id=GRANT,
    severity='high', analytic='New user consent from unfamiliar source', disposition='investigate'))

COUNTS = {
    'app_inventory.csv': rows('app_inventory.csv', ['event_id','_time','app_id','display_name','publisher','approval_state','app_type','risk_tier'], inventory),
    'oauth_grants.csv': rows('oauth_grants.csv', ['event_id','_time','grant_id','user','app_id','consent_type','scopes','result','source_ip','session_id','admin_approved'], grants),
    'identity_signins.csv': rows('identity_signins.csv', ['event_id','_time','user','source_ip','device','managed','result','auth_method','session_id','app'], signins),
    'token_events.csv': rows('token_events.csv', ['event_id','_time','token_id','grant_id','app_id','user','token_type','issuance','result','expires_at'], tokens),
    'graph_activity.csv': rows('graph_activity.csv', ['event_id','_time','user','app_id','token_id','operation','resource_id','status','bytes_returned','source_ip'], graph),
    'network_context.csv': rows('network_context.csv', ['event_id','_time','source_ip','context','owner','approved','notes'], network),
    'response_actions.csv': rows('response_actions.csv', ['event_id','_time','ticket','actor','user','target_id','action','result','reason'], response),
    'detection_results.csv': rows('detection_results.csv', ['event_id','_time','detection_id','user','app_id','grant_id','severity','analytic','disposition'], detections)
}

# The Splunk app is usable immediately: ship the exact same portable lookup CSVs.
LOOKUPS = ROOT / 'splunk' / 'after_detection_hunt_015' / 'lookups'
LOOKUPS.mkdir(parents=True, exist_ok=True)
for filename in COUNTS:
    (LOOKUPS / filename).write_bytes((DATA / filename).read_bytes())
print('Hunt 015 generated:', COUNTS, 'total', sum(COUNTS.values()))
