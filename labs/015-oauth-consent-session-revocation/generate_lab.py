#!/usr/bin/env python3
import csv,json,random
from pathlib import Path
from datetime import datetime,timedelta,timezone
R=Path(__file__).resolve().parent
rng=random.Random(20261012)
start=datetime(2026,10,9,7,tzinfo=timezone.utc)
def stamp(n):return (start+timedelta(minutes=n)).strftime('%Y-%m-%dT%H:%M:%SZ')
for spec in sorted((R/'schemas').glob('*.json')):
 cfg=json.loads(spec.read_text())
 fields=cfg['fields']; out=[]
 for i in range(500):
  r={k:str(v).replace('{i}',str(i)) for k,v in cfg['noise'].items()}
  r.update(event_id='noise-'+str(i),_time=stamp(rng.randrange(480)))
  out.append(r)
 for e in cfg['overrides']:
  row=dict(e['data']);row.update(event_id=e['id'],_time=stamp(e['minute']))
  out[e['index']]=row
 for folder in [R/'data',R/'splunk'/'after_detection_hunt_015'/'lookups']:
  folder.mkdir(parents=True,exist_ok=True)
  with (folder/cfg['name']).open('w',newline='',encoding='utf8') as f:
   w=csv.DictWriter(f,fieldnames=['_time','event_id']+fields)
   w.writeheader();w.writerows(sorted(out,key=lambda x:(x['_time'],x['event_id'])))
print('Generated 8 synthetic lookups')
