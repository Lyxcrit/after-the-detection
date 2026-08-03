from pathlib import Path
import csv

root = Path(__file__).resolve().parent
expected = {
    'asset_inventory.csv', 'endpoint_process.csv', 'endpoint_file.csv', 'endpoint_service.csv',
    'scheduled_task.csv', 'identity_auth.csv', 'dns.csv', 'network_activity.csv',
    'web_access.csv', 'detection_results.csv', 'investigation_findings.csv', 'response_activity.csv',
}
for name in sorted(expected):
    with (root / 'data' / name).open(newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 1500, (name, len(rows))
with (root / 'data/detection_results.csv').open(encoding='utf-8') as handle:
    assert any(row['detection_id'] == 'ATD-005-001' for row in csv.DictReader(handle))
print('PASS: 12 lookups, 1,500 rows each, 18,000 total records')
