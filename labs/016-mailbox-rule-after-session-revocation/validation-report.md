# Hunt 016 validation report

Run locally: `python3 generate_lab.py && python3 validate_lab.py`.

Verified locally 2026-10-19: **PASS**, 2,950 records, eight CSV lookups, deterministic regeneration and mirrored Splunk lookups.

| Lookup | Rows |
| --- | ---: |
| identity_signins.csv | 600 |
| network_context.csv | 250 |
| mailbox_inventory.csv | 150 |
| mailbox_rules.csv | 320 |
| mailbox_audit.csv | 450 |
| message_trace.csv | 900 |
| responder_actions.csv | 100 |
| detection_results.csv | 180 |

Cross-lookup joins, chronology, unique event IDs and representative forwarding behavior validated. The repository generator/validator remain the authoritative checks.
