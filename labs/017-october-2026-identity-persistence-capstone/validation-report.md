# Validation report — Hunt 017

**Generator:** `generate_lab.py` · **Validator:** `validate_lab.py` · **Seed:** `20261026` · **Runtime:** Python 3.11+ standard library.

**Local execution:** PASS on 2026-10-25. Generated **110,000 rows across eleven platform-portable CSV lookups**, 10,000 rows in every lookup. Checks passed: row counts, unique event IDs per file, session/source/device/grant/token/rule joins, target timestamps, modeled post-revocation resource activity, two distinct delivered external messages, approved forwarding look-alike, response actions, byte-identical Splunk app lookup copies, and deterministic rebuild hashes.

| Lookup | Rows |
|---|---:|
| identity_signins.csv | 10,000 |
| device_inventory.csv | 10,000 |
| network_context.csv | 10,000 |
| oauth_grants.csv | 10,000 |
| token_events.csv | 10,000 |
| graph_activity.csv | 10,000 |
| mailbox_rules.csv | 10,000 |
| mailbox_audit.csv | 10,000 |
| message_trace.csv | 10,000 |
| responder_actions.csv | 10,000 |
| detection_results.csv | 10,000 |
| **Total** | **110,000** |

For independent reproduction: run `python3 generate_lab.py && python3 validate_lab.py` from the lab directory. The publishing PR also runs the validator in GitHub Actions; final status should be checked before merge.
