# Hunt 015 validation report

- Generator seed: `20261012`; timestamp basis: UTC; Python standard library only.
- All eight CSVs parse, have unique event IDs, and match the Splunk app copies.
- Every OAuth grant resolves to a known application and sign-in session.
- Every issued token resolves to its grant, application, and user.
- Every Graph event resolves to its issued token, application, and user.
- Suspicious chain: sign-in → consent → token → mail reads → session revocation → continued successful read → grant removal → token revocation → denied read.
- Source IPs resolve to network context; benign apps have explicit approval context.
- Regeneration is byte-for-byte deterministic.

| Lookup | Records |
|---|---:|
| `app_inventory.csv` | 120 |
| `oauth_grants.csv` | 350 |
| `identity_signins.csv` | 650 |
| `token_events.csv` | 600 |
| `graph_activity.csv` | 900 |
| `network_context.csv` | 250 |
| `response_actions.csv` | 80 |
| `detection_results.csv` | 150 |
| **Total** | **3,100** |

**Overall: PASS**
