# Hunt 015 — Session Revoked, App Still Reading

**Cycle:** October 12 / 14 / 16, 2026 · **Difficulty:** guided/intermediate · **Time:** 40–60 minutes · **Focus:** delegated OAuth consent and access-token lifetime after interactive-session revocation.

At 09:24 UTC on October 9, `ACME\mrivera` successfully signs in to Microsoft 365 from `198.51.100.146`, an unclassified external source, using an unmanaged Windows device. At 09:26, the account grants `Mail.Read offline_access` to an unapproved app named **Quarterly Reports Sync** (`app-qrs-779`). A token is issued at 09:28 and Microsoft Graph mailbox reads follow. At 09:32, the SOC revokes the interactive session; at **09:36**, the app still records a successful Graph mail read with the same access token. The app consent is removed and the app disabled at 09:41, refresh tokens are revoked at 09:42, and a 09:44 request is denied.

**Core question:** What did revoking the interactive session actually contain, and what evidence supports or limits a claim that application access ended?

This is **synthetic training data**, not evidence from a customer incident. Identity-provider and resource behavior is simplified for the exercise; real revocation and Continuous Access Evaluation behavior varies by token, application, resource, and policy.

## Quick start

1. Open `data/detection_results.csv`; filter `detection_id=ATD15-001`.
2. Follow `grant_id=grant-qrs-779` into `oauth_grants.csv` and `app_id=app-qrs-779` into `app_inventory.csv`.
3. Reconstruct the `ACME\mrivera` sign-in history, source context, consent, token issuance, Graph requests, and responder actions.
4. Use `token_id=tok-qrs-779-1` to link Graph reads to an issued access token. Compare **event time** against the **09:32** session revocation, not ingestion order.
5. Decide what you would revoke next, whether the app should be disabled, and what you still cannot conclude.
6. Write your decision before reading `answer-key.json`.

## Data and portability

Eight platform-portable CSVs in `data/` contain **3,100 synthetic records**. The generator uses Python standard library, seed `20261012`, fixed UTC timestamps, stable event IDs, and explicit join keys. Run `python3 generate_lab.py` then `python3 validate_lab.py`. The validator checks cross-lookup relationships, key chronology, byte-for-byte determinism, and identical copies in the Splunk app.

| Lookup | Records | Pivot |
|---|---:|---|
| `detection_results.csv` | 150 | detection → grant/app |
| `identity_signins.csv` | 650 | user/session/source/device |
| `oauth_grants.csv` | 350 | consent → grant/app/scopes |
| `token_events.csv` | 600 | token → grant/app/user |
| `graph_activity.csv` | 900 | token → resource/status/time |
| `app_inventory.csv` | 120 | app approval/publisher |
| `network_context.csv` | 250 | source → approved egress context |
| `response_actions.csv` | 80 | ticket → containment action/time |

Noise includes approved business connectors, normal user consent, administrator-approved consent, managed-device sign-ins, normal calendar and profile reads, and routine SOC review actions. The primary chain has its own durable IDs and is intentionally distinguishable only after cross-lookup correlation.

## Investigation materials

- [Attack narrative](attack-narrative.md)
- [Analyst hunt guide](analyst-hunt-guide.md)
- [Investigation worksheet](investigation-worksheet.md)
- [Data dictionary](data-dictionary.md)
- [Sample SPL](sample-spl.md)
- [Response plan](response-plan.md)
- [Answer key](answer-key.json) — spoilers
- [Validation report](validation-report.md)
- [Installable Splunk lab app](splunk/after_detection_hunt_015/README.md)

**ATT&CK context:** T1528 (Steal Application Access Token) and T1098.003 (Additional Cloud Roles) are *investigative hypotheses*, not established behaviors in this synthetic evidence. The lab directly models an OAuth consent grant and subsequent resource use; it does not prove token theft or role escalation.
