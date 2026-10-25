# Data dictionary and join map

Every CSV has 10,000 records, `event_id`, and `timestamp` (UTC ISO-8601). Each file contains repeated routine snapshots/events plus purpose-built case events; only explicit event IDs and keys should be treated as incident-linked. No ingestion-time field is modeled.

| CSV | Fields after `event_id,timestamp` | Joins / interpretation |
|---|---|---|
| `identity_signins.csv` | `user,session_id,source_ip,device_id,auth_result,mfa_result,client` | session → token/audit/response; source → network; device → inventory |
| `device_inventory.csv` | `device_id,hostname,managed,trust,owner,role` | device context snapshots, not independent authentication proof |
| `network_context.csv` | `source_ip,source_type,geo,approved_egress,ticket` | IP classification; unclassified ≠ proven malicious |
| `oauth_grants.csv` | `grant_id,app_id,user,scopes,consent_actor,approval,status` | consent grant and approval context; status at event time |
| `token_events.csv` | `token_id,grant_id,app_id,user,session_id,action,result,expires_at` | token issue and modeled expiry; joins grant and Graph requests |
| `graph_activity.csv` | `request_id,token_id,app_id,user,resource,operation,result,bytes_returned` | modeled resource operation; bytes are not content proof |
| `mailbox_rules.csv` | `rule_id,user,subject_match,forward_to,approved_change,enabled,snapshot` | point-in-time rule snapshots, including after-disable |
| `mailbox_audit.csv` | `user,rule_id,session_id,operation,actor,source_ip,result,change_ticket` | change provenance, actor attribution limited to recorded account |
| `message_trace.csv` | `message_id,user,rule_id,destination,action,result,subject_class` | count distinct message IDs with `forward`/`delivered` |
| `responder_actions.csv` | `ticket,user,entity_type,entity_id,action,result,operator,notes` | response chronology; completed action ≠ global containment |
| `detection_results.csv` | `detection_id,user,signal,entity_id,severity,status,evidence` | initial leads; don't substitute for source evidence |

**Key case IDs:** `ACME\knguyen`, `sess-kn-new-017`, `grant-qrs-779`, `app-qrs-779`, `tok-qrs-779-1`, `rule-kn-invoices-017`, `INC-017`. Approved look-alike: `rule-partner-approved`, `CHG-2048`. Reserved documentation source addresses are used intentionally.
