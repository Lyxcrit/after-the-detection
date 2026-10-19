# Data dictionary and join map

Every CSV uses `event_id` (globally unique in this lab) and `_time` (UTC ISO 8601). Identifiers and addresses are synthetic; documentation-reserved IP blocks are used.

| Lookup | Fields beyond `event_id`, `_time` | Join and meaning |
|---|---|---|
| `identity_signins.csv` | `user,session_id,source_ip,device_id,managed,mfa_result,result` | `session_id` joins rule audit, rule state, alerts, and responses; `source_ip` joins network context |
| `network_context.csv` | `source_ip,network_class,owner,approved_egress,notes` | IP classification, not a reputation verdict |
| `mailbox_inventory.csv` | `user,mailbox_id,department,external_forward_exception` | Mailbox ownership and approved exception context |
| `mailbox_rules.csv` | `rule_id,user,mailbox_id,session_id,source_ip,rule_action,match_subject,forward_to,enabled,approved,change_ticket` | Rule-state snapshots; target rule appears twice (enabled and disabled) |
| `mailbox_audit.csv` | `operation,rule_id,user,session_id,source_ip,actor,result` | Creation, modification, disable; audit actor is account identity |
| `message_trace.csv` | `message_id,rule_id,user,mailbox_id,event_type,destination,status,rule_applied,subject_tag` | Message delivery vs forwarding; a message may have multiple trace events |
| `responder_actions.csv` | `ticket_id,user,session_id,rule_id,action,result,actor` | SOC containment, timestamp and ticket |
| `detection_results.csv` | `detection_id,user,session_id,rule_id,reason,severity,status` | Analyst starting point |

**Cardinality:** `rule_id` is a rule identity, not a unique row key in `mailbox_rules.csv`, because state changes create snapshots. `message_id` can have multiple delivery events. Never assume one-to-one joins between audit, rule state, and trace rows. `event_id` is the unique record key.
