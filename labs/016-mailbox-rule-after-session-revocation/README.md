# Hunt 016 — The Session Was Revoked. The Mail Rule Stayed.

**Cycle:** October 19 / 21 / 23, 2026 · **Difficulty:** intermediate · **Time:** 40–60 minutes · **Focus:** Exchange inbox-rule persistence and external forwarding after interactive-session containment.

At 13:04 UTC on October 16, `ACME\jortiz` signs in from managed workstation `FIN-WS-22`. At 13:19, the same user successfully signs in from `198.51.100.74` using `UNKNOWN-WIN` (unmanaged; MFA recorded as satisfied). At 13:22, a `New-InboxRule` audit event creates `rule-jo-invoices-77`, forwarding matching invoice messages to `invoice-review@outside.example` without an approved change ticket. The message trace shows external forward deliveries at 13:25 and 13:28. The SOC revokes the anomalous interactive session at 13:31, but another forward delivery succeeds at **13:36**. An administrator disables the rule at 13:44; subsequent modeled invoice messages are delivered to the mailbox without a recorded external forward.

**Investigation question:** What did revoking the session contain, what mailbox configuration remained, and what evidence supports a decision that forwarding stopped?

All identities, IPs, domains, tickets, and events are synthetic. The lab models Exchange audit, rule-state, and message-trace concepts; it does not claim that any specific cloud provider will exhibit identical propagation or enforcement behavior.

## Quick start

1. Start with `data/detection_results.csv`, filter `detection_id=ATD16-001`.
2. Resolve `session_id=sess-jo-new-01` in `identity_signins.csv`, then source IP context in `network_context.csv`.
3. Find `rule_id=rule-jo-invoices-77` in `mailbox_audit.csv` and `mailbox_rules.csv`; inspect actor, source, destination, state, and approval.
4. Use `message_trace.csv` to link `message_id`, `rule_id`, mailbox, destination, status, and event time.
5. Overlay `responder_actions.csv`. Compare the 13:31 session action, 13:36 external forward, and 13:44 rule disable.
6. Check approved external partner forwarding and internal automation as look-alikes. Record what the evidence proves and what remains unverified before reading the answer key.

## Data and portability

Eight platform-portable CSV lookups contain **2,950 synthetic records**. `generate_lab.py` uses fixed UTC times and deterministic index-based generation; `validate_lab.py` checks row counts, unique event IDs, cross-lookup joins, modeled chronology, Splunk copies, and byte-for-byte regeneration. Run `python3 generate_lab.py && python3 validate_lab.py` from this folder.

| Lookup | Rows | Primary pivot |
|---|---:|---|
| `identity_signins.csv` | 600 | user / session / source / device |
| `network_context.csv` | 250 | source IP / approved egress |
| `mailbox_inventory.csv` | 150 | user / mailbox / exception |
| `mailbox_rules.csv` | 320 | rule / destination / state / change ticket |
| `mailbox_audit.csv` | 450 | rule / operation / actor / session |
| `message_trace.csv` | 900 | message / rule / delivery destination |
| `responder_actions.csv` | 100 | ticket / action / time |
| `detection_results.csv` | 180 | alert / rule / user |
| **Total** | **2,950** | |

Noise includes approved internal rules, authorized partner forwarding, managed-device sign-ins, routine rule edits, message deliveries, and benign SOC reviews. Look-alikes are deliberately represented in the same lookup schemas as the target chain.

## Lab materials

- [Attack narrative](attack-narrative.md)
- [Analyst hunt guide](analyst-hunt-guide.md)
- [Investigation worksheet](investigation-worksheet.md)
- [Data dictionary](data-dictionary.md)
- [Sample SPL](sample-spl.md)
- [Response plan](response-plan.md)
- [Answer key](answer-key.json) — spoilers
- [Validation report](validation-report.md)
- [Lightweight installable Splunk app](splunk/after_detection_hunt_016/README.md)

**Evidence boundary:** A `delivered` forwarding trace supports delivery to the modeled external destination, not that a person read the content. The later absence of a forwarding row is supportive in this bounded dataset, not conclusive proof that no additional forwarding path exists. The original sign-in does not establish password theft, MFA bypass, or the identity of the operator.
