# Sample SPL — Hunt 016

All examples use portable CSV lookups. Install the included app or upload the CSVs into Splunk lookup files.

**Start from the detection:**

```spl
| inputlookup detection_results.csv
| search detection_id="ATD16-001"
| table _time detection_id user session_id rule_id reason severity
```

**Compare sign-ins and network context:**

```spl
| inputlookup identity_signins.csv
| search user="ACME\\jortiz"
| lookup network_context.csv source_ip OUTPUT network_class approved_egress owner
| table _time user session_id source_ip device_id managed mfa_result result network_class approved_egress
| sort 0 _time
```

**Rule audit and state snapshots:**

```spl
| inputlookup mailbox_audit.csv
| search rule_id="rule-jo-invoices-77"
| table _time operation actor user session_id source_ip result
| sort 0 _time
```

```spl
| inputlookup mailbox_rules.csv
| search rule_id="rule-jo-invoices-77"
| table _time rule_id enabled rule_action match_subject forward_to approved change_ticket
| sort 0 _time
```

**Distinct forwarded messages and delivery results:**

```spl
| inputlookup message_trace.csv
| search rule_id="rule-jo-invoices-77"
| eval is_external_forward=if(event_type="forward_delivery" AND status="delivered",1,0)
| table _time message_id event_type destination status rule_applied is_external_forward
| sort 0 _time
```

**Response timeline:**

```spl
| inputlookup responder_actions.csv
| search ticket_id="SOC-016-77"
| table _time action result actor session_id rule_id
| sort 0 _time
```

**Approved look-alikes:**

```spl
| inputlookup mailbox_rules.csv
| where rule_action="forward" AND match(forward_to,"@partner\\.example$")
| table _time rule_id user forward_to approved change_ticket
```

**Caution:** A CSV `lookup` with duplicate `rule_id` snapshots is ambiguous. Use `inputlookup` and time-sort or aggregate explicitly; don't use a plain `lookup` to infer latest state.
