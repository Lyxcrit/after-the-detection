# Sample SPL — Splunk is optional

Install the app or place CSVs in a lookup directory. Queries use `inputlookup` and work without ingesting raw events. `inputlookup` operates on lookup rows, so the `timestamp` field is used for ordering.

## Identity provenance

```spl
| inputlookup identity_signins.csv
| search user="ACME\\knguyen"
| eval event_epoch=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| sort 0 event_epoch
| table timestamp event_id user session_id source_ip device_id auth_result mfa_result
```

## Resolve source and device context

```spl
| inputlookup identity_signins.csv
| search session_id="sess-kn-new-017"
| lookup network_context.csv source_ip OUTPUT source_type approved_egress geo
| lookup device_inventory.csv device_id OUTPUT managed trust hostname
| table timestamp user source_ip source_type approved_egress device_id managed trust auth_result mfa_result
```

`network_context` and `device_inventory` contain repeated snapshots, so a production search should first deduplicate or select the appropriate as-of-time record. This lab's primary source/device classification is stable.

## OAuth grant → token → resource access

```spl
| inputlookup graph_activity.csv
| search app_id="app-qrs-779" user="ACME\\knguyen"
| lookup token_events.csv token_id OUTPUT grant_id session_id expires_at
| eval event_epoch=strptime(timestamp,"%Y-%m-%dT%H:%M:%SZ")
| sort 0 event_epoch
| table timestamp token_id grant_id session_id operation result bytes_returned
```

## Mailbox rule audit and delivered external forwards

```spl
| inputlookup mailbox_audit.csv
| search rule_id="rule-kn-invoices-017"
| sort 0 timestamp
| table timestamp operation user actor session_id source_ip change_ticket
```

```spl
| inputlookup message_trace.csv
| search rule_id="rule-kn-invoices-017" action="forward" result="delivered"
| stats earliest(timestamp) as first_seen latest(timestamp) as last_seen dc(message_id) as distinct_messages values(destination) as destinations by user rule_id
```

## Responder action timeline

```spl
| inputlookup responder_actions.csv
| search ticket="INC-017"
| sort 0 timestamp
| table timestamp action entity_type entity_id result operator notes
```

## Verify later rule state

```spl
| inputlookup mailbox_rules.csv
| search rule_id="rule-kn-invoices-017"
| sort 0 timestamp
| table timestamp snapshot enabled forward_to approved_change
```

In a real deployment, normalize vendor-specific event schemas and deduplicate snapshot lookups. Don't assume a `join` on a repeated inventory field has one-to-one cardinality.
