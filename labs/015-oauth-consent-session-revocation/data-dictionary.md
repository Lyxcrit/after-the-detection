# Data dictionary

All CSVs use UTC ISO-8601 timestamps in `_time` and a unique `event_id` per lookup. Values are synthetic; public documentation ranges are used for IPv4 examples. Identifiers are stable across regeneration.

| Lookup | Join keys | Important fields |
|---|---|---|
| `detection_results.csv` | `grant_id`, `app_id`, `user` | `detection_id`, `analytic`, `severity`, `disposition` |
| `identity_signins.csv` | `session_id`, `user`, `source_ip` | `device`, `managed`, `result`, `auth_method` |
| `oauth_grants.csv` | `grant_id`, `app_id`, `session_id`, `user` | `consent_type`, `scopes`, `admin_approved`, `result` |
| `token_events.csv` | `token_id`, `grant_id`, `app_id`, `user` | `token_type`, `issuance`, `expires_at`, `result` |
| `graph_activity.csv` | `token_id`, `app_id`, `user` | `operation`, `resource_id`, `status`, `bytes_returned`, `source_ip` |
| `app_inventory.csv` | `app_id` | `display_name`, `publisher`, `approval_state`, `app_type`, `risk_tier` |
| `network_context.csv` | `source_ip` | `context`, `owner`, `approved`, `notes` |
| `response_actions.csv` | `ticket`, `target_id`, `user` | `actor`, `action`, `result`, `reason` |

**Key interpretation:** `status=200` means the modeled Graph request succeeded, not that messages were exported externally. `status=403` means a modeled denial, not proof of which control enforced it. `auth_method=MFA` records an authentication result and does not establish the person controlling the session. `admin_approved=false` means no administrative approval is recorded for the grant in this dataset.
