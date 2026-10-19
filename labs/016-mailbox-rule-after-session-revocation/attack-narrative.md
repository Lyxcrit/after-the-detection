# Attack narrative — Hunt 016

Synthetic timestamps use UTC on October 16, 2026.

| Time | Evidence | Interpretation boundary |
|---|---|---|
| 13:04 | `ACME\jortiz`, managed `FIN-WS-22`, known egress | Normal comparator, not a claim that the account is safe |
| 13:19 | Successful sign-in from `198.51.100.74`, `UNKNOWN-WIN`, unmanaged, MFA satisfied | Unexplained authentication context; no proof of credential or MFA theft |
| 13:22 | `New-InboxRule` for `rule-jo-invoices-77` from the new session | Audit ties rule creation to session/source; actor attribution is an account, not a person |
| 13:25 / 13:28 | Invoice messages forwarded to `invoice-review@outside.example`, `delivered` | Delivery observed; recipient read/retention unknown |
| 13:31 | SOC revokes `sess-jo-new-01` | Session response completed; mailbox rule state not changed by this action |
| 13:36 | Another invoice message forwarded to external destination | Strong evidence of continued forwarding after session revocation |
| 13:44 | Admin disables the rule, state snapshot `enabled=false` | Rule-specific containment; verify propagation and other rules |
| 13:49 / 13:56 | Invoice messages delivered to mailbox; no modeled external forward | Supports changed behavior in supplied telemetry, not universal absence |
| 13:50 | Password reset completed | Does not establish the initial access mechanism |

**Benign comparators:** `rule-ben-*` entries include internal operations archiving, routine moves, and approved partner forwarding with `CHG-*` references. Treat an external address as a reason to inspect provenance, not automatic proof of malicious behavior.
