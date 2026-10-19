# Analyst hunt guide

**Start:** `ATD16-001` in `detection_results.csv`. Do not start from the answer key.

1. Resolve the alert's `user`, `session_id`, and `rule_id`. Confirm the event time and whether the sign-in succeeded.
2. Compare `ACME\jortiz` at 13:04 with 13:19: device, management status, source IP, MFA result, and available network context. Note what MFA success does *not* prove.
3. Correlate `mailbox_audit.csv` with `mailbox_rules.csv` using `rule_id`; determine who/what created the rule, the session/source, destination, condition, enabled state, and change approval.
4. Use `message_trace.csv` to separate inbox delivery from actual forwarding. Track `message_id` and `destination`; do not count one message twice as two forwarded messages.
5. Overlay `responder_actions.csv`. Did the 13:31 session revocation change mailbox configuration? What happened at 13:36? Which action happened at 13:44?
6. Compare benign rules with approved partner forwarding and internal archiving. Explain why the target chain warrants higher confidence than the look-alikes.
7. Scope other mailbox rules for the user, other accounts with the same destination, other sessions, and any additional mail-flow paths. The provided dataset cannot rule out unlogged mechanisms.
8. Write a concise response decision with confidence, observed impact, evidence gaps, and verification steps.

**Challenge:** Build one time-sorted table from sign-ins, rule audit, message trace, and responder activity. Avoid using ingestion order as event time.
