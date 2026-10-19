# Response plan — Hunt 016

**Priority:** preserve audit and trace evidence, verify the active mailbox configuration, and stop the unauthorized forwarding path while assessing scope.

1. Confirm the rule ID, mailbox, forwarding address, match condition, enabled state, and creation provenance in authoritative Exchange administration records. Preserve creation/modification audit events and timestamps.
2. Disable or remove the unapproved forwarding rule, following the organization's change and evidence-preservation procedures. Review other inbox rules, mailbox forwarding settings, transport rules, delegates, and application permissions; disabling one rule does not exhaust the paths.
3. Revoke suspicious sessions and evaluate identity recovery (credential reset, MFA review) based on the account's other activity. A password reset alone does not undo mailbox configuration changes.
4. Inspect message trace for distinct forwarded messages, delivery outcomes, recipients, and time window. Coordinate with mail administrators and incident response for impact assessment; don't claim a recipient opened a message without supporting evidence.
5. Validate post-action rule state and collect subsequent traces over an appropriate observation window. The absence of a row in this synthetic dataset isn't proof that no alternate mail path exists.
6. Compare legitimate forwarding rules and approved exceptions before broad tenant-wide removal; unnecessary blanket deletion can break business workflows.

**Evidence limits:** Initial access mechanism, real-world actor identity, external recipient read/retention, and other unobserved forwarding mechanisms remain unknown. This is a synthetic teaching scenario, not a production incident report.
