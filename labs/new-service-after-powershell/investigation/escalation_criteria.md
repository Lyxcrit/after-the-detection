# Escalation Criteria

This lab is intentionally ambiguous at first. A new service can be legitimate. PowerShell can be legitimate. The escalation decision should come from the combination of evidence.

## Escalate when

Escalation is more justified when one or more of the following are true:

- suspicious PowerShell command line is present
- encoded or bypass behavior is not expected
- service binary is in a user-writable path
- service is configured to auto-start
- service runs as `LocalSystem`
- outbound network activity appears after service start
- destination is first-seen or otherwise suspicious
- no approved change exists
- system owner cannot validate activity
- similar behavior appears on other hosts

## Monitor or tune when

Severity may be reduced when one or more of the following are true:

- activity matches approved software deployment
- service name and path are expected
- known administrator performed the action
- change record exists
- no related outbound activity exists
- no related process or authentication anomalies exist

## After the Detection principle

The detection should not make the escalation decision by itself.

It should provide enough context for the analyst to make a better decision faster.
