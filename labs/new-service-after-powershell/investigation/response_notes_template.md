# Response Notes Template

Use this as a simple analyst note template for the lab.

## Alert summary

- Alert name:
- Host:
- User:
- First observed:
- Detection source:
- Severity:

## What happened

Summarize the observed activity in plain language.

Example:

> Suspicious PowerShell activity on `WKSTN-042` was followed by the creation and execution of a new Windows service named `WinUpdateSvc`. The service binary was located in a user-writable path and made outbound connections after execution.

## Key evidence

- Suspicious PowerShell command line:
- Script block evidence:
- Service name:
- Service binary path:
- Account context:
- Network activity:
- Related detections or findings:

## Analyst pivots completed

- [ ] Reviewed process lineage
- [ ] Reviewed PowerShell script block activity
- [ ] Reviewed service creation details
- [ ] Validated service binary path
- [ ] Checked outbound network activity
- [ ] Checked host ownership
- [ ] Checked change history
- [ ] Contacted owner or admin team, if needed

## Assessment

- Is the behavior expected?
- Is there an approved change?
- Is the service path normal?
- Is outbound activity expected?
- Is there evidence of persistence?
- Is escalation required?

## Decision

- [ ] Close as expected activity
- [ ] Monitor for related activity
- [ ] Escalate for containment or deeper review
- [ ] Contact system owner
- [ ] Create or update incident case

## Notes

Add supporting notes here.
