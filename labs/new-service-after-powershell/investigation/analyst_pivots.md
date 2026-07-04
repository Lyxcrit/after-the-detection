# Analyst Pivots

This lab is designed to show how a detection can guide the analyst toward the next useful question.

## First pivots

1. Review the PowerShell command line and script block text.
2. Identify the parent process that launched PowerShell.
3. Check whether PowerShell created or modified files.
4. Review service creation details.
5. Validate the service binary path.
6. Check whether the service started.
7. Review network activity after service execution.
8. Check asset ownership and change history.

## Questions to answer

- Did the user normally run PowerShell on this host?
- Was the encoded or bypass behavior expected?
- Was the new service tied to a known software install?
- Is `C:\Users\Public\Libraries\Cache` an expected service binary path?
- Did the service binary appear shortly before service creation?
- Did the host contact a new or unusual destination after the service started?
- Is there an approved change record?
- Who owns the host or application?

## Evidence that supports escalation

- Suspicious PowerShell flags
- Script block download behavior
- Service binary in user-writable path
- Auto-start service
- Service execution as SYSTEM
- First-seen external destination
- No approved change or system owner validation

## Evidence that may reduce severity

- Approved change window
- Known software deployment
- Known administrator action
- Expected service name and path
- No related outbound activity
- No suspicious child processes

## After the Detection note

The detection should not stop at `service created`.

It should help the analyst answer:

> What happened before this service was created, what happened after, and what context would make this benign or worth escalating?
