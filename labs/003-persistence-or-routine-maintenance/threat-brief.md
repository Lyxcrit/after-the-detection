# Threat Brief

Persistence detections are valuable, but they can be easy to overstate.

A newly created service, scheduled task, or autorun entry can represent attacker persistence. It can also represent approved deployment, monitoring, backup, repair, or software maintenance.

This hunt models the gap between a persistence-shaped event and a confirmed persistence finding.

The analyst must decide whether `WindowsCacheSync` on `WEB-EDGE-01` is malicious by tying the service event to:

- the suspicious web request;
- IIS-descended command and PowerShell execution;
- payload staging under `C:\ProgramData\WinCache`;
- service creation and start events;
- outbound callback activity;
- legitimate look-alikes in the same window.
