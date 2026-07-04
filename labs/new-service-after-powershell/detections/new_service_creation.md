# Detection Idea: New Windows Service Creation

## Goal

Identify new Windows service creation events that may indicate persistence or unauthorized software installation.

## Behavior modeled

The lab includes a Windows Service Control Manager event where a service named `WinUpdateSvc` is created and points to:

```text
C:\Users\Public\Libraries\Cache\winupdate.exe
```

## Why it matters

A new service is not automatically malicious.

It could be:

- administrative activity
- software installation
- patching activity
- application deployment
- expected operational change

The investigation becomes more interesting when the service:

- points to a user-writable path
- is created by a non-admin workflow or unexpected account
- appears shortly after suspicious scripting activity
- starts automatically
- launches an unusual binary
- is followed by outbound network activity

## Analyst context to include

- service name
- service binary path
- account that created the service
- host
- start type
- service account
- related process lineage
- related PowerShell activity
- owner or change context

## Escalation guidance

Escalation becomes more justified when the service path is suspicious, the activity lacks an approved change, or the service creation follows suspicious process execution.
