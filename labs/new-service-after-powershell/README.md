# Lab: New Service After Suspicious PowerShell

## Summary

This lab models a common investigation pattern:

> Suspicious PowerShell activity is followed by new Windows service creation and a first-seen outbound connection.

The goal is not to prove that every new service is malicious. The goal is to show how an analyst can move from an ambiguous alert to a clearer investigation path using context, timeline, pivots, and supporting evidence.

## Scenario

A user account on `WKSTN-042` launches PowerShell with suspicious command-line behavior. Shortly afterward, a new Windows service named `WinUpdateSvc` is created on the same host. The service binary points to a user-writable directory. The host then makes a DNS request and outbound connection to a first-seen external destination.

Individually, each event may be explainable.

Together, they create an investigation worth reviewing.

## Why this matters

A new service creation event by itself can be legitimate:

- an administrator installed software
- a patching tool created a service
- an application team deployed an update
- normal operations created a temporary service

But a new service created shortly after suspicious PowerShell activity should raise better questions:

- What spawned PowerShell?
- What account executed it?
- What did the command attempt to do?
- What service was created?
- What binary does the service point to?
- Is the path expected?
- Was there related network activity?
- Is there evidence of persistence?

That is the after-the-detection layer.

## ATT&CK mapping

This lab can be discussed through several ATT&CK techniques depending on the final analytic framing:

- Execution: PowerShell
- Persistence: Windows Service
- Defense Evasion: Obfuscated or suspicious command line
- Command and Control: outbound connection to first-seen destination

The exact mapping should depend on your detection logic and telemetry.

## Synthetic telemetry

The lab includes small CSV files for:

- Sysmon process creation
- PowerShell Operational events
- Service Control Manager events
- Windows Security logon/process context
- DNS/proxy activity

These files are intentionally small so the investigation path is easy to follow.

## Detections included

- Suspicious PowerShell command line
- New service creation
- Service creation shortly after suspicious PowerShell

## Investigation flow

1. Suspicious PowerShell executes on `WKSTN-042`.
2. A payload-like file path appears in a user-writable directory.
3. A new service is created pointing to that path.
4. The host makes a DNS query to a first-seen domain.
5. The analyst reviews process lineage, service details, account context, and outbound activity.

## Analyst question

The alert should not simply say:

> New service created.

It should help answer:

> What happened before the service was created, what changed after, and what should I validate next?

## Synthetic data note

This lab uses synthetic telemetry. It is not customer data, victim data, production data, or evidence from a real incident.
