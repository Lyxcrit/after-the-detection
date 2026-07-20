# Analyst Hunt Guide

## Starting point

Begin with the service-creation detection:

`ATD-003-002 — New Auto-Start Service from Staged Path`

Do not decide from the service name alone.

## Checkpoint 1 — Identify the persistence candidate

Use `endpoint_service.csv`.

Record service name, image path, start type, action, source process, source process ID, user, and signature status.

## Checkpoint 2 — Trace the creating process

Use `endpoint_process.csv`.

Questions:

- What process created the service?
- What launched that process?
- Is the chain tied to IIS, deployment, admin activity, or scheduled maintenance?
- Which user context owns the chain?

## Checkpoint 3 — Determine whether the service points to a staged payload

Use `endpoint_file.csv`.

Questions:

- Was the service binary created earlier in the timeline?
- Which process wrote it?
- Is the file signed?
- Is the path expected for approved software?
- Does the hash appear on peer hosts?

## Checkpoint 4 — Review external and internal network context

Use `network_activity.csv`.

Questions:

- Did the staged binary or service-launched process call out?
- Is the destination tied to the earlier staging activity?
- Which network events are routine backup, monitoring, or deployment?

## Checkpoint 5 — Validate web and identity context

Use `web_access.csv` and `identity_auth.csv`.

Questions:

- Which web request likely preceded the suspicious process chain?
- Which authentication events are approved?
- Which authentication events require scoping?
- Does any evidence prove lateral movement, or only attempted access?

## Checkpoint 6 — Separate signal from moderate noise

Document why the following are not the same as the suspicious service:

- `CompanyMonitoringAgent` on `APP-API-02`;
- `WebLogRotation` scheduled task;
- backup activity from `BACKUP-01`;
- authorized scanner traffic from `VULN-SCAN-01`;
- admin triage by `WEBLAB\\admin.jlee`.

## Final analyst response

Provide a one-paragraph incident summary, suspicious service details, process lineage, staged payload path/hash/signature, network behavior after service start, benign look-alikes, recommended response, and evidence gaps.
