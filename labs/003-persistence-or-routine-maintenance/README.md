# Hunt 003: Persistence or Routine Maintenance?

Hunt 003 is a guided After the Detection weekly hunt in the July edge-exploitation arc.

**Difficulty:** Guided, moderate noise  
**Expected time:** 15–20 minutes  
**Primary host:** `WEB-EDGE-01`

The weekly hunts are the reps. The monthly capstone is the field exercise.

This hunt focuses on a common investigation mistake: treating a persistence-shaped event as confirmed persistence before the surrounding relationships support that conclusion.

The analyst starts with a service-creation detection on `WEB-EDGE-01` and must determine whether it belongs to the malicious chain or routine operating activity.

## Learning objectives

By the end of the hunt, an analyst should be able to:

- trace service creation back to the creating process and user context;
- determine whether the service image path points to a staged payload;
- correlate service creation with earlier process, file, web, and network evidence;
- distinguish malicious persistence from approved deployment, maintenance, backup, scanner, and admin-response activity;
- decide which detections should be escalated, treated as context, or scoped further;
- document evidence gaps without overstating the finding.

## Starting signal

Begin with `detection_results.csv`.

The most important detection is:

> New Auto-Start Service from Staged Path on `WEB-EDGE-01`

Do not review this service in isolation. Build the timeline around it.

## Moderate-noise design

LinkedIn feedback favored **guided, moderate noise**, so Hunt 003 includes look-alikes that require judgment without turning the exercise into a full monthly capstone.

Noise includes:

- routine health checks and commodity web scanning;
- a likely triggering diagnostics request hidden among web traffic;
- service-context PowerShell used for approved deployment;
- a deployment workflow that legitimately launches `cmd.exe`;
- scheduled log rotation and backup activity on the same edge server;
- similar peer-server maintenance on `WEB-EDGE-02`;
- authorized vulnerability-scanner traffic;
- admin triage activity after the suspicious service appears;
- multiple low/medium detections that should not all become escalations.

## Quick start

1. Read `attack-narrative.md`.
2. Load the CSVs as lookups or install the bundled Splunk lab app.
3. Start with `detection_results.csv`.
4. Review `endpoint_service.csv` for service creation.
5. Pivot backward into `endpoint_process.csv` and `endpoint_file.csv`.
6. Pivot outward into `network_activity.csv` and `web_access.csv`.
7. Use `identity_auth.csv`, `scheduled_task.csv`, and peer-host data to separate malicious activity from noise.
8. Compare your decision with `response-plan.md`.

## Platform positioning

The CSV data can be used with Splunk, Elastic, Sentinel, Datadog, Security Onion, DuckDB, pandas, or direct spreadsheet review.

Splunk examples are included because they make the workflow easy to demonstrate. APT Falconer and FalconSearch are showcase layers, not requirements.
