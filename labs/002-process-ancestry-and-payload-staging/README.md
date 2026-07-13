# Hunt 002: Process Ancestry and Payload Staging

Hunt 002 is a guided After the Detection weekly hunt in the July edge-exploitation arc.

**Difficulty:** Guided, moderate noise  
**Expected time:** 10–15 minutes  
**Primary host:** `WEB-EDGE-01`

The weekly hunts are the reps. The monthly capstone is the field exercise.

This hunt narrows the broader edge-exploitation scenario to one investigation skill: proving how suspicious execution moved from a public web workload into a command shell, PowerShell, a download utility, and a staged payload.

The data also includes legitimate PowerShell, expected file writes, approved software deployment, scheduled maintenance, peer-server activity, backup access, monitoring collection, vulnerability scanning, and web-request noise. The objective is not to label every script interpreter as malicious. The objective is to use ancestry, user context, host role, timing, file activity, and network activity to explain which chain belongs to the incident.

All telemetry is synthetic and platform-portable.

## Learning objectives

By the end of the hunt, an analyst should be able to:

- trace a suspicious process backward to the originating application context;
- follow the descendants forward into payload staging;
- correlate process IDs with file and network events;
- distinguish malicious PowerShell from legitimate administration and deployment;
- state which evidence supports escalation;
- identify evidence gaps without replacing them with assumptions.

## Starting signal

Begin with `detection_results.csv`.

The initial high-severity detection is:

> Suspicious Script Interpreter from Web Application on `WEB-EDGE-01`

## Package contents

- `threat-brief.md`
- `attack-narrative.md`
- `coverage-map.md`
- `data-dictionary.md`
- `splunk-ingest-guide.md`
- `sample-spl.md`
- `analyst-hunt-guide.md`
- `response-plan.md`
- `apt-falconer-showcase.md`
- `falconsearch-notes.md`
- `linkedin-content.md`
- `root-readme-snippet.md`
- `validate_lab.py`
- `data/*.csv`

## Moderate-noise design

LinkedIn feedback favored **guided, moderate noise**, so Hunt 002 includes enough look-alike activity to require judgment without turning the exercise into a full capstone. The added noise includes:

- routine health checks and commodity web scanning;
- a likely triggering request hidden among normal web access;
- service-context PowerShell used for monitoring and app-pool maintenance;
- a deployment workflow that legitimately launches `cmd.exe`;
- backup activity touching the same edge server over SMB;
- a peer web server with similar but benign maintenance activity;
- vulnerability-scanner traffic;
- multiple medium-severity review detections that should not all be escalated.

The expected analyst behavior is to separate the malicious IIS-descended chain from similar-but-benign activity using ancestry, identity, host role, timing, file writes, and network context.

## Quick start

1. Read `attack-narrative.md`.
2. Load the CSVs or review them directly.
3. Start with the high-severity detection in `detection_results.csv`.
4. Trace the process ancestry in `endpoint_process.csv`.
5. Correlate process IDs to `endpoint_file.csv` and `network_activity.csv`.
6. Use `analyst-hunt-guide.md` to record your conclusion.
7. Compare your result with the expected findings in `response-plan.md`.

## Platform positioning

The CSV data can be used with Splunk, Elastic, Sentinel, Datadog, Security Onion, DuckDB, pandas, or direct spreadsheet review.

Splunk examples are included as a practical demonstration. APT Falconer and FalconSearch are showcase layers, not requirements.
