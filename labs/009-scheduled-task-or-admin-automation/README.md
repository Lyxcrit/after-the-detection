# Hunt 009: Scheduled Task or Admin Automation?

**Difficulty:** Guided, moderate noise  
**Expected time:** 35–50 minutes  
**Starting point:** A new scheduled task appears on `HR-WS-22` under a Microsoft-looking path.

The task name is plausible: `\Microsoft\Windows\Update\TelemetryCheck`.

That is not enough to call it malicious.

The hunt is about deciding whether the task is legitimate administration, a naming collision with enterprise automation, or persistence. The analyst has to compare task metadata, creator, run-as account, command path, process ancestry, file trust, network behavior, and approved change records.

## Quick start

1. Start with `detection_results.csv`.
2. Inspect the task definition in `scheduled_task.csv`.
3. Follow the task into `endpoint_process.csv` and `endpoint_file.csv`.
4. Compare the suspicious task with the approved `\ACME\Patch\TelemetryCheck` task on `PATCH-01`.
5. Check `software_trust.csv` and `change_records.csv` before deciding.
6. State what proves persistence on `HR-WS-22`, and what does **not** prove propagation elsewhere.
7. Choose containment and estate-wide hunting actions.

## Data

Nine platform-portable CSV lookups contain 1,800 records each, for **16,200 total synthetic records**.
