# Hunt 005: The Work Is in the Pivots

**Difficulty:** Guided, moderate noise  
**Expected time:** 25–40 minutes  
**Primary host:** `ADMIN-WS-07`  
**Starting signal:** `ATD-005-001 — PowerShell Download from Legitimate Domain`

PowerShell downloads an administrative utility from a legitimate domain. That event is worth reviewing, but it does not establish malicious intent.

The analyst has to follow the process tree, resulting artifacts, credential access, persistence, outbound activity, and a failed WinRM attempt toward a second host. Approved deployments, routine maintenance, backup activity, scanning, and responder actions are mixed into the same data.

## Quick start

1. Read `attack-narrative.md`.
2. Start with `detection_results.csv`.
3. Trace `ATD-005-001` into `endpoint_process.csv`.
4. Correlate process IDs with file, DNS, network, task, and service events.
5. Separate approved deployment and maintenance from the incident.
6. Record conclusions in `investigation-worksheet.md`.
7. Compare with `response-plan.md` and `answer-key.json`.

## Data

Twelve platform-portable CSV lookups contain 1,500 records each, for 18,000 total records. All telemetry is synthetic.
