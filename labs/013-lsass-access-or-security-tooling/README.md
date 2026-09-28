# Hunt 013: LSASS Access or Security Tooling?

**Difficulty:** Guided, moderate noise  
**Expected time:** 30–45 minutes  
**Primary host:** `DEV-WS-12`  
**Primary user:** `ACME\jpatel`

A process on `DEV-WS-12` opens LSASS with high access, then `rundll32.exe` invokes `comsvcs.dll` to write `C:\ProgramData\Diag\lsass.dmp`. A few minutes later the dump is archived, and the workstation authenticates to `FILE-DEV-03` as `ACME\jpatel`.

That sequence is suspicious, but the environment also contains legitimate LSASS access from the endpoint security sensor, normal Windows Error Reporting, approved diagnostic collection, routine developer file access, and responder activity.

The analyst must distinguish credential-access behavior from legitimate security/diagnostic tooling, then decide what the later authentication does and does not prove.

## Quick start

1. Start with `detection_results.csv`.
2. Pivot into `process_access.csv` and compare source process, target, access mask, signer, and tool context.
3. Reconstruct the process chain in `endpoint_process.csv`.
4. Confirm whether a dump artifact exists in `file_activity.csv`.
5. Review the later authentication in `identity_auth.csv` and correlate `network_activity.csv`.
6. Use `software_inventory.csv` to validate legitimate security tooling.
7. Separate responder activity before deciding scope.
8. Record conclusions in `investigation-worksheet.md`.

## Data

Eight platform-portable CSV lookups contain **500 records each — 4,000 synthetic records total**. Generation is deterministic with seed `20260928`.

## What the evidence can support

The supplied telemetry supports high confidence that `DEV-WS-12` experienced malicious LSASS dumping and should be contained. It supports reviewing `FILE-DEV-03` because authentication from the compromised workstation follows the dump.

It does **not** prove which credentials were present in LSASS, that `ACME\jpatel` was obtained from the dump, that the later authentication used dumped credentials, or that `FILE-DEV-03` was compromised. Those require additional evidence.

## Sample SPL

See `sample-spl.md` for portable lookup-based pivots.

## Splunk lab app

A lightweight app skeleton is included under `splunk-app/after_the_detection_013/`. Copy it into `$SPLUNK_HOME/etc/apps/` if you want a dedicated app namespace, then place the generated CSVs under its `lookups/` directory.
