# Attack Narrative

A user-context PowerShell process stages `C:\ProgramData\WinCache\check.ps1` on `HR-WS-22`, then creates `\Microsoft\Windows\Update\TelemetryCheck` to run the script as `SYSTEM`.

The task starts fourteen seconds later. `taskeng.exe` launches hidden PowerShell, which executes `telemetry.dll` through `rundll32.exe`, performs basic system discovery, and opens outbound TLS sessions to `203.0.113.55`.

Nearby activity is intentionally confusing. `PATCH-01` creates a similarly named `\ACME\Patch\TelemetryCheck` task that launches a trusted internal script as `ACME\svc_patch` and reports to `MGMT-01`. `HR-WS-22` also has a known `\ACME\Inventory\Daily` task.

The supplied evidence supports malicious scheduled-task persistence on `HR-WS-22`. It does not prove the suspicious task exists on another host, and the external TLS sessions do not by themselves establish command-and-control content or data theft.
