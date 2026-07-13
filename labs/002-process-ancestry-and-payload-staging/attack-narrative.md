# Attack Narrative

At 14:02 UTC, `WEB-EDGE-01` generates a high-severity detection because PowerShell is descended from a command shell launched by the IIS worker process.

The suspicious chain uses the application-pool identity and runs from a service context rather than an interactive administrator session.

The PowerShell process creates `C:\ProgramData\IISCache`, launches `certutil.exe`, retrieves a file from `cdn-sync.example`, and stages `version.dll`. The file is unsigned and is immediately loaded with `rundll32.exe`.

The same time window includes legitimate look-alikes:

1. An administrator runs `Collect-IISHealth.ps1` during approved incident triage.
2. `APP-API-02` runs a deployment script and installs a signed company agent.
3. A scheduled log-rotation task on `WEB-EDGE-01` creates an archive and sends it to an internal service.
4. `WEB-EDGE-02` performs peer-server app-pool warmup.
5. Monitoring, backup, deployment, and vulnerability-scanner activity touch the same web tier.

The analyst must identify the malicious chain and explain why the look-alikes do not belong to the intrusion.

The same time window now includes additional moderate noise: health checks, commodity scans, vulnerability-scanner traffic, peer-server maintenance, monitoring collection, backup access, and deployment activity that legitimately uses `cmd.exe`. Analysts should not escalate every detection row. The expected outcome is a justified distinction between the IIS-descended malicious chain and the benign look-alikes.
