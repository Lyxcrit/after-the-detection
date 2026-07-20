# Attack Narrative

At 14:00 UTC, `WEB-EDGE-01` receives a suspicious request to `/api/v1/diagnostics`.

Immediately afterward, the IIS worker process spawns `cmd.exe`, which launches hidden PowerShell. The PowerShell chain retrieves an unsigned payload from `cdn-sync.example`, stages it under `C:\ProgramData\WinCache\wcache.exe`, and executes it.

A few minutes later, `wcache.exe` creates an auto-start service named `WindowsCacheSync` that points to the staged payload. The service starts and the service-launched payload contacts the same external infrastructure.

The same time window includes moderate noise:

- normal health checks;
- commodity web scanning;
- authorized vulnerability-scanner traffic;
- an administrator querying service state;
- scheduled log rotation;
- backup activity;
- a legitimate `CompanyMonitoringAgent` deployment on `APP-API-02`;
- peer-host maintenance on `WEB-EDGE-02`.

The analyst should not escalate every service or script event. The objective is to connect the service event to the suspicious chain and separate it from legitimate operating activity.
