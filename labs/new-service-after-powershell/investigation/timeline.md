# Investigation Timeline

| Time UTC | Event | Why it matters |
|---|---|---|
| 2026-06-24T13:58:44Z | `ACME\\j.smith` logs into `WKSTN-042` | Establishes interactive user context before the activity. |
| 2026-06-24T14:03:11Z | `powershell.exe` launches with suspicious flags | Possible script execution or payload staging. |
| 2026-06-24T14:03:12Z | PowerShell script block shows download-and-execute behavior | Adds context beyond command-line flags. |
| 2026-06-24T14:03:19Z | Directory created under `C:\Users\Public\Libraries\Cache` | User-writable staging location. |
| 2026-06-24T14:03:46Z | Payload-like file written to `winupdate.exe` | Potential staged binary. |
| 2026-06-24T14:04:02Z | `sc.exe create WinUpdateSvc` | Service creation shortly after suspicious PowerShell. |
| 2026-06-24T14:04:03Z | Service Control Manager logs service creation | Confirms new service and binary path. |
| 2026-06-24T14:05:10Z | `winupdate.exe` runs as SYSTEM via `services.exe` | Service execution and privilege context. |
| 2026-06-24T14:05:18Z | Host connects to `updates-example.test` | Outbound activity after service starts. |

## Analyst takeaway

The strongest signal is not any single event.

The stronger signal is the sequence:

> suspicious PowerShell → staged file → service creation → service execution → outbound network activity

That sequence gives the analyst a clearer path than a standalone notable.
