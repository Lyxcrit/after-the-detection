# Response Plan and Expected Findings

## Expected malicious chain

`w3wp.exe (4120) -> cmd.exe (7784) -> powershell.exe (7932) -> certutil.exe (8016)`

PowerShell also launches:

`rundll32.exe (8128)`

## Staged payload

- Path: `C:\ProgramData\IISCache\version.dll`
- SHA-256: `3c6d45f5d9f6509f27e5f6f4c2f4cb4048fe6f0b148f365b5a3c5f65e13d777a`
- Signature: unsigned
- External source: `https://cdn-sync.example/assets/v3.dat`
- Resolved IP: `192.0.2.210`

## Why escalation is justified

- execution originates from the IIS web worker;
- the chain runs under the application-pool identity;
- hidden PowerShell creates a staging directory;
- a signed utility retrieves an unsigned DLL;
- the DLL is immediately loaded with `rundll32.exe`;
- process, file, and network timestamps align.

## Moderate-noise findings to reject or downgrade

The following events are intentionally present so the hunt is guided but not trivial. They should generally be rejected, downgraded, or documented as benign context after review:

- `WEB-EDGE-02` runs `Warmup-AppPool.ps1` and recycles an app pool through approved service-context maintenance.
- `WEB-EDGE-01` runs `Collect-WebCounters.ps1`, creates monitoring JSON, and sends it to the internal monitoring collector.
- `BACKUP-01` uses `Snapshot-WebConfig.ps1` and `robocopy.exe` to copy web configuration over SMB using approved backup context.
- `WEB-EDGE-01` runs `msdeploy.exe -> cmd.exe` under `WEBLAB\svc_webdeploy`; this resembles a shell event but has different ancestry and an approved deployment context.
- `SVC-SCAN-01` produces vulnerability-scanner web traffic.
- `198.51.100.53` creates commodity internet-scan noise.

## Benign look-alikes

### `Collect-IISHealth.ps1`

- interactive administrator context;
- approved incident-triage session;
- writes a text file under Windows Temp;
- queries application events;
- contacts an internal management service.

### `install-agent.ps1`

- runs on `APP-API-02`;
- originates from services under SYSTEM;
- tied to an approved deployment session from `MGMT-01`;
- creates a signed MSI and signed company agent.

### `RotateLogs.ps1`

- launched by a scheduled-task process;
- expected path under Program Files;
- creates a log archive;
- contacts an internal logging service.

## Recommended response

1. Isolate `WEB-EDGE-01` according to policy.
2. Preserve volatile evidence and the staged DLL.
3. Block or investigate `cdn-sync.example` and `192.0.2.210`.
4. Hunt for the hash, path, domain, and process chain across the environment.
5. Review the web application and access logs around 14:02 UTC.
6. Determine which request caused the IIS worker to spawn the shell.
7. Validate whether the DLL established persistence or additional network activity outside this focused dataset.

## Evidence gaps

This weekly rep includes surrounding web-access context, but it still does not include:

- full HTTP request body or application debug logs for the diagnostics endpoint;
- memory evidence;
- full PowerShell script-block content;
- persistence telemetry after `rundll32.exe`;
- enterprise-wide hash prevalence;
- definitive vulnerability/root-cause analysis for the web application.

Those are appropriate follow-on questions and can be expanded in the monthly capstone.
