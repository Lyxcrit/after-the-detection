# Response Plan and Expected Findings

## Expected conclusion

`WindowsCacheSync` on `WEB-EDGE-01` should be treated as malicious persistence.

## Supporting evidence

### Entry and execution

- `203.0.113.77` sends a suspicious POST to `/api/v1/diagnostics` immediately before process execution.
- `w3wp.exe` launches `cmd.exe`.
- `cmd.exe` launches hidden PowerShell under `IIS APPPOOL\\DefaultAppPool`.

### Payload staging

- PowerShell launches `certutil.exe`.
- `certutil.exe` retrieves `https://cdn-sync.example/bin/wcache.dat`.
- The payload is written to `C:\ProgramData\WinCache\wcache.exe`.
- The file is unsigned.
- SHA-256: `9f7b4a3d6d5cb44df5c9d7909d7e8e61769a02da341f5ceaa6e620efdb3434ad`.

### Persistence

- `wcache.exe` creates `WindowsCacheSync`.
- The service image path points to the staged unsigned payload.
- The start type is `auto`.
- The service starts.
- The service-launched payload contacts `cdn-sync.example` at `/api/register`.

## Benign or contextual activity

### `CompanyMonitoringAgent`

Likely approved deployment: `APP-API-02`, `WEBLAB\\svc_deploy`, signed MSI, signed agent, and `Program Files` path.

### `WebLogRotation`

Likely routine maintenance: scheduled task, appears on both `WEB-EDGE-01` and `WEB-EDGE-02`, creates expected log archives, and contacts internal backup infrastructure.

### Admin triage

Likely response activity: interactive administrator context, occurs after the suspicious service appears, and queries service state rather than creating the service.

### Vulnerability scan

Likely authorized scan: source is `VULN-SCAN-01`, timing occurs after the suspicious chain, and scanner activity alone does not explain the service creation.

### Failed authentication to `APP-API-02`

Needs scoping: source is `WEB-EDGE-01`, user is the app-pool identity, result is failure, and this is not proof of lateral movement.

## Recommended response

1. Isolate `WEB-EDGE-01` according to policy.
2. Preserve the staged payload, service configuration, PowerShell logs, process telemetry, web logs, and network evidence.
3. Block or investigate `cdn-sync.example` and `192.0.2.210`.
4. Stop and disable `WindowsCacheSync` only after evidence preservation.
5. Hunt across the environment for the service name, path, hash, domain, and process chain.
6. Review web application logs and vulnerability state for `/api/v1/diagnostics`.
7. Scope `APP-API-02` for any successful follow-on activity despite the failed auth event in this dataset.

## Confidence

High confidence for malicious execution, payload staging, service-based persistence, and external callback. Medium confidence for attempted internal scoping. Low confidence for successful lateral movement.
