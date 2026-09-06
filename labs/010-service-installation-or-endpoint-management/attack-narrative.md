# Attack Narrative

`ACME\adavis` stages `C:\ProgramData\WinSupport\supportsvc.exe` and `collect.ps1` on `ENG-WS-17`, then uses `sc.exe create` to register `WinSupportSvc` as an auto-start `LocalSystem` service.

`services.exe` starts the binary. `supportsvc.exe` launches PowerShell, performs basic discovery, and opens TLS to `198.51.100.44`. The files are unsigned and no approved change explains the service.

Seven minutes later, SCCM legitimately deploys `ACMESupportAgent` to `APP-06`. Its ancestry is `CcmExec.exe -> msiexec.exe`, its binary is trusted internal software under `C:\Program Files\ACME\Support`, an approved deployment exists, and the agent reports to `SCCM-01`.

The evidence supports high-confidence service-based persistence on `ENG-WS-17`. It does not prove the service exists elsewhere, and TLS metadata does not establish session content, command semantics, or data theft.
