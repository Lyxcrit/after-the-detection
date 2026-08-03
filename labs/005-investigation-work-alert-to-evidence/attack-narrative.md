# Attack Narrative

On August 4, an administrator on `ADMIN-WS-07` launches PowerShell and downloads a diagnostic archive from a legitimate vendor domain.

The archive is extracted and a signed diagnostic utility creates an LSASS memory dump. An unsigned DLL is then staged under `C:\ProgramData\TelemetryCache`, with a scheduled task and service referencing the DLL. The persistence-launched process contacts `cdn-tools.example` at `192.0.2.44`.

A later WinRM attempt toward `APP-API-02` fails. The destination requires further scoping, but the provided evidence does not prove successful access or execution there.
