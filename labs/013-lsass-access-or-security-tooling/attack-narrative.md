# Attack Narrative

At 14:06 UTC, `ACME\jpatel` is active on `DEV-WS-12`. A user-context PowerShell process launches `rundll32.exe` with `comsvcs.dll, MiniDump` against the LSASS PID. The process opens `lsass.exe` with high access and writes `C:\ProgramData\Diag\lsass.dmp`.

At 14:09, PowerShell archives the dump as `C:\ProgramData\Diag\diag-0928.zip`.

At 14:14, `DEV-WS-12` authenticates successfully to `FILE-DEV-03` as `ACME\jpatel`, followed by an SMB connection. No supplied process execution, file creation, persistence, or other post-authentication activity on `FILE-DEV-03` establishes destination compromise.

Purposeful look-alikes include `SenseIR.exe` legitimately opening LSASS as part of endpoint security, `WerFault.exe` collecting an approved application crash dump, routine developer SMB access, and responder commands from `IR-JUMP-01`.

The investigation should separate mechanism from consequence: LSASS dumping is established on `DEV-WS-12`; credential theft content and the meaning of the later authentication remain bounded by the available evidence.
