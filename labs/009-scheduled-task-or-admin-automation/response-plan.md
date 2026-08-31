# Response Plan / Expected Decision

`HR-WS-22` has high-confidence malicious scheduled-task persistence.

The decision is not based on the Microsoft-looking task name. It is based on the combined evidence:

- the task was created by `ACME\kpatel`
- it runs hidden PowerShell as `SYSTEM`
- the script lives under `C:\ProgramData\WinCache`
- the task launches an unsigned DLL through `rundll32.exe`
- the payload performs discovery and opens external TLS sessions
- there is no approved change matching the task

Preserve the task XML, script, DLL, hashes, and process/network evidence, disable the task, then isolate `HR-WS-22`.

Hunt the exact task path, script/DLL hashes, `WinCache` path, and external destination across the estate.

Do **not** claim persistence on another host until matching evidence is found. The legitimate `PATCH-01` task is a useful comparison, not proof of propagation.
