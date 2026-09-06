# Response Plan

`ENG-WS-17` has high-confidence malicious service-based persistence.

Preserve the service configuration, binary, script, hashes, process ancestry, and network evidence. Disable `WinSupportSvc`, then isolate `ENG-WS-17`.

Do not remove `ACMESupportAgent` from `APP-06`: its SCCM/MSI ancestry, trusted binary, approved deployment, expected path, and management-server traffic support a benign endpoint-management explanation.

Hunt `WinSupportSvc`, `C:\ProgramData\WinSupport`, both hashes, and `198.51.100.44` across the estate. Do not claim propagation until matching evidence is found. Do not claim what TLS carried from metadata alone.
