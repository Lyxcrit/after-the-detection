# Attack Narrative

A locally created Microsoft-looking scheduled task on `HR-WS-22` executes an untrusted PowerShell script. The script opens TLS to `203.0.113.77`, then uses `sc.exe` to create `WinSupportSvc` on `ENG-WS-17`. The new service runs as LocalSystem from an untrusted path and contacts the same external destination. Later, `OneDriveHealth` appears in `ACME\lchen`'s startup configuration on `FIN-WS-09`; its untrusted script executes at logon and contacts the same destination.

Legitimate look-alikes include the approved `\ACME\Patch\TelemetryCheck` task on `PATCH-01`, SCCM deployment of `ACMESupportAgent` on `APP-06`, a signed Teams updater, and centrally managed `mapdrives.cmd`.

The supplied evidence supports a three-host incident chain and three distinct persistence mechanisms. It does not establish how the attacker initially obtained `ACME\mgarcia`, what the TLS payload contained, or that central policy/SCCM infrastructure was compromised.
