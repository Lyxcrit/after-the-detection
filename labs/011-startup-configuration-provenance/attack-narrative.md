# Attack Narrative

`OneDriveHealth` appears as new user startup configuration on `FIN-WS-09`. The target is an untrusted script under the user's roaming profile. At the next interactive logon, `explorer.exe` launches PowerShell, which starts a second untrusted artifact and produces outbound TLS to `203.0.113.77`.

The host also has three benign look-alikes: a centrally managed drive-mapping script, a signed Teams updater, and an approved DisplayProfile startup shortcut.

The supplied evidence supports high-confidence malicious user-context startup persistence on `FIN-WS-09`. It does not support enterprise-policy compromise, propagation to another host, or a claim about TLS payload content.
