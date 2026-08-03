# Response Plan and Expected Findings

`ADMIN-WS-07` is confirmed compromised. The initial PowerShell download is only the starting signal; malicious intent is supported by the LSASS dump, persistence referencing an unsigned DLL, and the persistence-launched callback.

`APP-API-02` is not confirmed compromised. The evidence shows a failed WinRM attempt, not successful authentication or remote execution.

## Recommended actions

1. Isolate `ADMIN-WS-07`.
2. Disable or reset `ACME\admin.jlee` according to policy.
3. Preserve the LSASS dump, staged DLL, task, and service configuration.
4. Block and hunt for `cdn-tools.example`, `192.0.2.44`, the staged path, and related hashes.
5. Review successful uses of the administrator identity.
6. Scope `APP-API-02` without overstating the available evidence.
