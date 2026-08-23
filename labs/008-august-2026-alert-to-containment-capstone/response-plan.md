# Response Plan

`ADMIN-WS-07` and `FIN-WS-14` are confirmed compromised and should be isolated. `APP-API-02` and `APP-API-03` require scoping, but failed WinRM alone does not confirm compromise. `FILE-02` belongs in incident scope with high confidence after post-reset authentication, command execution, and finance-file access.

Because `FILE-02` is a shared server, preserve volatile evidence first if the operational window permits, then restrict network access. The outbound TLS event justifies an exfiltration hunt, not an exfiltration conclusion.