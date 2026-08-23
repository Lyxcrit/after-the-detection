# Attack Narrative

`ADMIN-WS-07` downloads an administrative archive from a legitimate domain, then stages code and accesses credentials. Failed WinRM attempts hit two application servers, while legitimate deployment WinRM succeeds nearby. The attacker successfully reaches `FIN-WS-14`, which is later isolated and triggers a reset of `ACME\mrivera`.

After reset, the identity fails from `FIN-WS-14` but succeeds from `FILE-02`. Command execution follows and `Q3.xlsx` is copied into `C:\Users\Public`. Scheduled backup and responder activity touch the same server. An outbound TLS session occurs later, but the supplied evidence does not tie the finance file to that connection.