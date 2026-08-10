# Attack Narrative

`FIN-WS-14` is confirmed compromised before the hunt begins. The compromised user's session attempts WinRM against `APP-API-02` and `APP-API-03`; both attempts fail.

Two minutes later, `APP-API-02` receives successful WinRM from `DEPLOY-01` using `ACME\svc_deploy`, followed by an approved agent installation. Later, a responder connects from `JUMP-01`.

Do not merge unrelated successful sessions into the attacker's failed attempts just because they use the same destination and protocol.
