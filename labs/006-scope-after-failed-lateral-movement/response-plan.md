# Response Plan / Expected Decision

`FIN-WS-14` is confirmed compromised and should be contained.

`APP-API-02` and `APP-API-03` require scoping because the compromised source attempted WinRM access. The supplied evidence does not confirm either destination as compromised.

The successful WinRM on `APP-API-02` comes from `DEPLOY-01` using `ACME\svc_deploy` and is followed by the expected deployment process and artifact. Later activity comes from an authorized responder.

Do not isolate production application servers solely because a failed authentication originated from a compromised host.
