# Response Plan

## Immediate

- Preserve the LSASS-access event, process tree, command line, dump file metadata, archive metadata, active sessions, and network connections on `DEV-WS-12`.
- Contain `DEV-WS-12` once volatile collection is complete if operational conditions allow; accelerate containment if active credential use or destructive behavior is observed.
- Reset/revoke credentials exposed to `DEV-WS-12` according to identity and incident-response policy. Do not claim the dataset identifies exactly which secrets were present in LSASS.
- Review `FILE-DEV-03` for logon-session details, process creation, file access, persistence, and other post-authentication evidence before calling it compromised.

## Preserve legitimate tooling

Do not disable the endpoint security sensor because `SenseIR.exe` legitimately accesses LSASS. Validate signer, installation context, expected behavior, and product inventory.

Do not treat Windows Error Reporting or approved diagnostic dump collection as malicious solely because dump behavior appears elsewhere in the incident.

## Evidence gaps

- Contents of `lsass.dmp`
- Which credentials, if any, were recovered
- Whether `ACME\jpatel` was obtained from the dump
- Whether the successful `FILE-DEV-03` authentication used stolen credentials
- Any attacker execution or persistence on `FILE-DEV-03`
