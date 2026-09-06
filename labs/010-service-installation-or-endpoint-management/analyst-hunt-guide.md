# Analyst Hunt Guide

1. Read the service configuration: name, display name, image path, start type, account, actor, time.
2. Follow how it was created.
3. Follow what the Service Control Manager starts.
4. Check binary/script provenance.
5. Compare the SCCM look-alike on `APP-06`.
6. Check change-management context.
7. Make the persistence decision on `ENG-WS-17`.
8. Hunt the exact service name, path, hashes, and destination without assuming propagation.
