# Analyst Hunt Guide

1. Review `ATD-005-001` without assuming intent.
2. Reconstruct the process ancestry on `ADMIN-WS-07`.
3. Correlate process IDs to downloaded files and the LSASS dump.
4. Validate whether `TelemetryCacheSync` and `TelemetryCache` belong to the suspicious chain.
5. Tie the persistence-launched process to DNS and network activity.
6. Decide what the failed WinRM attempt does and does not prove about `APP-API-02`.
7. Separate approved deployment, maintenance, scanning, backup, and responder activity.
8. Produce a timeline, scope statement, confidence ratings, response actions, and evidence gaps.
