# Hunt 008: August 2026 Monthly Capstone — From Alert to Containment

**Difficulty:** Field exercise  
**Expected time:** 90–150 minutes  
**Scale:** 8 portable CSV lookups × 10,000 records = **80,000 synthetic records**

This capstone combines August Hunts 005–007: follow an ambiguous alert through process/file/credential evidence, distinguish attempted movement from confirmed compromise, then re-evaluate identity activity after containment changes the baseline.

The chain crosses `ADMIN-WS-07`, `FIN-WS-14`, `APP-API-02`, `APP-API-03`, and `FILE-02`. Approved deployment, backup activity, responder actions, and an unresolved outbound TLS connection are mixed into the timeline.

Run `python3 generate_lab.py` to deterministically generate all eight CSV lookups in `data/` and mirror them into the bundled Splunk app. Then run `python3 validate_lab.py`.

Start with `CAP-001`, build the timeline, make scope/confidence decisions, choose containment actions, and document what the evidence still does not prove.