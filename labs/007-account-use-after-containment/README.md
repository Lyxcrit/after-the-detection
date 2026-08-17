# Hunt 007: Account Use After Containment

**Difficulty:** Guided, moderate noise  
**Expected time:** 30–45 minutes  

`FIN-WS-14` is confirmed compromised, isolated, and `ACME\mrivera` has a password reset. Three minutes later, the same user successfully authenticates from `FILE-02`, followed by command execution and finance-share access.

The hunt is about what containment changes: a username alone is not enough. Compare source host, result, timing, process execution, file access, scheduled backup activity, and responder activity before deciding whether `FILE-02` belongs in incident scope.

## Quick start
1. Start with `detection_results.csv`.
2. Build the containment timeline from `identity_admin.csv`.
3. Compare post-reset authentication in `identity_auth.csv`.
4. Pivot to process and file activity on `FILE-02`.
5. Separate backup and responder activity.
6. Make a scope and containment decision.

## Data
Nine portable CSV lookups contain 1,800 records each: **16,200 synthetic records**.
