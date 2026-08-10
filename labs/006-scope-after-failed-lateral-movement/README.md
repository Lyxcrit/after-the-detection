# Hunt 006: Scope After Failed Lateral Movement

**Difficulty:** Guided, moderate noise  
**Expected time:** 25–40 minutes  
**Confirmed source host:** `FIN-WS-14`

`FIN-WS-14` is already confirmed compromised. It attempts WinRM to `APP-API-02` and `APP-API-03`; both authentications fail.

Nearby telemetry includes a successful approved deployment to `APP-API-02`, normal application activity, and responder access. Decide what belongs in confirmed scope and what only requires additional review.

## Quick start

1. Start with `detection_results.csv`.
2. Compare source, user, result, and timing in `identity_auth.csv`.
3. Correlate `network_activity.csv`.
4. Review processes and files on both destinations.
5. Separate deployment and responder activity.
6. Record a confidence decision for each host.

## Data

Eight platform-portable CSV lookups contain 1,500 records each, for 12,000 total synthetic events.
