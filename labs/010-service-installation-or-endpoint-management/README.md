# Hunt 010: Service Installation or Endpoint Management?

**Difficulty:** Guided, moderate noise  
**Expected time:** 35–50 minutes

A new auto-start service appears on `ENG-WS-17`:

`WinSupportSvc` / **Windows Support Service**

The name and mechanism are plausible. Enterprise software installs services all the time.

The investigation is about the surrounding evidence: creator, service account, image path, process ancestry, binary trust, change records, follow-on activity, and network behavior.

Nearby, SCCM legitimately installs `ACMESupportAgent` on `APP-06`. That service also auto-starts as `LocalSystem`, so a hunt based only on “new service + SYSTEM” will produce the wrong answer.

## Quick start

1. Start with `detection_results.csv`.
2. Inspect `endpoint_service.csv`.
3. Follow creation/start activity into `endpoint_process.csv`.
4. Check `endpoint_file.csv` and `software_trust.csv`.
5. Compare `WinSupportSvc` with `ACMESupportAgent`.
6. Check `change_records.csv`.
7. Use `network_activity.csv` for context without overstating TLS metadata.
8. Make the containment decision, then write the estate-wide scope query.

## Data

Eight portable CSV lookups contain 500 records each, for **4,000 total synthetic records**.
