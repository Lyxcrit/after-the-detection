# Hunt 014: Successful Sign-In, Wrong Context

**Difficulty:** Guided, moderate noise  
**Expected time:** 30–45 minutes  
**Primary identity:** `ACME\knguyen`  
**Known workstation:** `SALES-WS-18`

At 15:48 UTC, `ACME\knguyen` is active from the user's normal managed workstation through expected corporate egress. At 16:12, the same identity successfully authenticates to Microsoft 365 from a new source and an unmanaged Windows device. At 16:15, the new session begins SharePoint activity.

The dataset also contains normal VPN source changes, mobile sign-ins, token refreshes, help-desk activity, managed-device changes, and routine cloud access. The analyst must explain the authentication context before deciding whether the account requires response.

## Quick start

1. Start with `detection_results.csv`.
2. Build the user's timeline from `identity_auth.csv`.
3. Resolve source context with `network_context.csv` and `vpn_activity.csv`.
4. Resolve device context with `device_inventory.csv`.
5. Follow the new session into `cloud_activity.csv`.
6. Separate approved support activity using `helpdesk_activity.csv`.
7. Compare against normal user/session patterns in `session_activity.csv`.
8. Record what is proven, what is suspicious, and what remains unknown.

## Data

Eight platform-portable CSV lookups contain **500 records each — 4,000 synthetic records total**. Generation is deterministic with seed `20261004`.

## Expected decision

The supplied evidence supports high confidence that `ACME\knguyen` has an anomalous, actively used cloud session that is not explained by known VPN, managed-device, mobile, or help-desk context. Revoke the anomalous session and review the identity's other active sessions.

The data does **not** prove password theft, token theft, MFA bypass, compromise of the unmanaged Windows device, or the initial-access mechanism.

## Splunk lab app

A lightweight app is included under `splunk-app/after_the_detection_014/`. Copy the generated CSVs into its `lookups/` directory and use the queries in `sample-spl.md`.
