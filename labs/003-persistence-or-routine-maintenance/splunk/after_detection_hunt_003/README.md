# After the Detection - Hunt 003 Splunk Lab App

This is a lightweight Splunk lab app for Hunt 003: Persistence or Routine Maintenance?

It is not a production TA. It is an installable lab package that ships the synthetic CSV lookups and starter saved searches.

## Install

Copy this directory to:

```text
$SPLUNK_HOME/etc/apps/after_detection_hunt_003
```

Restart Splunk or reload apps.

## Use

Run:

```spl
| inputlookup endpoint_service.csv
```

Or open the saved searches named:

- `ATD Hunt 003 - 00 Review Detections`
- `ATD Hunt 003 - 01 Service Review`
- `ATD Hunt 003 - 02 Suspicious Process Lineage`
- `ATD Hunt 003 - 03 Payload Staging`
- `ATD Hunt 003 - 04 Network Context`
- `ATD Hunt 003 - 05 Combined Timeline`
- `ATD Hunt 003 - 06 Candidate Findings`

## Scope

This app is for the synthetic hunt dataset only.

For production ingestion, use your normal endpoint, authentication, web, network, and asset sources and adapt the SPL logic.
