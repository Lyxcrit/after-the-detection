# Splunk Ingest Guide

You have two Splunk options.

## Option 1 — Upload CSVs as lookups

The fastest approach is to upload each CSV from `data/` as a lookup using the original filename.

In Splunk Web:

1. Go to **Settings > Lookups > Lookup table files**.
2. Select **New Lookup Table File**.
3. Upload each CSV from `data/`.
4. Keep the original filename.
5. Run the included SPL with `inputlookup`.

Example:

```spl
| inputlookup endpoint_service.csv
```

No index or sourcetype is required for the guided exercise.

## Option 2 — Install the bundled Splunk lab app

This hunt includes a lightweight Splunk app under:

```text
splunk/after_detection_hunt_003/
```

Copy that directory to:

```text
$SPLUNK_HOME/etc/apps/after_detection_hunt_003
```

Then restart Splunk or reload apps.

The app includes all hunt CSVs under `lookups/`, `default/app.conf`, `default/savedsearches.conf`, and a local README.

After installation, run:

```spl
| inputlookup endpoint_service.csv
```

## Production translation

- `endpoint_process.csv` -> Endpoint.Processes or equivalent endpoint process telemetry.
- `endpoint_file.csv` -> Endpoint.Filesystem.
- `endpoint_service.csv` -> Windows System 7045 / service telemetry.
- `scheduled_task.csv` -> Windows Task Scheduler / endpoint scheduled-task telemetry.
- `web_access.csv` -> web, proxy, WAF, or application access logs.
- `network_activity.csv` -> endpoint network, DNS, proxy, firewall, or Web.
- `identity_auth.csv` -> Authentication.
- `asset_inventory.csv` -> asset and identity context.

The hunt logic is portable even when field names differ.
