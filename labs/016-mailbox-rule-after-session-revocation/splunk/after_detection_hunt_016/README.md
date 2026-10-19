# After the Detection — Hunt 016 Splunk app

Lightweight lookup-based app; no ingestion pipelines or external dependencies. Copy the `after_detection_hunt_016` directory into `$SPLUNK_HOME/etc/apps/`, restart or refresh Splunk, then use `| inputlookup identity_signins.csv` and the queries in `../../sample-spl.md`.

The deterministic generator populates `lookups/` with all eight CSVs. `default/transforms.conf` registers each lookup for SPL, and `metadata/default.meta` makes them visible in this app. This app does not collect live mail telemetry or connect to Microsoft 365.
