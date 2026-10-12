# After the Detection — Hunt 015 Splunk Lab App

Copy `after_detection_hunt_015/` into `$SPLUNK_HOME/etc/apps/` and restart Splunk or refresh app configuration. The app ships the same eight CSV files as `../../data/` in `lookups/`; no indexing, ingest configuration, or external apps are required.

Use the `Hunt 015 Overview` dashboard and the SPL in `../../sample-spl.md`. All lookup names are defined under `default/transforms.conf`. The generator overwrites both copies deterministically; `validate_lab.py` verifies they match byte-for-byte.

The app is a self-contained synthetic training lab and does not contact Microsoft 365 or any customer systems.
