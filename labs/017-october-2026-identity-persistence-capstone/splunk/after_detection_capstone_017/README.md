# After the Detection — Hunt 017 Splunk lookup app

Copy the `after_detection_capstone_017` directory into `$SPLUNK_HOME/etc/apps/` (or package this directory as a `.tar.gz` for Splunk Web app install). Restart/reload as required by your deployment. Eleven CSV files are included under `lookups/` and registered in `default/transforms.conf` for `inputlookup` queries. No indexes, scheduled searches, credentials, macros, or custom commands are required.

Start with `| inputlookup detection_results.csv | search detection_id="ATD17-001"` and the sample queries in `../../sample-spl.md`. This app is a lab artifact, not a production detection package.
