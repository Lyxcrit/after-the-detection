# Splunk Ingest Guide

The fastest approach is to upload each CSV as a lookup using the original filename.

Example:

```spl
| inputlookup endpoint_process.csv
```

No index or sourcetype is required for the guided exercise.

For production translation:

- map `endpoint_process.csv` to Endpoint.Processes or equivalent endpoint process telemetry;
- map `endpoint_file.csv` to Endpoint.Filesystem;
- map `web_access.csv` to web/proxy/application access logs;
- map `network_activity.csv` to endpoint network, Web, DNS, proxy, or firewall sources;
- map `identity_auth.csv` to Authentication;
- map `asset_inventory.csv` to asset and identity context.

The hunt logic is portable even when field names differ.
