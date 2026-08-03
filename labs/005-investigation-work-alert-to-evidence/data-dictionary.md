# Data Dictionary

All timestamps are UTC ISO 8601. Event IDs are unique within each lookup.

- `asset_inventory.csv`: host and ownership context
- `endpoint_process.csv`: process ancestry and command lines
- `endpoint_file.csv`: file creation and source process correlation
- `endpoint_service.csv`: service activity and image paths
- `scheduled_task.csv`: task creation and execution
- `identity_auth.csv`: authentication and movement review
- `dns.csv`: process-aware DNS
- `network_activity.csv`: process-aware connections
- `web_access.csv`: nearby web activity and noise
- `detection_results.csv`: starting alerts and contextual detections
- `investigation_findings.csv`: expected decision points
- `response_activity.csv`: authorized investigation and containment
