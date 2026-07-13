# Data Dictionary

## Common conventions

- `_time` is UTC in ISO 8601 format.
- Domains and external IP addresses are synthetic or reserved for documentation.
- `process_id` and `parent_process_id` are scoped to the host and scenario window.
- `session_context` is simplified synthetic context to support the teaching objective.

## Files

### `web_access.csv`

Synthetic HTTP access activity for the edge web tier. Includes health checks, commodity scanning, vulnerability-scanner traffic, approved admin browsing, and the likely suspicious diagnostics request.

Important fields: `src_ip`, `http_method`, `uri_path`, `status`, `user_agent`, `note`.

### `asset_inventory.csv`

Host role, ownership, criticality, and internet exposure.

### `endpoint_process.csv`

Process creation events and ancestry.

Important fields: `process_id`, `parent_process_id`, `parent_process_name`, `command_line`, `session_type`, `signature_status`.

### `endpoint_file.csv`

File and directory creation or modification.

Important fields: `file_path`, `sha256`, `source_process`, `source_process_id`, `signature_status`.

### `network_activity.csv`

Process-aware outbound and internal network activity.

### `identity_auth.csv`

Authentication and session context used to validate benign administration.

### `detection_results.csv`

Synthetic detection output. One row is the primary starting signal; additional rows are moderate-noise review items.

### `investigation_findings.csv`

Candidate findings with a blank `analyst_decision` field for the analyst to complete.
