# Data Dictionary

## Common conventions

- `_time` is UTC in ISO 8601 format.
- Domains and external IP addresses are synthetic or reserved for documentation.
- `process_id`, `parent_process_id`, and `source_process_id` are scoped to the host and scenario window.
- `note` fields are included to support a guided weekly hunt. In a real dataset, those notes would come from enrichment, case context, or analyst annotation.

## Datasets

- `asset_inventory.csv` — host role, ownership, criticality, exposure, and peer group.
- `web_access.csv` — synthetic web/application access data around suspected edge exploitation.
- `endpoint_process.csv` — process creation and ancestry.
- `endpoint_file.csv` — file and directory creation or modification.
- `endpoint_service.csv` — service creation and service-state changes.
- `scheduled_task.csv` — scheduled-task activity used to separate normal maintenance from persistence.
- `network_activity.csv` — process-aware network activity.
- `identity_auth.csv` — authentication and session context.
- `detection_results.csv` — synthetic detection output; not every detection should be escalated.
- `investigation_findings.csv` — candidate findings with expected decision categories: `escalate`, `context`, or `investigate`.
