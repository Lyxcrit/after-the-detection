# Coverage Map

| Investigation area | Dataset | Primary fields | Analyst question |
|---|---|---|---|
| Web context | `web_access.csv` | src_ip, uri_path, status, note | Which request likely preceded execution? |
| Initial detection | `detection_results.csv` | detection_id, severity, reason | Which detections are escalation-worthy? |
| Process ancestry | `endpoint_process.csv` | process_id, parent_process_id, command_line | What created the persistence candidate? |
| Payload staging | `endpoint_file.csv` | file_path, sha256, source_process_id | Does the service point to a staged payload? |
| Service creation | `endpoint_service.csv` | service_name, image_path, start_type, action | Is this persistence or routine service activity? |
| Scheduled tasks | `scheduled_task.csv` | task_name, user, process_id, note | Which scheduled actions are normal maintenance? |
| Network activity | `network_activity.csv` | process_id, dest_domain, uri, note | Did the service-launched payload call out? |
| Identity context | `identity_auth.csv` | user, result, session_context | Which access patterns are approved or suspicious? |
| Asset context | `asset_inventory.csv` | role, criticality, peer_group | Does the behavior fit the host? |
| Findings | `investigation_findings.csv` | expected_decision, analyst_decision | What should be escalated, scoped, or treated as context? |

## ATT&CK-aligned concepts

- Server Software Component / web application exploitation context
- Command and Scripting Interpreter
- Ingress Tool Transfer
- Create or Modify System Process: Windows Service
- Scheduled Task / Job as a benign look-alike
- Account and host scoping
