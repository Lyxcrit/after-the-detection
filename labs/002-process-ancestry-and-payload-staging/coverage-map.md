# Coverage Map

| Investigation area | Dataset | Primary fields | Analyst question |
|---|---|---|---|
| Initial alert | `detection_results.csv` | host, user, process, parent, reason | What triggered review? |
| Web request context | `web_access.csv` | src_ip, method, uri_path, status, user_agent | Which request likely preceded execution, and which requests are noise? |
| Process ancestry | `endpoint_process.csv` | process_id, parent_process_id, command_line | Which application or session originated execution? |
| Payload staging | `endpoint_file.csv` | file_path, sha256, source_process_id | What changed on disk, and which process caused it? |
| Network retrieval | `network_activity.csv` | process_id, dest_domain, uri, bytes_in | Which process retrieved the staged content? |
| User/session context | `identity_auth.csv` | user, source, target, session_context | Is the activity tied to approved administration? |
| Host role | `asset_inventory.csv` | role, criticality, internet_facing | Does the behavior fit the system? |
| Candidate findings | `investigation_findings.csv` | evidence_summary, analyst_decision | Which findings support escalation? |

## ATT&CK-aligned concepts

- Command and Scripting Interpreter: PowerShell
- System Binary Proxy Execution
- Ingress Tool Transfer
- User Execution and service-context comparison
- File and Directory Discovery through analyst pivots

The lab is designed around investigation relationships rather than ATT&CK-label memorization.
