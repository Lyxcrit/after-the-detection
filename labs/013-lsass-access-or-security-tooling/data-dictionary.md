# Data Dictionary

| Lookup | Purpose | Key fields |
|---|---|---|
| detection_results.csv | Starting signals | _time, detection_id, host, user, rule_name, severity |
| endpoint_process.csv | Process creation | _time, host, user, process_name, parent_process, command_line, pid |
| process_access.csv | Cross-process access | _time, host, source_process, target_process, access_mask, signer, trusted |
| file_activity.csv | Dump/archive and benign file activity | _time, host, user, action, path, process_name |
| identity_auth.csv | Authentication evidence | _time, src_host, dest_host, user, protocol, result, logon_type |
| network_activity.csv | Network sessions | _time, src_host, dest_host, dest_ip, dest_port, protocol, bytes_out |
| software_inventory.csv | Installed/trusted tooling context | _time, host, product, process_name, publisher, approved |
| responder_activity.csv | IR activity to exclude from attacker timeline | _time, host, user, source_host, action, details |

All data is synthetic.
