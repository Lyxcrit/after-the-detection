# Data Dictionary

| Lookup | Purpose | Key fields |
|---|---|---|
| detection_results.csv | Starting signals | _time, detection_id, host, user, rule_name, severity |
| endpoint_process.csv | Process creation | _time, host, user, process_name, parent_process, command_line, pid |
| file_activity.csv | Browser-store copy/staging/archive activity | _time, host, user, action, path, source_path, process_name |
| browser_activity.csv | Browser/profile maintenance context | _time, host, user, action, profile_path, process_name, approved |
| network_activity.csv | Network sessions | _time, src_host, dest_ip, dest_port, protocol, bytes_out |
| identity_activity.csv | Cloud sign-in/session context | _time, user, source_ip, device, application, result, managed_device |
| software_inventory.csv | Installed/trusted tooling | _time, host, product, process_name, publisher, approved |
| responder_activity.csv | IR activity to exclude | _time, host, user, source_host, action, details |

All data is synthetic.
