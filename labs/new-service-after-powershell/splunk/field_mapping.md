# Field Mapping

This lab uses simplified field names to keep the data readable.

## Sysmon process data

File:

```text
labs/new-service-after-powershell/data/sysmon_process.csv
```

Recommended sourcetype:

```text
synthetic:sysmon_process
```

Important fields:

- `_time`
- `host`
- `user`
- `parent_process_name`
- `parent_process_path`
- `process_name`
- `process_path`
- `process_command_line`
- `process_guid`
- `process_id`
- `parent_process_guid`
- `parent_process_id`

## PowerShell Operational data

Recommended sourcetype:

```text
synthetic:powershell_operational
```

Important fields:

- `_time`
- `host`
- `user`
- `event_code`
- `script_block_id`
- `script_block_text`

## Service Control Manager data

Recommended sourcetype:

```text
synthetic:service_control_manager
```

Important fields:

- `_time`
- `host`
- `event_code`
- `user`
- `service_name`
- `service_file_name`
- `service_type`
- `start_type`
- `account_name`

## DNS/proxy data

Recommended sourcetype:

```text
synthetic:dns_proxy
```

Important fields:

- `_time`
- `host`
- `user`
- `process_name`
- `query`
- `dest_ip`
- `dest_port`
- `action`
- `bytes_out`
- `bytes_in`

## Notes for Splunk ES users

These fields are simplified for a public lab. In a production Splunk ES environment, you may want to normalize this data to CIM-aligned fields and map process, authentication, service, and network activity into the relevant data models.

The purpose of this lab is not to prescribe a single field model. The purpose is to show the investigation relationship between events.
