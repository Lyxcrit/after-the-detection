# Sample SPL

These examples are intentionally simple and designed for lab discussion. They are not production-ready detections.

Adjust indexes, sourcetypes, field names, macros, and data model mappings for your environment.

## Suspicious PowerShell command line

```spl
index=synthetic sourcetype=synthetic:sysmon_process process_name="powershell.exe"
| search process_command_line="*ExecutionPolicy Bypass*" OR process_command_line="*EncodedCommand*" OR process_command_line="*-NoProfile*"
| table _time host user parent_process_name process_name process_command_line process_guid parent_process_guid
```

## New service creation

```spl
index=synthetic sourcetype=synthetic:service_control_manager event_code=7045
| table _time host user service_name service_file_name start_type account_name
```

## Service creation after suspicious PowerShell

```spl
index=synthetic sourcetype=synthetic:sysmon_process process_name="powershell.exe"
| search process_command_line="*ExecutionPolicy Bypass*" OR process_command_line="*EncodedCommand*" OR process_command_line="*-NoProfile*"
| rename _time as powershell_time process_guid as powershell_guid process_command_line as powershell_command_line
| table powershell_time host user powershell_guid powershell_command_line
| join type=inner host user [
    search index=synthetic sourcetype=synthetic:service_control_manager event_code=7045
    | rename _time as service_time
    | table service_time host user service_name service_file_name start_type account_name
]
| eval delta_seconds=service_time-powershell_time
| where delta_seconds >= 0 AND delta_seconds <= 600
| table powershell_time service_time delta_seconds host user service_name service_file_name powershell_command_line
```

## Outbound activity after service execution

```spl
index=synthetic sourcetype=synthetic:dns_proxy process_name="winupdate.exe"
| table _time host user process_name query dest_ip dest_port action bytes_out bytes_in
```

## Timeline view

```spl
(index=synthetic sourcetype=synthetic:sysmon_process host=WKSTN-042)
OR (index=synthetic sourcetype=synthetic:powershell_operational host=WKSTN-042)
OR (index=synthetic sourcetype=synthetic:service_control_manager host=WKSTN-042)
OR (index=synthetic sourcetype=synthetic:dns_proxy host=WKSTN-042)
| sort 0 _time
| table _time sourcetype host user process_name process_command_line service_name service_file_name query dest_ip event_code
```
