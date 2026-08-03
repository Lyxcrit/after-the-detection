# Sample SPL

## Start with the detection

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search detection_id="ATD-005-001"
```

## Trace the process chain

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="ADMIN-WS-07"
| sort 0 _time
| table _time user parent_process_name parent_process_id process_name process_id command_line signature_status classification note
```

## Review files and persistence

```spl
| inputlookup endpoint_file.csv
| append [ | inputlookup scheduled_task.csv ]
| append [ | inputlookup endpoint_service.csv ]
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="ADMIN-WS-07"
| sort 0 _time
```

## Review DNS and network pivots

```spl
| inputlookup dns.csv
| append [ | inputlookup network_activity.csv ]
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="ADMIN-WS-07"
| sort 0 _time
```
