# Sample SPL

## Starting detections
```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search detection_id="ATD-009-*"
| sort 0 _time
```

## Compare scheduled tasks
```spl
| inputlookup scheduled_task.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search task_name="*TelemetryCheck*"
| sort 0 _time
| table _time host user task_name action task_command run_as note
```

## Follow HR-WS-22 process ancestry
```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="HR-WS-22"
| sort 0 _time
| table _time user parent_process_name process_name command_line note
```

## Check trust context
```spl
| inputlookup software_trust.csv
| search file_path="*TelemetryCheck*" OR file_path="*WinCache*"
| table _time host file_path signature_status publisher sha256 note
```

## Look for the persistence pattern elsewhere
```spl
| inputlookup scheduled_task.csv
| search task_name="\\Microsoft\\Windows\\Update\\TelemetryCheck"
| stats count values(task_command) values(run_as) by host
```
