# Sample SPL

## 0. Review surrounding web activity

```spl
| inputlookup web_access.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time src_ip http_method uri_path status user_agent note
```

## 1. Start with the detections

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| sort 0 _time
| table _time severity title host user parent_process_name process_name reason status
```

## 2. Review process ancestry on the edge server

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time user session_type parent_process_name parent_process_id process_name process_id command_line signature_status
```

## 3. Focus on the suspicious chain

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01" (process_id="7784" OR process_id="7932" OR process_id="8016" OR process_id="8128")
| sort 0 _time
| eval lineage=parent_process_name."(".parent_process_id.") -> ".process_name."(".process_id.")"
| table _time user lineage command_line signature_status
```

## 4. Correlate file writes to process IDs

```spl
| inputlookup endpoint_file.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time user action file_path sha256 source_process source_process_id signature_status
```

## 5. Correlate network activity

```spl
| inputlookup network_activity.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time user process_name process_id dest_domain dest_ip dest_port uri action bytes_in
```

## 6. Compare all PowerShell activity

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search process_name="powershell.exe"
| sort 0 _time
| table _time host user session_type parent_process_name process_id command_line
```

## 7. Build a combined timeline

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="process",
       detail=parent_process_name." -> ".process_name." | ".command_line
| fields _time host user event_type process_id detail
| append [
    | inputlookup endpoint_file.csv
    | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="file",
           process_id=source_process_id,
           detail=action." | ".file_path." | signature=".signature_status
    | fields _time host user event_type process_id detail
]
| append [
    | inputlookup network_activity.csv
    | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="network",
           detail=process_name." -> ".dest_domain.uri." | bytes_in=".bytes_in
    | fields _time host user event_type process_id detail
]
| search host="WEB-EDGE-01"
| sort 0 _time
```

## 8. Compare the moderate-noise review detections

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search severity="medium" OR severity="low"
| sort 0 _time
| table _time detection_id title host user parent_process_name process_name reason status
```

## 9. Review candidate findings and analyst decisions

```spl
| inputlookup investigation_findings.csv
| table finding_id finding_type host entity evidence_summary initial_confidence analyst_decision
```
