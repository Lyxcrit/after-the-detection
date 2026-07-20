# Sample SPL

## 0. Review detections

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| sort 0 _time
| table _time detection_id severity title host user parent_process_name process_name reason status
```

## 1. Start with service creation

```spl
| inputlookup endpoint_service.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| sort 0 _time
| table _time host user service_name display_name image_path start_type action source_process source_process_id signature_status note
```

## 2. Trace the suspicious service lineage

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01" (process_id="7724" OR process_id="7860" OR process_id="7904" OR process_id="8032" OR process_id="8468" OR process_id="8500" OR process_id="8556")
| sort 0 _time
| eval lineage=parent_process_name."(".parent_process_id.") -> ".process_name."(".process_id.")"
| table _time user session_type lineage command_line signature_status note
```

## 3. Correlate file staging

```spl
| inputlookup endpoint_file.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time user action file_path sha256 source_process source_process_id signature_status note
```

## 4. Correlate network activity by process ID

```spl
| inputlookup network_activity.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time user process_name process_id dest_domain dest_ip dest_port uri action bytes_in note
```

## 5. Review web context

```spl
| inputlookup web_access.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ")
| search host="WEB-EDGE-01"
| sort 0 _time
| table _time src_ip http_method uri_path status user_agent note
```

## 6. Build a combined timeline

```spl
| inputlookup web_access.csv
| eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="web", user="-", process_id="-", detail=src_ip." ".http_method." ".uri_path." status=".status." | ".note
| fields _time host user event_type process_id detail
| append [ | inputlookup endpoint_process.csv | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="process", detail=parent_process_name." -> ".process_name." | ".command_line." | ".note | fields _time host user event_type process_id detail ]
| append [ | inputlookup endpoint_file.csv | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="file", process_id=source_process_id, detail=action." | ".file_path." | signature=".signature_status." | ".note | fields _time host user event_type process_id detail ]
| append [ | inputlookup endpoint_service.csv | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="service", process_id=source_process_id, detail=action." | ".service_name." | ".image_path." | ".note | fields _time host user event_type process_id detail ]
| append [ | inputlookup network_activity.csv | eval _time=strptime(_time, "%Y-%m-%dT%H:%M:%SZ"), event_type="network", detail=process_name." -> ".dest_domain.uri." | ".note | fields _time host user event_type process_id detail ]
| search host="WEB-EDGE-01"
| sort 0 _time
```

## 7. Review candidate findings

```spl
| inputlookup investigation_findings.csv
| table finding_id finding_type host entity evidence_summary expected_decision analyst_decision
```
