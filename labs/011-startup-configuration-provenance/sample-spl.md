# Sample SPL

```spl
| inputlookup detection_results.csv
| search detection_id="ATD11-*"
| sort 0 _time
```

```spl
| inputlookup startup_config.csv
| search host="FIN-WS-09"
| sort 0 _time
| table _time user source_type item_name target_path provenance classification
```

```spl
| inputlookup endpoint_process.csv
| search host="FIN-WS-09"
| sort 0 _time
| table _time user parent_process process_name command_line classification
```

```spl
| inputlookup policy_context.csv
| search host="FIN-WS-09"
| table _time user policy_name source approved classification
```
