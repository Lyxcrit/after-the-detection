# Sample SPL

```spl
| inputlookup detection_results.csv
| search id="CAP-*"
| sort 0 _time
```

```spl
| inputlookup network_activity.csv
| search dest="203.0.113.77"
| sort 0 _time
| table _time src dest user process port classification
```

```spl
| inputlookup endpoint_process.csv
| search host IN ("HR-WS-22","ENG-WS-17","FIN-WS-09")
| sort 0 _time
| table _time host user parent process command classification
```

```spl
| inputlookup change_records.csv
| search host IN ("ENG-WS-17","APP-06","FIN-WS-09")
| table _time host change owner scope approved classification
```
