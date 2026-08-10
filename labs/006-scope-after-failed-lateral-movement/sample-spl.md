# Sample SPL

## Starting detections

```spl
| inputlookup detection_results.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search detection_id="ATD-006-*"
| sort 0 _time
```

## Authentication comparison

```spl
| inputlookup identity_auth.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search dest_host IN ("APP-API-02","APP-API-03")
| sort 0 _time
| table _time src_host dest_host user protocol result classification note
```
