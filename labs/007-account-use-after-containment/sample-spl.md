# Sample SPL

```spl
| inputlookup identity_auth.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search user="ACME\\mrivera"
| sort 0 _time
| table _time src_host dest_host user protocol result classification note
```

```spl
| inputlookup endpoint_process.csv
| eval _time=strptime(_time,"%Y-%m-%dT%H:%M:%SZ")
| search host="FILE-02"
| sort 0 _time
| table _time host user parent_process_name process_name command_line classification note
```
