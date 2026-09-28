# Sample SPL

## Start with detections

```spl
| inputlookup detection_results.csv
| sort _time
```

## Compare LSASS access

```spl
| inputlookup process_access.csv
| search target_process="lsass.exe"
| table _time host source_process target_process access_mask signer trusted parent_process
| sort _time
```

## Reconstruct DEV-WS-12 process activity

```spl
| inputlookup endpoint_process.csv
| search host="DEV-WS-12"
| table _time user parent_process process_name command_line pid
| sort _time
```

## Find dump/archive artifacts

```spl
| inputlookup file_activity.csv
| search host="DEV-WS-12" ("*lsass*" OR "*diag-0928*")
| sort _time
```

## Review authentication after the dump

```spl
| inputlookup identity_auth.csv
| search src_host="DEV-WS-12"
| table _time src_host dest_host user protocol result logon_type
| sort _time
```

## Correlate destination network activity

```spl
| inputlookup network_activity.csv
| search src_host="DEV-WS-12" dest_host="FILE-DEV-03"
| sort _time
```
