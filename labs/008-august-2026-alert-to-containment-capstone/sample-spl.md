# Sample SPL

```spl
| inputlookup detection_results.csv
| search id="CAP-*"
| sort 0 _time
```

```spl
| inputlookup identity_auth.csv
| search user="ACME\\mrivera"
| sort 0 _time
| table _time src dest user protocol result note
```

```spl
| inputlookup endpoint_process.csv
| search host="FILE-02"
| sort 0 _time
| table _time host user parent process cmd note
```

```spl
| inputlookup network_activity.csv
| search src="FILE-02"
| sort 0 _time
| table _time src dest user port bytes note
```