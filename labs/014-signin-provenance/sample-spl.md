# Sample SPL

```spl
| inputlookup detection_results.csv
| sort _time
```

```spl
| inputlookup identity_auth.csv
| search user="ACME\\knguyen"
| sort _time
```

```spl
| inputlookup cloud_activity.csv
| search user="ACME\\knguyen"
| sort _time
```

```spl
| inputlookup vpn_activity.csv
| search user="ACME\\knguyen"
| sort _time
```
