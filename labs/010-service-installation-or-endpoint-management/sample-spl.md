# Sample SPL

## Start
```spl
| inputlookup detection_results.csv
| search detection_id="ATD-010-*"
| sort 0 _time
```

## Compare installs
```spl
| inputlookup endpoint_service.csv
| search action="installed"
| table _time host actor service_name display_name image_path start_type service_account note
```

## Follow execution
```spl
| inputlookup endpoint_process.csv
| search host="ENG-WS-17"
| sort 0 _time
| table _time user parent_process_name process_name command_line note
```

## Compare trust
```spl
| inputlookup software_trust.csv
| search file_path="*WinSupport*" OR file_path="*ACME\\Support*"
| table _time host file_path signature_status publisher reputation sha256 note
```

## Scope the service
```spl
| inputlookup endpoint_service.csv
| search service_name="WinSupportSvc"
| stats count values(image_path) values(service_account) by host
```
