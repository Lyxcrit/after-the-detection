# Sample SPL — Hunt 015

The bundled Splunk app defines `atd015_*` lookup names in `transforms.conf`. The examples below use those names for joins and the shipped CSVs for `inputlookup`. Run searches in the `After the Detection 015` app context.

## Detection → consent → app approval

```spl
| inputlookup detection_results.csv
| search detection_id="ATD15-001"
| lookup atd015_grants grant_id OUTPUT scopes consent_type admin_approved session_id source_ip
| lookup atd015_apps app_id OUTPUT display_name publisher approval_state
| table _time detection_id user app_id display_name publisher approval_state scopes consent_type admin_approved source_ip session_id
```

## Reconstruct primary user's sign-ins

```spl
| inputlookup identity_signins.csv
| search user="ACME\\mrivera"
| lookup atd015_network source_ip OUTPUT context approved
| sort 0 _time
| table _time user result auth_method source_ip context approved device managed session_id
```

## Grant → token → Graph calls

```spl
| inputlookup graph_activity.csv
| search app_id="app-qrs-779"
| lookup atd015_tokens token_id OUTPUT grant_id issuance expires_at
| lookup atd015_grants grant_id OUTPUT scopes consent_type admin_approved
| sort 0 _time
| table _time app_id user token_id grant_id scopes operation resource_id status bytes_returned expires_at
```

## Compare resource calls against session revocation

```spl
| inputlookup graph_activity.csv
| search token_id="tok-qrs-779-1"
| eval after_session_revoke=if(_time>"2026-10-09T09:32:00Z", "yes", "no")
| sort 0 _time
| table _time operation resource_id status after_session_revoke token_id
```

## Responder actions

```spl
| inputlookup response_actions.csv
| search ticket="IR-2026-4779"
| sort 0 _time
| table _time actor user target_id action result reason
```

**Interpretation:** A successful Graph read at 09:36 follows the 09:32 revocation event. That supports continued modeled app access after the session action, but does not prove the precise token enforcement mechanism. The later 403 cannot be attributed to a single control without additional evidence.
