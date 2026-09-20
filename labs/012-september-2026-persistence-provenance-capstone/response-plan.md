# Response Plan

Preserve the scheduled-task definition and script on HR-WS-22, WinSupportSvc configuration/binary on ENG-WS-17, and OneDriveHealth startup configuration/script on FIN-WS-09 before removal. Isolate the three confirmed hosts according to operational impact and credential exposure. Hunt the exact task name/path, service name/path, startup item/path, relevant user accounts, and `203.0.113.77` across the estate.

Do not disable the approved patch task on PATCH-01, ACMESupportAgent on APP-06, Teams startup, or the enterprise MapDrives policy based on this evidence. Validate those mechanisms and leave them intact unless additional evidence changes the scope. Preserve the distinction between confirmed compromise and administrative proximity.
