# Attack Narrative

At 15:48 UTC, `ACME\knguyen` uses Microsoft 365 from `SALES-WS-18`, a managed corporate workstation using expected egress.

At 16:12, the same identity successfully authenticates from `198.51.100.77`. The identity event reports Windows, an unmanaged device, and session `sess-kng-7f2`. The source is not assigned by the corporate VPN data and does not match the user's known mobile activity.

At 16:15, session `sess-kng-7f2` accesses SharePoint and reads several documents. This establishes active use of the anomalous session, but not how access was obtained.

Purposeful look-alikes include corporate VPN source changes, mobile sign-ins, token refreshes, an approved help-desk password-reset verification for another user, and normal SharePoint activity.

The response problem is identity-focused: revoke the unexplained session, evaluate other active sessions and credential exposure, and avoid claiming a password, token, or MFA mechanism without evidence.
