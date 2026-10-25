# Attack narrative — synthetic, analyst spoiler

On October 23, `ACME\knguyen` has a normal managed sign-in from `SALES-WS-18` at 15:48. At 16:12 the account authenticates successfully from `UNKNOWN-WIN` at `198.51.100.74`; the source is unclassified and the device unmanaged. MFA is satisfied, but no trusted-device or VPN context explains the source. At 16:14 the new session is associated with SharePoint file activity.

At 16:16 the account grants `Mail.Read offline_access` to unreviewed `app-qrs-779` (`Quarterly Reports Sync` in the analyst materials), producing `grant-qrs-779`. `tok-qrs-779-1` is issued at 16:17. Graph `Mail.Read` returns success at 16:18 and 16:21. At 16:19, the same account/session creates `rule-kn-invoices-017`, forwarding invoice-subject mail to `invoice-review@outside.example`. The first modeled forward is at 16:20.

The SOC revokes the interactive session at 16:22. A second forward occurs at 16:24 and another Graph read succeeds at 16:25. At 16:28 responders disable the app and remove consent, and at 16:29 revoke refresh tokens. A modeled Graph request at 16:31 is denied. At 16:34 responders disable the inbox rule; messages at 16:36 and 16:40 have inbox delivery without modeled forwarding. The account password is reset at 16:39. A verification action is recorded at 16:42.

This is a **synthetic correlation exercise**, not an attribution claim. The event relationships demonstrate distinct control planes and containment gaps. They do not establish token theft, MFA bypass, or who controlled the account. Mail delivery does not establish external reading. Absence of later forwards in the dataset does not prove complete eradication in a real tenant.
