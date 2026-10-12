# Response plan and tradeoffs

**Immediate:** Preserve sign-in, grant, token, Graph, app-inventory, and response events with event times and IDs. Identify the exact user, app, grant, token, scopes, and observed resources. Review all active delegated grants for the identity and determine whether the unapproved app has other users or business dependencies.

**Containment:** Revoke the anomalous interactive session and examine other sessions. Do **not** assume that action instantly invalidates every already-issued application access token. Evaluate removal of the delegated consent, disabling the unapproved app, revoking refresh tokens, and any available token/session enforcement controls. Confirm results from subsequent resource access telemetry rather than relying solely on a successful control-plane API response.

**Tradeoffs:** Disabling an app can affect multiple users and business workflows; scope its users before acting when feasible. A password reset can be a reasonable defensive measure without evidence of password theft. A token can remain technically unexpired while a resource denies it, or be rejected for unrelated policy reasons. Preserve evidence before broad revocation where doing so does not create unacceptable risk.

**Escalation:** Escalate if mailbox reads continue after expected controls, if other users granted the same app, if additional scopes or privileged grants appear, or if message content is observed moving to external destinations. Obtain application registration history, sign-in/consent audit logs, token/CAE policy context, mailbox audit details, and network evidence as available.

**Evidence boundaries:** This lab establishes an unapproved consent and observed delegated mail reads. It does not establish credential theft, token theft, MFA bypass, exfiltration, device compromise, or why the 09:44 request returned 403.
