# Analyst hunt guide

**Start:** `ATD15-001`. Do not assume the detection name proves malicious consent.

1. **Authenticate the context.** Find the 09:14 managed sign-in and 09:24 unmanaged sign-in for `ACME\mrivera`. Compare source, device, result, MFA, and `session_id` with `network_context.csv`.
2. **Resolve the grant.** Join detection `grant_id` to `oauth_grants.csv`, then `app_id` to `app_inventory.csv`. Record consent type, `Mail.Read offline_access`, publisher, and approval status.
3. **Resolve the token.** Join `grant_id` to `token_events.csv` and identify `tok-qrs-779-1`. Read `expires_at`; token validity is not proof a resource will accept it.
4. **Follow resource use.** Join `token_id` to `graph_activity.csv`. Compare 09:29, 09:31, 09:36, and 09:44 responses. Keep the 09:36 HTTP 200 separate from the 09:44 HTTP 403.
5. **Read responder actions.** Find ticket `IR-2026-4779`; establish 09:32 session revocation, 09:41 consent removal/app disable, and 09:42 refresh-token revocation.
6. **Scope and decide.** Identify affected account, app, consent grant, token, and mailbox operations. Do not add devices or other mailboxes to confirmed compromise without evidence.

**Useful checks:** Were successful resource calls logged *after* the revocation event time? Is it the same token? Was the app approved? Could an admin-approved connector explain the grant? Is the source an approved egress? What would prove an actual export rather than reads? What other active grants exist for the identity?

**Confidence:** High for grant and observed Graph reads; moderate/high for unapproved anomalous context; unknown for initial access, actor identity, exact revocation enforcement, and downstream use of message content.
