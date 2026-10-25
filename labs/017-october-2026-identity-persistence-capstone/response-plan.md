# Response plan — bounded evidence and operational tradeoffs

**Immediate:** Preserve the relevant sign-in, grant, token, mailbox audit, rule snapshots, message traces, and responder action IDs. Revoke the anomalous session; investigate all other sessions for the identity and verify the authentication provider recorded completion. Don't assume that action removes consent or mailbox configuration.

**Application path:** Remove the unreviewed grant and disable the unapproved app where authorized; revoke refresh tokens and inspect Graph request outcomes after the action. Resource-side enforcement, token lifetime, and policy behavior must be confirmed rather than inferred from an administrative success response.

**Mail path:** Capture the unapproved rule and destination, disable the rule, verify authoritative rule state, and observe subsequent message traces. Search for other rules, mailbox forwarding settings, transport rules, delegate permissions, and related mailboxes. Distinguish approved partner forwarding (`CHG-2048`) to avoid breaking finance workflows.

**Identity and scope:** Require credential recovery and examine other active sessions as appropriate. Review source IP, device, app, forwarding destination, and mailbox scope for other accounts. A password reset does not reverse completed API reads or external mail delivery.

**Impact:** Count distinct delivered external message IDs, preserve content classification and notification decision criteria, and identify whether sensitive files or mail content could have been exposed. Do not claim external human reading from delivery alone. Engage legal/privacy teams according to actual classification and policy.

**Tradeoffs:** Tenant-wide external forwarding blocks and disabling every OAuth connector can cause significant disruption. Escalate to broader restrictions only with evidence of additional affected identities, shared malicious infrastructure, repeated unauthorized grants, or inability to contain the active paths selectively. Record the operational owner and rollback plan.

**Exit criteria:** Session action confirmed, unreviewed grant/app disabled, resource requests no longer successful in the observed window, rule disabled, no further modeled forwarding, other access paths reviewed, affected messages scoped, and gaps assigned. This is a *bounded* finding, not proof of universal eradication.
