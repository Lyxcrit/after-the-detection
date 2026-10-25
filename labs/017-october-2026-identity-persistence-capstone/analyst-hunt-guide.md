# Analyst hunt guide

**Starting alert:** `ATD17-001` (`unmanaged_successful_signin`). Do not read `answer-key.json` until after completing the worksheet.

## 1. Authenticate the context

Filter `identity_signins` for `ACME\knguyen`; compare the 15:48 and 16:12 successful sign-ins. Join on `source_ip` to `network_context` and `device_id` to `device_inventory`. Document what MFA `satisfied` actually says. Look for plausible VPN, managed-device, or approved help-desk explanations before escalating.

## 2. Build the identity-to-resource chain

Follow `session_id=sess-kn-new-017`. Resolve `grant-qrs-779` in `oauth_grants`; join `token_events` by `grant_id` and `graph_activity` by `token_id`. Note the scope, app approval, issue time, resource, operation, result, and bytes returned. Find the 16:25 Graph success after the 16:22 session action. Distinguish a successful API read from a claim about message content or a human actor.

## 3. Investigate mailbox configuration

Find `rule-kn-invoices-017` in `mailbox_audit` and `mailbox_rules`; join the create audit to `sess-kn-new-017`. Count **distinct message IDs** with external `forward` and `delivered` in `message_trace`. Compare against `rule-partner-approved`, which has a valid change ticket. Establish whether the 16:24 forward occurred after session revocation.

## 4. Scope across records

Search the unclassified source IP, app ID, external forwarding destination, and account across all lookups. The data includes ordinary connectors, approved external forwarding, routine reviews, managed endpoints, and repeated inventory snapshots. Do not treat all external IPs or rules as malicious. Explain which evidence ties entities to the chain and which is merely adjacent.

## 5. Containment and proof

Overlay `INC-017` actions with event time. Determine whether the session action stopped the app or rule. Compare the 16:31 denied Graph request and 16:34 rule disable with later traces. Record any visibility limitations before declaring containment complete.

## Expected analyst deliverables

A timeline with event IDs and UTC timestamps; a scoped entity list; a table of confirmed/suspected/unknown behaviors; a distinct-message impact estimate; targeted response steps with business impact; and explicit evidence gaps.
