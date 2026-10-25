# Hunt 017 — October 2026 Identity Persistence Capstone

**Field exercise:** October 26 / 28 / 30, 2026 · **Time:** 120–180 minutes · **Difficulty:** intermediate/advanced · **Seed:** `20261026`.

At 15:48 UTC on October 23, `ACME\knguyen` uses the managed `SALES-WS-18` through known corporate egress. At 16:12 the same identity signs in successfully from `UNKNOWN-WIN` at unclassified `198.51.100.74`, with MFA marked **satisfied**. At 16:16 an unreviewed `Mail.Read offline_access` consent grant is created for `app-qrs-779`; Graph reads follow. At 16:19 an unapproved Exchange inbox rule is created. Revoking the anomalous interactive session at **16:22** does not remove the modeled app grant or mailbox rule. At 16:24 the rule forwards another message, and at 16:25 the app successfully reads mail. Responders disable the app/remove consent at 16:28, revoke refresh tokens at 16:29, disable the rule at 16:34, and verify later modeled activity.

**Investigation:** Determine whether the sign-in was anomalous, what the account actually accessed, which mechanisms survived session revocation, what was contained, and what evidence remains missing. Correlate identity, device, network, OAuth, token, Graph, mailbox rule, message trace, and responder records. Distinguish approved partner forwarding and business connectors from the target chain.

All data is synthetic, with reserved documentation IP addresses. This exercise models event semantics; it does not assert a specific cloud provider's token revocation or rule propagation behavior.

## Start here

1. Open `data/detection_results.csv`; begin with `ATD17-001` through `ATD17-004`.
2. Build an evidence timeline without reading the answer key. Follow `sess-kn-new-017`, `grant-qrs-779`, `tok-qrs-779-1`, and `rule-kn-invoices-017`.
3. Pivot into network context and device inventory before calling the sign-in malicious.
4. Correlate resource activity and message traces with **event time**, not ingest order. Count distinct forwarded `message_id` values, not all trace rows.
5. Overlay `INC-017` response actions and confirm which access paths still had observed success after session revocation.
6. Compare approved app/partner forwarding look-alikes; document scope, confidence, impact, containment, and gaps.

## Data and portability

Eleven platform-portable CSVs in `data/` have **10,000 records each (110,000 total)**. Each file includes stable event IDs and explicit correlation fields. The deterministic generator and independent validator use only Python standard library. From this directory run:

```bash
python3 generate_lab.py
python3 validate_lab.py
```

The validator checks 11 row counts, event-ID uniqueness, referential integrity, target chronology, post-revocation resource access, forwarded message counts, approved look-alikes, identical Splunk copies, and byte-for-byte regeneration. See [validation report](validation-report.md).

## Materials

- [Coverage map: Hunts 014–016](prior-three-weeks-coverage-map.md)
- [Attack narrative](attack-narrative.md)
- [Analyst hunt guide](analyst-hunt-guide.md)
- [Investigation worksheet](investigation-worksheet.md)
- [Data dictionary](data-dictionary.md)
- [Sample SPL](sample-spl.md)
- [Response plan](response-plan.md)
- [Answer key](answer-key.json) — spoilers
- [Validation report](validation-report.md)
- [Installable Splunk app](splunk/after_detection_capstone_017/README.md)

**Evidence boundaries:** MFA satisfied does not prove MFA bypass. Successful Graph `Mail.Read` supports modeled API resource access, not a human reading every message. A `delivered` forward trace supports modeled mail delivery, not recipient consumption. Later denied requests and absence of further forwards support bounded containment but do not establish that every possible token, app, rule, or copy of data was eliminated. The initial-access mechanism and operator identity remain unknown.
