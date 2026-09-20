# Capstone 012: September 2026 — Persistence, Provenance, and Scope

**Field exercise:** multi-stage investigation with purposeful moderate noise  
**Expected time:** 90–150 minutes

The exercise starts with a Microsoft-looking scheduled task on `HR-WS-22`. The chain reaches `ENG-WS-17` through remote service creation and later surfaces as user-context startup persistence on `FIN-WS-09`. Nearby legitimate patch automation, endpoint-management service installation, application startup, and enterprise logon policy are deliberately mixed into the evidence.

The analyst must build the timeline, prove which mechanisms belong to the incident, preserve benign look-alikes, decide scope and confidence, and make containment choices without treating every administrative mechanism as attacker-controlled.

## Data
Ten platform-portable CSV lookups contain **10,000 records each — 100,000 synthetic records total**. Generation is deterministic with seed `20260921`.
