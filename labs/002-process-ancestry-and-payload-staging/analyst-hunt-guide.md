# Analyst Hunt Guide

## Starting point

Use the high-severity detection on `WEB-EDGE-01`.

## Checkpoint 0 — Review surrounding web activity

This hunt still starts from the detection, but the added web data lets you check whether one request plausibly preceded the process chain.

- Which requests are routine health checks?
- Which requests are commodity scanning?
- Which source IP is temporally closest to the suspicious process chain?
- Is the web request enough by itself to prove exploitation?

## Checkpoint 1 — Identify the origin

- What process launched the command shell?
- What is the grandparent process?
- Which user and session context own the chain?
- Why is that relationship abnormal for the host?

## Checkpoint 2 — Follow the descendants

- Which process launched PowerShell?
- Which child processes did PowerShell create?
- What commands were used?

## Checkpoint 3 — Identify the staged payload

- Which directory was created?
- Which file was written?
- Which process wrote it?
- What is the hash and signature state?
- Was the file executed?

## Checkpoint 4 — Validate network context

- Which process contacted the external destination?
- What domain, IP, URI, and byte count were observed?
- Does the network event align with the file creation time?

## Checkpoint 5 — Separate noise

Explain why each of the following is likely benign:

- `Collect-IISHealth.ps1`
- `install-agent.ps1`
- `RotateLogs.ps1`
- `Warmup-AppPool.ps1` on `WEB-EDGE-02`
- `Collect-WebCounters.ps1`
- `msdeploy.exe -> cmd.exe`

Do not rely only on the script names.

## Final response

Provide:

1. a one-paragraph incident summary;
2. the suspicious process chain;
3. the staged file and hash;
4. the external destination;
5. the benign look-alikes and why they differ;
6. an escalation recommendation;
7. one or more evidence gaps.
