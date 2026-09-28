# Analyst Hunt Guide

Start with the LSASS-access detection, but do not decide based on target process alone.

## Pivots

1. Compare all `lsass.exe` access by source process, signer, access mask, parent process, and installed-tool context.
2. Reconstruct `powershell.exe -> rundll32.exe -> comsvcs.dll MiniDump`.
3. Verify whether a dump file was actually created and what touched it next.
4. Compare the suspicious sequence with legitimate `SenseIR.exe` LSASS access.
5. Build the 20-minute identity/network timeline after the dump.
6. Treat successful authentication to `FILE-DEV-03` as a scope lead, not automatic proof of compromise.
7. Remove responder activity from the attacker timeline.

## Decisions

- Is LSASS dumping on `DEV-WS-12` established?
- Which LSASS access is legitimate security tooling?
- Does `FILE-DEV-03` belong in confirmed scope, investigative scope, or neither?
- Which credential claims can you make?
- What do you contain first, and what evidence do you preserve?
