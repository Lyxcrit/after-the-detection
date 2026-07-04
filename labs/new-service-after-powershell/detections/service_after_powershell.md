# Detection Idea: Service Creation After Suspicious PowerShell

## Goal

Identify a higher-confidence pattern where suspicious PowerShell activity is followed by Windows service creation on the same host.

## Behavior modeled

The lab models this sequence:

1. User launches PowerShell with suspicious flags.
2. PowerShell stages content in a user-writable path.
3. `sc.exe` creates a new service.
4. The service starts and executes a binary from the staged path.
5. The process makes outbound network connections.

## Why it matters

This analytic is more useful than either signal alone.

Suspicious PowerShell can be noisy.

New service creation can be legitimate.

But suspicious PowerShell followed by new service creation creates a stronger investigation path.

## Analyst context to include

- suspicious PowerShell command line
- service name and binary path
- time delta between PowerShell and service creation
- account context
- process lineage
- host history
- outbound network activity after service start
- change ticket or ownership context, if available

## Escalation guidance

Escalate when the sequence lacks an approved change and includes one or more of:

- encoded or bypass PowerShell execution
- service binary in a user-writable path
- unexpected account creating the service
- first-seen external destination
- related authentication or lateral movement activity
