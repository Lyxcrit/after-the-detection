# Detection Idea: Suspicious PowerShell Command Line

## Goal

Identify PowerShell execution patterns that may require review, especially when combined with later persistence or outbound network activity.

## Behavior modeled

This lab includes PowerShell using suspicious execution flags and script block behavior:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- encoded command usage
- download-and-execute style behavior
- writing payload-like content to a user-writable directory

## Why it matters

PowerShell is commonly used legitimately. This detection should not be treated as proof of malicious activity by itself.

The value increases when the PowerShell activity is followed by:

- file creation in a user-writable path
- service creation
- suspicious parent/child process relationships
- first-seen outbound network activity

## Analyst context to include

- user
- host
- parent process
- command line
- script block text, when available
- time window around execution
- related process events
- related service creation events
- related network activity

## Escalation guidance

Escalation becomes more justified when suspicious PowerShell is followed by persistence behavior, unusual outbound connections, or execution from non-standard paths.
