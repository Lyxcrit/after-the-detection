# Lab Format

Each After the Detection lab should follow the same basic structure so the content is easy to compare, reuse, and expand.

## Required sections

1. Summary
2. Scenario assumptions
3. Synthetic telemetry files
4. ATT&CK mapping
5. Data sources
6. Detection ideas
7. Investigation timeline
8. Analyst pivots
9. Response notes
10. Escalation criteria

## Design principles

- Keep the data synthetic.
- Keep the scenario small enough to understand.
- Focus on the investigation path, not just the detection.
- Show what happened before and after the alert.
- Include supporting evidence that may not deserve its own notable.
- Explain what an analyst should validate.
- Include enough SIEM detail to be useful without tying the lab to only one platform.

## Recommended lab folder structure

```text
labs/<lab-name>/
├── README.md
├── data/
│   ├── windows_security.csv
│   ├── sysmon_process.csv
│   ├── powershell_operational.csv
│   ├── service_control_manager.csv
│   └── dns_proxy.csv
├── detections/
│   ├── suspicious_powershell.md
│   ├── new_service_creation.md
│   └── service_after_powershell.md
├── investigation/
│   ├── timeline.md
│   ├── analyst_pivots.md
│   ├── response_notes_template.md
│   └── escalation_criteria.md
└── splunk/
    ├── sample_spl.md
    └── field_mapping.md
```

## Public language

Use language such as:

> This lab uses synthetic telemetry modeled from common behavior patterns. It is not real customer data or evidence from a specific incident.

Avoid language such as:

> This is what the attacker did.

Unless the lab is explicitly based on verified public reporting and cites the source.
