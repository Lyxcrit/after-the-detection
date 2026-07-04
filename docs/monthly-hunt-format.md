# Monthly Hunt Format

After the Detection Monthly Hunts are synthetic, platform-portable hunt packages based on defender-relevant attack patterns.

The point is not just to fire a detection.

The point is to answer:

> The detection fired. Now what?

## Monthly hunt objectives

Each monthly hunt should help defenders:

- understand a current or relevant attack pattern
- load synthetic data into their tool of choice
- test detection ideas
- build a timeline
- scope affected entities
- practice analyst pivots
- review response decision points
- see how Splunk/APT Falconer could showcase the workflow

## Required sections

Each monthly hunt should include:

```text
README.md
threat-brief.md
attack-narrative.md
coverage-map.md
data-dictionary.md
splunk-ingest-guide.md
sample-spl.md
analyst-hunt-guide.md
response-plan.md
apt-falconer-showcase.md
falconsearch-notes.md
linkedin-content.md
```

## Required data categories

Each real monthly hunt should include multiple telemetry perspectives, not just one host event.

Recommended CSV files:

```text
data/
├── endpoint_process.csv
├── endpoint_file.csv
├── endpoint_service.csv
├── identity_auth.csv
├── dns.csv
├── proxy.csv
├── firewall.csv
├── asset_inventory.csv
├── detection_results.csv
└── investigation_findings.csv
```

## Design principle

A useful monthly hunt should include:

- normal background activity
- suspicious activity
- related weak signals
- false leads or benign context
- the real synthetic attack path
- enough entity data to scope the activity

A toy dataset says:

> Here is a suspicious event. Find it.

A monthly hunt says:

> Here is the kind of attack defenders are seeing. Here is the data. One alert fired. Now prove what happened, scope it, and decide what to do next.

## Current hunt candidate

The first real monthly hunt is:

> Hunt 001: Edge Exploitation to Persistence

It should model:

1. suspicious inbound traffic to an exposed service
2. shell-like child process execution
3. script or payload staging
4. persistence through service or scheduled task
5. rare outbound destination
6. identity activity that may indicate scoping or lateral movement
7. analyst decision-making after initial detection
