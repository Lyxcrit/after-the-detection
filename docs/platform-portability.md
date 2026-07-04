# Platform Portability

After the Detection labs are designed to be platform-portable.

The synthetic telemetry should be usable in the SIEM, data lake, security analytics platform, notebook, or lab environment of your choice.

## Core idea

The data is the community artifact.

The showcase is one way to demonstrate the investigation experience.

That means:

- CSV data should be easy to ingest anywhere.
- Field names should be documented.
- Detection ideas should be written generically first.
- Platform-specific examples should be optional helpers.
- Splunk and APT Falconer walkthroughs should be positioned as examples, not requirements.

## Suggested public language

> The data is platform-portable. Load it into the SIEM or analytics tool of your choice. Splunk and APT Falconer examples are included as one way to demonstrate how detections become investigations.

## Supported paths

Initial support focuses on:

- CSV files
- documented field dictionaries
- generic detection coverage maps
- Splunk ingest/search examples
- APT Falconer investigation showcases

Future examples may include Elastic, Sentinel, Datadog, Security Onion, DuckDB, and Python notebooks.

## Why CSV

CSV is intentionally boring. That is the point.

A simple format allows defenders to:

- ingest the data into Splunk
- import it into Elastic
- load it into Sentinel
- analyze it in Python
- query it with DuckDB
- review it in a spreadsheet
- adapt it for internal demos

## Separation of concerns

Each lab should separate portable artifacts from platform-specific helpers.

```text
labs/<lab-id>/
├── data/          # portable CSV telemetry
├── schema/        # field dictionaries and entity model
├── detections/    # generic detection coverage ideas
├── platforms/     # optional platform helpers
├── showcase/      # Splunk/APT Falconer/FalconSearch demo notes
└── investigation/ # analyst pivots, timeline, response notes
```

## APT Falconer positioning

APT Falconer is not required to use the data.

It is used as a showcase for the bigger question:

> The detection fired. Now what?

The showcase should demonstrate how context, pivots, timeline, ATT&CK behavior, analyst notes, and response decisions can come together after the alert fires.
