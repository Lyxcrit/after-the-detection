# Showcase Model

After the Detection labs separate the portable hunt package from the platform-specific showcase.

## Portable lab

The portable lab includes:

- synthetic CSV telemetry
- field dictionary
- attack narrative
- generic detection ideas
- analyst hunt guide
- response plan

Anyone should be able to use this material in the tool of their choice.

## Splunk showcase

The Splunk showcase should demonstrate:

- how to ingest the CSVs
- suggested sourcetypes
- sample SPL
- detection coverage
- timeline construction
- entity scoping
- risk/notable-style thinking

The Splunk examples are helpers, not requirements.

## APT Falconer showcase

APT Falconer should demonstrate the investigation experience after the first detection fires.

The showcase should answer:

- What fired?
- Why did it matter?
- What happened before?
- What happened after?
- What entities are involved?
- What techniques are represented?
- What pivots should the analyst take next?
- What evidence supports escalation?
- What response notes should be captured?

## FalconSearch showcase

FalconSearch should be framed as the execution and scale layer.

The showcase should explain how reusable detection-ready data surfaces could help with:

- faster investigations
- broader coverage
- repeatable pivots
- reduced duplicated search effort
- consistent access to relevant telemetry

## Public positioning

Use this language:

> The lab data is platform-portable. I am showcasing it in Splunk with APT Falconer because that is the investigation workflow I have been building toward.

Avoid this language:

> You need APT Falconer to use this lab.

The public value is the data and investigation model. The product value is showing that a better workflow already exists.
