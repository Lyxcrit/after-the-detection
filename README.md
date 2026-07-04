# After the Detection Labs

Public, synthetic detection-engineering labs for exploring what happens **after** an alert fires.

This repository supports the **After the Detection** series: practical notes, mock telemetry, investigation paths, and detection workflow examples for SOC, DCO, threat hunting, and SIEM teams.

## What this is

This repo is a public place for safe, repeatable detection labs. Each lab is designed to show:

- the scenario being modeled
- the mock telemetry that would support the investigation
- the detections or analytics a SIEM team may want to build
- the analyst pivots that matter after the alert fires
- response notes and escalation criteria
- how context turns an alert into an investigation

## What this is not

This repository does **not** contain customer data, victim data, real incident data, or proprietary environment exports.

The data in this repo is synthetic and intentionally simplified. It is meant for education, detection-engineering practice, and SOC workflow discussion.

## First lab

The first lab models a common investigation pattern:

> Suspicious PowerShell activity followed by new Windows service creation.

Start here:

- [Lab: New Service After PowerShell](labs/new-service-after-powershell/README.md)

## Why mock data?

Mock data lets defenders safely practice the workflow without exposing real environments. The goal is not to pretend synthetic telemetry is real. The goal is to demonstrate how an analyst can move from alert to understanding.

## After the Detection principle

A detection is not finished when it fires.

The alert is the beginning of the workflow. The value comes from what happens next:

- context
- pivots
- timeline
- scope
- entity behavior
- response notes
- escalation decisions
- analyst understanding

## License and use

Use these labs for learning, internal workshops, demo environments, and detection-engineering discussions. If you reuse the material publicly, please link back to this repository.
