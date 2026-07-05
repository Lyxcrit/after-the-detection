# After the Detection Hunt Series Model

After the Detection is moving from a single monthly-hunt framing to a Hunt Series model.

The weekly hunts are the reps. The monthly capstone is the field exercise.

Each week, I'll publish a small synthetic hunt focused on one part of the investigation. At the end of the month, I'll combine those concepts into a larger capstone hunt with more noise, more ambiguity, and a full after-the-detection workflow.

## How the series works

- Weekly hunts are focused teaching reps.
- Monthly capstones are larger field exercises that check whether the weekly concepts hold up under noisier conditions.
- The goal is still the same: move from an alert to scoped understanding, not just alert acknowledgement.

## Weekly hunts

Weekly hunts should stay tight and practical:

- one investigation slice at a time
- a constrained dataset that supports the teaching objective
- enough noise to force judgment, but not so much that the lesson gets buried
- clear pivots, decision points, and analyst tradeoffs

Weekly hunts are where the repetition happens. They should help defenders build instinct around process lineage, host changes, identity context, network pivots, and escalation decisions.

## Monthly capstones

Monthly capstones should build on the weekly material rather than replace it.

Each capstone should:

- combine the concepts practiced during the month
- add more background activity and ambiguity
- force timeline building across multiple telemetry types
- test whether the analyst can separate signal, noise, and benign response activity

## Hunt 001 positioning

Hunt 001: Edge Exploitation to Persistence should be treated as a guided weekly hunt in the July edge-exploitation arc.

It is not the final monthly capstone. It is the rep that teaches the workflow:

- suspicious child-process execution from an edge host
- follow-on file and service changes
- outbound activity review
- internal scoping questions
- response-context validation

## Platform and showcase notes

The data remains platform-portable.

Splunk examples are practical demonstrations, not requirements. APT Falconer remains a showcase layer for investigation flow, not a dependency for using the hunts.
