# LinkedIn Content — Hunt 002

## Monday Post Theme

PowerShell is not the story. The process tree is.

Hunt 002 — Process Ancestry and Payload Staging — starts with suspicious script execution on `WEB-EDGE-01`. The analyst has to determine what process actually started the chain, which PowerShell activity is malicious, what file was staged, which events are routine administration or software deployment, and whether the evidence supports escalation.

The audience selected **guided, moderate noise**, so this hunt includes legitimate PowerShell, expected file writes, peer-server activity, vulnerability scanning, backup access, deployment activity, and multiple review detections that should not all be escalated.

The goal is to build the habit of asking: who launched it, what did it do next, and what changed because it ran?

## Wednesday Article

**Title:** A Process Name Is Not a Verdict: Why Ancestry Changes the Investigation

**Thesis:** A process name tells us which tool was used. The surrounding relationships tell us what the tool meant in that moment.

The article explains why analysts should pivot backward to parent and grandparent process context, then forward into file writes, network activity, and response notes.

## Wednesday Promo Post

A process name is not a verdict.

Sometimes PowerShell is administration. Sometimes it is software deployment. Sometimes it is attacker execution. The difference is usually in the relationships: who launched it, what launched the parent, which user owned it, what did it create, and what ran next.

This week’s After the Detection article introduces Hunt 002: Process Ancestry and Payload Staging.

#AfterTheDetection #DetectionEngineering #ThreatHunting #SOC #IncidentResponse #CyberSecurity

## Friday Opinion Post

We should stop treating suspicious process names like conclusions.

“PowerShell ran” is not an incident summary. Neither is `cmd.exe` executed, `certutil.exe` was observed, or a DLL appeared under ProgramData.

Those are clues. The verdict comes from the relationships between them.

Question: Which clue most often changes your verdict on suspicious PowerShell?

1. Parent and grandparent process
2. Command line or script block
3. File and network follow-on
4. User and host baseline

#AfterTheDetection #DetectionEngineering #ThreatHunting #SOC #IncidentResponse
