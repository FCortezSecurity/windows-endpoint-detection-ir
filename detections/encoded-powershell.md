# Detection: Encoded PowerShell Execution

| Field | Value |
|---|---|
| **Name** | Encoded PowerShell Execution |
| **Purpose** | Detect obfuscated PowerShell commands that evade plain-text command-line inspection |
| **Data source** | Security 4688, Sysmon Event ID 1 (process command line); PowerShell Operational 4104 (decoded script block) |
| **MITRE ATT&CK** | T1059.001 (Command and Scripting Interpreter: PowerShell), T1027 (Obfuscated Files or Information) |

## Detection Logic

Flag any process creation where the command line contains `-EncodedCommand` (or
its abbreviations `-enc`, `-e`). The process-level event only shows the
Base64 blob; correlate with the matching PowerShell Operational 4104 event
(same host, near-identical timestamp) to recover the actual decoded script.

```spl
index=windows (EventCode=4688 OR EventCode=1)
| eval cmd=coalesce(CommandLine, Process_Command_Line)
| where match(cmd, "(?i)-enc(odedcommand)?\s")
| eval parent=coalesce(ParentImage, Creator_Process_Name)
| table _time, source, cmd, parent
```

To pull the decoded content once a suspicious encoded execution is found:

```spl
index=windows EventCode=4104 Message="*<keyword from decoded script>*"
| table _time, Message
```

## Expected Result

One process-creation hit per execution (duplicated across Security and
Sysmon), correlated to one 4104 event containing the fully decoded script
text.

## False Positives

Legitimate automation, deployment tools, and some enterprise software use
`-EncodedCommand` as a safe way to pass scripts containing quotes or special
characters through the command line without escaping issues. The mere
presence of `-EncodedCommand` is not inherently malicious; the decoded
content and context (parent process, network activity following execution,
account used) determine intent.

## Investigation Steps

1. Pull the matching 4104 event to recover the decoded script content.
2. Check `ParentImage` / `Creator_Process_Name` for how PowerShell was
   launched (interactive session vs. another process).
3. Check the acting `User` and whether this matches expected administrative
   activity.
4. Look for follow-on activity: file writes (Sysmon 11), network connections
   (Sysmon 3), or further process creation in the same session.

## Recommended Response

Review the decoded content for malicious intent. If confirmed malicious,
isolate the host, reset any credentials used in the session, and inspect
for persistence mechanisms (scheduled tasks, registry run keys, new
services).

## Validation Notes

Tested by generating an encoded `Write-Output` / `Invoke-WebRequest` /
`New-Item` payload (`scenario2-marker`). The process-level view
(Security 4688 and Sysmon Event 1) showed only the opaque Base64 string in
both sources; the PowerShell 4104 event independently reconstructed the
full, readable script, confirming Windows' built-in script block logging
defeats this specific obfuscation technique regardless of the attacker's
encoding choice.

A secondary finding during testing: 4104 logs *all* PowerShell activity,
including legitimate administrative commands run by the analyst
(e.g., `Add-LocalGroupMember`). A production detection must pattern-match
on the encoding indicator itself, not merely the presence of a 4104 event.

See screenshots: `30-encoded-command-process.png`,
`31-encoded-command-decoded-4104.png`, `32-sysmon-4104-noise-baseline.png`,
`33-encoded-powershell-detection-query.png`.
