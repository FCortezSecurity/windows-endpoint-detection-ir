# Detection: Suspicious Parent/Child Process Relationship & Binary Masquerading

| Field | Value |
|---|---|
| **Name** | (1) Binary Identity Masquerading &nbsp;&nbsp; (2) Office-to-Shell Parent/Child Relationship |
| **Purpose** | Detect a process whose on-disk filename does not match its compiled binary identity, and/or an Office-class application spawning a shell/script interpreter — both common indicators of malicious document execution or dropper activity |
| **Data source** | Sysmon Event ID 1 (Process Creation): `Image`, `OriginalFileName`, `ParentImage`, `CommandLine` |
| **MITRE ATT&CK** | T1036 / T1036.003 (Masquerading: Rename System Utilities), T1059.001 (PowerShell) |

## Detection Logic

**Masquerading (binary identity mismatch):**

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where isnotnull(OriginalFileName) AND OriginalFileName!="-"
| eval image_name=lower(replace(Image, ".*\\\\", ""))
| eval claimed_name=lower(if(match(OriginalFileName, "\.[a-zA-Z0-9]+$"),
        OriginalFileName, OriginalFileName+".exe"))
| where image_name!=claimed_name
| where NOT match(Image, "(?i)SplunkUniversalForwarder|EdgeUpdate|SoftwareDistribution|UsoClient")
| table _time, Image, OriginalFileName, ParentImage, User
```

**Suspicious parent/child relationship:**

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(lower(ParentImage), "winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe")
| where match(lower(Image), "powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|mshta\.exe")
| table _time, ParentImage, Image, CommandLine, User
```

## Expected Result

Masquerading query: any process where the on-disk filename and the
compiled `OriginalFileName` metadata disagree. Parent/child query: any
instance of an Office application directly spawning a shell or script
interpreter — a pairing that essentially never occurs during normal
application use.

## False Positives

The masquerading detection has a non-trivial false-positive surface on a
stock Windows system: several first-party Windows components (WMI
handlers, the logon reminder dialog, IIS verification tools, Windows
Update components) are legitimately compiled with an internal name that
differs from their deployed filename. A tuned version must exclude known
system paths/binaries or rely on an allowlist; even then, a long tail of
legitimate exceptions should be expected (see full false-positive
iteration history in `investigations/INC-002-masquerading-parentchild.md`).

The parent/child detection has a much smaller false-positive surface,
since Office applications legitimately spawning `powershell.exe`, `cmd.exe`,
or script interpreters is rare outside of IT-managed macro-based automation
(which, if present, should be explicitly allowlisted by process path/hash).

## Investigation Steps

1. For a masquerading hit: check the file's actual location (a renamed
   system binary outside its normal install path, e.g., `System32`, is far
   more suspicious than one found in its expected location).
2. Hash the binary (Sysmon's `Hashes` field) and check against known-good
   baselines or threat intelligence.
3. For a parent/child hit: review the full `CommandLine` of the child
   process for further indicators (encoded commands, download cradles,
   obfuscation).
4. Check what the child process did next — network connections, file
   writes, further process creation.

## Recommended Response

Terminate the suspicious process tree, isolate the host if malicious intent
is confirmed, preserve the binary and its hash for analysis, and review the
delivery vector (if Office-related, check for a malicious attachment or
macro as the likely source).

## Validation Notes

Both detections were validated against a single simulated incident: a copy
of `cmd.exe` renamed to `WINWORD.EXE`, used to spawn real `powershell.exe`
as a child process. The masquerading detection required three tuning
iterations (17 → 2 → 1 false positives) to reach a usable state, each
iteration driven by a genuine Windows telemetry quirk rather than a logic
error (sentinel `"-"` values, legitimate installer renaming, missing file
extensions in some system binaries' metadata). The parent/child detection
was clean on the first attempt. This asymmetry is itself a useful finding:
behavioral/relationship-based detections can be considerably more precise
than identity/metadata-based ones for some technique categories, and
pairing both approaches against the same incident provides defense in
depth — an attacker evading one detection method (e.g., not renaming the
binary) would still be caught by the other.

See full incident narrative, including the complete false-positive
iteration history:
`investigations/INC-002-masquerading-parentchild.md`.
See screenshots: `38-scenario4-process-chain.png`,
`39a-masquerading-detection-v1-false-positives.png`,
`39b-masquerading-detection-v2-partial-fix.png`,
`39c-masquerading-detection-v3-final.png`,
`40-scenario4-parentchild-detection.png`.
