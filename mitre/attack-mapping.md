# MITRE ATT&CK Mapping

This document maps every technique simulated and detected in this project
to its corresponding MITRE ATT&CK technique ID, with a short explanation of
*why* the observed activity maps to that technique rather than just citing
the ID.

| Scenario | Technique ID | Technique Name | Why it maps |
|---|---|---|---|
| 1. Brute Force | **T1110** | Brute Force | Multiple automated authentication attempts against a single account using a password list |
| 1. Brute Force | **T1110.001** | Brute Force: Password Guessing | The specific sub-technique observed — distinct plaintext passwords submitted in sequence, not a hash-cracking or spraying-across-accounts pattern |
| 1. Brute Force | **T1078** | Valid Accounts | Once the brute force succeeded, the attacker (simulated) held legitimate, valid credentials usable for any further action under that account's privileges |
| 2. Encoded PowerShell | **T1059.001** | Command and Scripting Interpreter: PowerShell | PowerShell was the execution vector for the simulated payload |
| 2. Encoded PowerShell | **T1027** | Obfuscated Files or Information | The `-EncodedCommand` flag renders the actual script content unreadable at the process-command-line level, a direct obfuscation technique |
| 3. New Account + Privilege Escalation | **T1136.001** | Create Account: Local Account | A new local Windows account was created as the persistence foothold |
| 3. New Account + Privilege Escalation | **T1098** | Account Manipulation | The newly created account was immediately modified (added to a privileged group) to expand its access beyond its default state |
| 4. Masquerading / Parent-Child | **T1036** | Masquerading | A binary was deliberately renamed to impersonate a trusted, expected application name |
| 4. Masquerading / Parent-Child | **T1036.003** | Masquerading: Rename System Utilities | Specifically, a system utility (`cmd.exe`) was renamed to impersonate a different trusted application (`WINWORD.EXE`) |
| 4. Masquerading / Parent-Child | **T1059.001** | Command and Scripting Interpreter: PowerShell | The masqueraded binary's ultimate purpose was launching PowerShell as a child process |
| 4. Masquerading / Parent-Child | **T1566** | Phishing *(context only — not directly executed)* | Noted as the typical real-world delivery mechanism that would produce this exact process lineage (a malicious Office document with a macro); this project tested the resulting process behavior rather than the delivery vector itself |
| 5. Scheduled Task Persistence | **T1053.005** | Scheduled Task/Job: Scheduled Task | A Windows Scheduled Task was created as a persistence mechanism, configured with a logon trigger to survive reboots and re-execute on every user logon |

## Cross-Cutting Observations

- **T1078 (Valid Accounts)** is relevant beyond Scenario 1: every later
  scenario was executed using either the compromised `svc-backup` account's
  context (conceptually) or the administrator-level `lab-user` account,
  illustrating how an initial valid-account foothold (Scenario 1) enables
  every subsequent stage of a real intrusion (Scenarios 2-5).
- **T1027 (Obfuscation)** and **T1036 (Masquerading)** are closely related
  defense-evasion techniques observed in this project: one hides the
  *content* of an action (Scenario 2), the other hides the *identity* of
  the actor performing it (Scenario 4). A mature detection program should
  cover both categories rather than assuming one implies coverage of the
  other.
- No single detection source in this lab caught every technique in
  isolation. Security event logs, Sysmon process telemetry, and PowerShell
  script block logging each contributed unique, non-overlapping coverage
  (see `docs/lessons-learned.md` for the specific gaps identified, such as
  Sysmon's default network-logging blind spot for SMB traffic).

## Reference

Full technique definitions: [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
