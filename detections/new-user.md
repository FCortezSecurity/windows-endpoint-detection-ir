# Detection: New Local Account Creation

| Field | Value |
|---|---|
| **Name** | New Local Account Creation |
| **Purpose** | Detect creation of new local user accounts, a common precursor to persistence or privilege escalation |
| **Data source** | Security 4720 (account created), 4722 (account enabled), 4724 (password set); Sysmon Event ID 1 (`net.exe` / `net1.exe` process activity) |
| **MITRE ATT&CK** | T1136.001 (Create Account: Local Account) |

## Detection Logic

```spl
index=windows source="WinEventLog:Security" EventCode=4720
| eval Actor=mvindex(Account_Name,0), Target=mvindex(Account_Name,-1)
| table _time, Actor, Target
```

Pair with the process-level view to see exactly how the account was created:

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
  (Image="*\\net.exe" OR Image="*\\net1.exe") CommandLine="*user*/add*"
| table _time, Image, CommandLine, ParentImage, User
```

## Expected Result

A 4720 event naming the creator (`Actor`) and the new account (`Target`),
typically accompanied within milliseconds by 4722 (enabled) and 4724
(password set). At the process level, `net.exe` hands off to `net1.exe`,
both carrying the full command including the account name and (if supplied
on the command line) the password in plain text.

## False Positives

Legitimate account provisioning by an administrator — setting up a new
employee, a service account, or a lab account (as happened multiple times
during this project's own setup) — produces an identical event pattern.
Account creation alone is not a reliable standalone indicator; it must be
combined with other signals (see `privileged-group-change.md`) such as
immediate escalation to a privileged group, an unexpected actor, or an
account name designed to blend in with existing naming conventions.

## Investigation Steps

1. Identify the creating account (`Actor`) and confirm whether that account
   or person is authorized to provision new accounts.
2. Check the new account's name for suspicious patterns: generic names,
   names mimicking service accounts, or names close to existing accounts.
3. Check whether the account was subsequently added to a privileged group
   (4732) — see the companion detection.
4. Review command-line history for the plaintext password, and treat any
   captured credential as potentially exposed.

## Recommended Response

If unauthorized: disable the new account immediately, review the creating
account's recent activity for compromise, and rotate the creating account's
credentials. If the password was visible in logs, treat it as compromised
regardless of outcome.

## Validation Notes

Generated during Phase 2 (`test-user`, legitimate baseline) and again during
Scenario 3 (`backup-svc2`, simulated malicious). Both produced identical
event structure, confirming that event type alone cannot distinguish intent
— see `privileged-group-change.md` for the detection that adds the
distinguishing signal (timing between creation and privilege escalation).

A notable finding: `net user <name> <password> /add` places the password in
plain text in both the Security 4688 command line and the Sysmon
`CommandLine` field, visible to anyone with log read access. This is a
real exposure worth flagging in hardening recommendations, independent of
whether the account creation itself was malicious.

See screenshots: `21-account-creation-baseline.png`,
`25-net-user-security-events.png`, `26-net-user-sysmon.png`.
