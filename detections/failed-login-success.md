# Detection: Multiple Failed Logons Followed by Success

| Field | Value |
|---|---|
| **Name** | Multiple Failed Logons Followed by Success |
| **Purpose** | Detect brute-force or credential-guessing attacks that end in a successful compromise |
| **Data source** | Security 4625 (failed logon), 4624 (successful logon) |
| **MITRE ATT&CK** | T1110 (Brute Force), T1110.001 (Password Guessing), T1078 (Valid Accounts) |

## Detection Logic

```spl
index=windows source="WinEventLog:Security" EventCode=4625
| eval user=mvindex(Account_Name,-1)
| bucket _time span=5m
| stats count as fail_count, earliest(_time) as first_fail, latest(_time) as last_fail by user, _time
| where fail_count >= 3
| join user [
    search index=windows source="WinEventLog:Security" EventCode=4624
    | eval user=mvindex(Account_Name,-1)
    | eval success_time=_time
    | table user, success_time
  ]
| where success_time > last_fail AND success_time < last_fail + 300
| table user, fail_count, first_fail, last_fail, success_time
```

## Expected Result

One row per compromised account: three or more failed logons within a
5-minute window, followed by a successful logon for the same account
within 5 minutes of the last failure.

## False Positives

A legitimate user mistyping their own password multiple times before
succeeding; a service or script retrying a stale/rotated credential before
it is updated, then succeeding once the credential refreshes. Analysts
should check `Logon_Type` (interactive vs. network), whether the timing is
consistent with the account owner's normal activity, and whether MFA or
other context makes the pattern expected rather than anomalous.

## Investigation Steps

1. Confirm `Logon_Type` for both the failures and the success (3 = network,
   2 = interactive, etc.).
2. Review `Workstation_Name` and `Source_Network_Address`, with the caveat
   that NTLM-authenticated logons on non-domain-joined hosts frequently do
   not populate these reliably (see Lessons Learned).
3. Determine if the successful session performed any further action
   (4688/Sysmon Event 1 under the same `Logon_ID`).
4. Check whether account lockout policy is enabled; if not, this is itself
   a gap worth flagging.

## Recommended Response

Reset the compromised account's password, enforce a strong password policy,
enable account lockout after a small number of failures, and review
post-compromise activity under that session.

## Validation Notes

Generated via NetExec (`nxc smb <target> -u svc-backup -p <wordlist>`)
against a dedicated low-privilege test account. Produced four failed
logons in under half a second (consistent with automated tooling) followed
by a fifth failure ~27 seconds later and a success ~36 seconds after that.

A significant telemetry limitation was identified during validation: both
the failed and successful logon events recorded `Source_Network_Address`
as the Windows host's own IP address rather than the true attacking
machine's address, and `Workstation_Name` was blank throughout — a known
limitation of NTLM logon auditing on non-domain-joined hosts. Sysmon Event
ID 3 (Network Connection) was checked as a potential corroborating source
and found to not capture the inbound SMB traffic at all, since the default
Sysmon configuration excludes common file-sharing ports from network
logging. In this lab configuration, Security 4625/4624 was the *only*
telemetry source that detected the attack, and even it could not reliably
confirm the true origin address — a meaningful visibility gap documented
further in `docs/lessons-learned.md`.

See full incident narrative: [`investigations/INC-001-brute-force.md`](../investigations/INC-001-brute-force.md).

## Evidence

![Source IP attribution quirk for NTLM-authenticated SMB logons](../screenshots/29-source-ip-quirk.png)
*Every failed logon recorded the Windows host's own address instead of the true attacker IP — a known NTLM auditing limitation on non-domain hosts.*

![Sysmon network visibility gap during the same attack window](../screenshots/29-source-ip-quirk-sysmon-gap.png)
*Sysmon Event ID 3 logged other traffic during this exact window but captured zero events for the inbound SMB connection — the default config excludes file-sharing ports from network logging.*
