# Lessons Learned

This document captures the real technical problems encountered while
building this lab and the findings generated while testing detections
against real telemetry. Each entry reflects something actually diagnosed
and fixed during this project, not a hypothetical.

## Environment & Infrastructure

### Sysmon events silently failed to reach Splunk (access denied)
**Symptom:** All other log sources (Security, System, PowerShell) forwarded
correctly, but the Sysmon channel produced zero events in Splunk despite
Sysmon itself logging normally on the endpoint.
**Diagnosis:** `splunkd.log` showed `errorCode=5` (access denied) when the
forwarder attempted to subscribe to the `Microsoft-Windows-Sysmon/Operational`
channel.
**Root cause:** The Splunk Universal Forwarder service runs as the virtual
account `NT SERVICE\SplunkForwarder`, which is not automatically granted
read access to every Windows Event Log channel — Sysmon's channel has its
own access control list, separate from the built-in Security/System/
Application logs.
**Fix:** Retrieved the forwarder's service SID (`sc.exe showsid
SplunkForwarder`) and added it to the Sysmon channel's ACL with read-only
access via `wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:"..."`.
Verified with `wevtutil gl` and confirmed resolution by restarting the
forwarder and observing Sysmon events appear in Splunk within minutes.
**Takeaway:** Not every event channel grants the same default read
permissions to the same accounts. When a forwarder reads some channels but
not others, check the specific channel's ACL rather than assuming a
forwarder-wide permission issue.

### VM and host clocks disagreed by exactly the timezone offset
**Symptom:** Splunk's `_time` field was correct, but the raw event text
embedded in each log entry showed a time two hours earlier.
**Root cause:** The VM was set to Pacific time while the Splunk host was
set to Central time. Splunk correctly normalized `_time` to UTC-equivalent
truth, but the *raw text* of each event remained in the VM's local
timezone, creating a confusing mismatch between the two.
**Fix:** `Set-TimeZone -Id "Central Standard Time"` on the VM to match the
host, then restarted the forwarder.
**Takeaway:** `_time` being correct does not mean the raw log text will
read cleanly in an investigation timeline. For any multi-machine lab,
match timezones explicitly before generating evidence, not after.

### SMB connectivity from the attacker VM was blocked despite a seemingly correct firewall rule
**Symptom:** A firewall rule scoped to allow TCP 445 from the Kali VM's IP
was created and enabled, but `nmap` still reported port 445 as `filtered`.
**Root cause:** The host-only network adapter was classified by Windows as
a **Public** network profile. Several default SMB/File-and-Printer-Sharing
rules are scoped to Domain/Private profiles only and remain disabled on
Public, regardless of custom rules added alongside them.
**Fix:** Reclassified the host-only adapter as **Private**
(`Set-NetConnectionProfile -NetworkCategory Private`) and enabled the
built-in File and Printer Sharing rule group.
**Takeaway:** A custom allow rule does not override the network profile's
baseline posture. Check `Get-NetConnectionProfile` early when a
seemingly-correct firewall rule doesn't behave as expected.

### WMI/DCOM-based remote execution failed with `rpc_s_access_denied`
**Symptom:** SMB authentication against the Windows VM succeeded
consistently (including with administrator credentials), but every
WMI-based remote execution method (`wmiexec`, `mmcexec`, both via NetExec
and Impacket directly) failed with `rpc_s_access_denied`.
**Root cause:** SMB access and WMI/DCOM access are governed by separate
Windows service surfaces. The lab firewall only permitted inbound SMB
(445) from the attacker VM; RPC/DCOM (port 135 plus a dynamic high port
range) was never opened.
**Resolution:** Rather than opening the broader RPC/DCOM port range (which
would have required a wider, less realistic firewall posture for a
"single service exposed" lab), the encoded PowerShell payload was executed
directly on the Windows VM instead. The resulting telemetry (Sysmon Event
1, Security 4688, PowerShell 4104) is identical regardless of whether the
process creation was triggered locally or via remote WMI execution, since
from the endpoint's perspective a new process is a new process either way.
**Takeaway:** Valid credentials and SMB access do not imply remote code
execution capability. This is itself a useful detection boundary to
understand: an environment that locks down RPC/DCOM while allowing SMB
authentication meaningfully reduces an attacker's lateral movement options
even after credential compromise.

### Account and host shared the same name, creating log ambiguity
**Symptom:** Early Security events showed `Account Name: WIN-LAB-01` in
both the "creator" and "new account" fields of certain events, which was
confusing to read — was this referring to the computer or a user?
**Root cause:** The only enabled local user account on the VM was named
identically to the computer itself (`WIN-LAB-01`), a leftover from
accepting Windows Setup's default account name.
**Fix:** Created a dedicated `lab-user` account, migrated to it, and
disabled the original `WIN-LAB-01` account.
**Takeaway:** Naming conventions that seem harmless during setup can
materially reduce the clarity of an incident timeline later. Establish
clear account naming before generating any telemetry intended for
analysis.

## Telemetry Gaps & Attribution Limits

### `Source_Network_Address` did not reflect the true attack origin
**Finding:** During the brute-force scenario (Security 4625/4624), every
event recorded `Source_Network_Address` as the Windows host's own
host-only adapter IP, and `Workstation_Name` as blank — not the actual
attacking VM's address.
**Explanation:** This is a documented limitation of NTLM-authenticated
logon auditing on non-domain-joined Windows hosts; the field is not always
populated with the true remote peer's address for this authentication
type.
**Mitigation used:** Correlated timing against the attacker-side command
history and lab network topology (only one other host existed on the
network) to establish attribution with confidence, since direct field-based
attribution was unreliable.
**Takeaway:** Do not treat `Source_Network_Address` as ground truth for
NTLM/SMB authentication events on non-domain hosts. Cross-reference with
other sources (network-layer logging, firewall logs, or out-of-band
knowledge of the environment) when attribution matters.

### Sysmon's default configuration does not log inbound SMB network connections
**Finding:** Sysmon Event ID 3 (Network Connection) was active and
correctly logging other traffic (outbound HTTPS, local NetBIOS broadcasts)
during the exact window of the brute-force attack, but recorded zero
events for the inbound SMB connection from the attacking VM.
**Explanation:** The SwiftOnSecurity community Sysmon configuration
deliberately excludes common file-sharing ports from network connection
logging, since this traffic is extremely high-volume and noisy on real
production networks.
**Impact:** In this lab's configuration, Windows Security logs were the
*only* telemetry source that detected the brute-force attack at all — a
single point of coverage with no corroborating source.
**Recommendation:** A production deployment should either tune Sysmon's
`<NetworkConnect>` rules to include sensitive inbound ports (135, 139, 445,
3389, 5985) despite the added volume, or deploy a dedicated network-layer
monitoring tool (Zeek, Suricata) to close this specific visibility gap.
This directly informs this project's V2 roadmap.

### Filename-vs-metadata masquerading detection has a long tail of legitimate exceptions
**Finding:** An initial masquerading detection (comparing a process's
on-disk filename against its compiled `OriginalFileName` metadata)
produced 17 false positives on a stock, idle Windows 10 VM. After three
rounds of tuning, the detection was narrowed to catch the one true
positive in a 15-minute window, but widening the search window to 60
minutes surfaced four *additional* legitimate mismatches not seen before
(WMI components, a logon reminder dialog, an IIS registration verifier).
**Root causes identified:**
- Some processes report `OriginalFileName` as a literal `"-"` string
  rather than a true null/empty value, which must be explicitly excluded.
- Legitimate Microsoft installer and update packages intentionally ship
  with an `OriginalFileName` different from their public-facing filename
  (e.g., a Windows Update component with internal name `mrtstub.exe`).
- Some first-party Windows system binaries have `OriginalFileName` values
  with no file extension at all (e.g., `UsoClient`), breaking a naive
  string-equality comparison.
**Takeaway:** This class of detection (identity/metadata mismatch) will
always have a non-trivial, evolving false-positive surface on a real
Windows system, because many legitimate first-party components are
compiled with internal names that differ from their deployed filename. A
production rule needs either a maintained allowlist of known-legitimate
system binaries, or a corroborating signal (unusual file path, unsigned
binary, unexpected parent process) — it should not be deployed as a
standalone high-confidence alert based on filename comparison alone.

### Every new local account is auto-enrolled in the "Users" group
**Finding:** Every account creation (4720) was accompanied by an automatic
4732 event adding the account to the built-in "Users" group, regardless of
whether the account creation was legitimate or simulated-malicious.
**Takeaway:** A detection for "account added to a group shortly after
creation" is unusable without excluding the Users group specifically,
since it fires on literally every account creation on the system. Only
escalation to a genuinely privileged group (Administrators, Remote Desktop
Users, etc.) is a meaningful signal.

### Command-line arguments expose plaintext credentials in logs
**Finding:** Commands such as `net user <name> <password> /add` place the
password in plain text in both the Security 4688 `Process_Command_Line`
field and the Sysmon `CommandLine` field, fully visible to anyone with
read access to these logs.
**Takeaway:** This is both a detection opportunity (such commands are a
real indicator of local account creation activity, T1136.001) and a
genuine operational risk: centralized logging infrastructure must itself
be access-controlled, since it can become a credential-harvesting target
in its own right. Interactive credential prompts
(`Read-Host -AsSecureString`, or `net user <name> *`) avoid this exposure
and were used for this lab's own legitimate account setup specifically to
avoid the same issue.

### PowerShell Script Block Logging (4104) captures everything, including the analyst's own activity
**Finding:** While reviewing 4104 events for a simulated attack, legitimate
administrative commands run by the analyst during normal lab setup (e.g.,
`Add-LocalGroupMember`) appeared mixed into the same event stream.
**Takeaway:** 4104 is a powerful source precisely because it is
comprehensive, but that comprehensiveness means detections built on it
must pattern-match for specific indicators (encoding, known-malicious
cmdlets, suspicious syntax) rather than treating the mere presence of a
4104 event as meaningful on its own.

## Summary

The most valuable lessons in this project came from false positives and
failed tool executions, not from clean successes. Every "my detection
didn't work the first time" or "this telemetry source didn't capture what
I expected" moment above represents a real limitation an analyst would
need to understand and account for in a production environment — which is
the core skill this project set out to build.
