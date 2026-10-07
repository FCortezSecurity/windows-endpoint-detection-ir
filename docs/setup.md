# Setup Guide

This document walks through building the lab environment from scratch,
including the fixes required along the way. Where a step required
troubleshooting during the original build, that fix is included inline so
a fresh build doesn't hit the same issue blind. Full root-cause detail for
each is in `lessons-learned.md`.

## 1. Prerequisites

- A hypervisor: VirtualBox or VMware (this guide uses VirtualBox)
- A Windows 10/11 ISO
- A Kali Linux VM (pre-built VirtualBox image from kali.org/get-kali, or
  your own)
- Host machine with at least 16 GB RAM (6 GB for the Windows VM, 2-4 GB
  for Kali, remainder for Splunk running on the host)

## 2. Windows VM

### Create the VM
- Name: `WIN-LAB-01`
- Type: Microsoft Windows 10/11 (64-bit)
- Memory: 6144 MB (4096 MB minimum)
- Processors: 2
- Disk: 60 GB, dynamically allocated
- **Skip unattended installation** during the wizard, so you control the
  account setup yourself

### Network adapters
- **Adapter 1:** NAT (internet access for downloads/updates)
- **Adapter 2:** Host-only Adapter, same network Kali will join

### Install Windows
- Choose **Windows 10/11 Pro** if offered (Home lacks `gpedit.msc`, though
  this guide uses `auditpol`/registry directly so Home still works)
- Custom install, local account only (disconnect the NAT adapter
  temporarily during setup if it insists on a Microsoft account)

### Avoid an account/hostname naming collision
Do **not** leave the default account name identical to the computer name.
This lab initially did and it created real ambiguity in Security event
logs (see `lessons-learned.md`). Create a clearly-named account instead:

```powershell
$pw = Read-Host -AsSecureString "Password for lab-user"
New-LocalUser -Name "lab-user" -Password $pw -FullName "Lab User" -Description "Primary lab analyst account"
Add-LocalGroupMember -Group "Administrators" -Member "lab-user"
```

Sign in as `lab-user`, confirm it works, then disable any default account
that shares the computer's name:

```powershell
Disable-LocalUser -Name "<original-account-name>"
```

### Static IP on the host-only adapter

```powershell
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.56.10 -PrefixLength 24
```

Allow ping for connectivity testing:

```powershell
New-NetFirewallRule -DisplayName "Lab ICMPv4 In" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -Profile Any
```

### Fix: reclassify the host-only network as Private
Host-only adapters are frequently classified as **Public** by Windows,
which silently blocks several default service rules (SMB among them) even
when custom firewall rules are added:

```powershell
Set-NetConnectionProfile -InterfaceAlias "Ethernet 2" -NetworkCategory Private
```

### Match the VM's timezone to your Splunk host
Mismatched timezones don't break Splunk's internal `_time` field, but they
make raw event text and incident timelines confusing to read:

```powershell
Set-TimeZone -Id "<Your-Timezone-Id>"   # e.g. "Central Standard Time"
```

### Take a baseline snapshot
Shut the VM down and snapshot it before installing any logging agents.
Name it something like `clean-baseline`.

## 3. Audit Policy & PowerShell Logging

Windows does not audit process creation, logon failures, or account
management by default. Enable them explicitly:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

Include the full command line in 4688 events:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
```

Enable PowerShell Script Block Logging:

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
```

Verify:

```powershell
auditpol /get /subcategory:"Process Creation","Logon","User Account Management","Security Group Management","Other Object Access Events"
```

## 4. Sysmon

```powershell
New-Item -ItemType Directory -Path C:\Tools\Sysmon -Force
cd C:\Tools\Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath . -Force
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig-export.xml
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Verify:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## 5. Splunk Enterprise (on your host machine)

1. Download Splunk Enterprise (Windows, 64-bit MSI) from splunk.com.
2. Install with default settings; choose **On-premises Splunk
   Enterprise**; set a strong admin username/password (do not reuse this
   anywhere else in the lab).
3. In Splunk Web (`http://localhost:8000`):
   - **Settings → Indexes → New Index** → name it `windows`
   - **Settings → Forwarding and receiving → Configure receiving → New
     Receiving Port** → `9997`

## 6. Splunk Universal Forwarder (on the Windows VM)

1. Download the Universal Forwarder (Windows, 64-bit MSI).
2. Install with **Local System** as the service account.
3. Set a forwarder admin username/password (different from the Splunk
   admin credentials).
4. At the Receiving Indexer screen, enter your host's host-only IP
   (e.g., `192.168.56.1`) and port `9997`.

Create `inputs.conf`:

```powershell
@"
[WinEventLog://Security]
index = windows
disabled = 0

[WinEventLog://System]
index = windows
disabled = 0

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
index = windows
disabled = 0

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = windows
disabled = 0
renderXml = false
"@ | Set-Content -Path "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf" -Encoding ASCII
```

Restart the forwarder:

```powershell
Stop-Service SplunkForwarder
Start-Sleep 20
Start-Service SplunkForwarder
```

### Fix: Sysmon channel access denied (errorCode=5)
If Security/System/PowerShell logs forward correctly but Sysmon events
never appear in Splunk, check `splunkd.log` for `errorCode=5`. The
forwarder's service account needs explicit read access to the Sysmon
channel's ACL:

```powershell
sc.exe showsid SplunkForwarder
# copy the SERVICE SID from the output, then:
wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ca:"O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x7;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;<your-SplunkForwarder-SID>)"
```

Restart the forwarder again after applying this.

### Open the receiving port on the host firewall

```powershell
New-NetFirewallRule -DisplayName "Splunk Receiver 9997 (Lab)" -Direction Inbound -Protocol TCP -LocalPort 9997 -RemoteAddress 192.168.56.0/24 -Action Allow -Profile Any
```

### Verify end to end
From the VM:

```powershell
Test-NetConnection 192.168.56.1 -Port 9997
```

In Splunk Web, Last 15 minutes:

```spl
index=windows | stats count by host, source
```

You should see all four sources: Security, System, PowerShell, and Sysmon.

### Take a snapshot
Name it `sysmon-baseline-labuser`. This is your reset point before running
any attack scenarios.

## 7. Kali Linux VM

### Network
- **Adapter 1:** NAT
- **Adapter 2:** Host-only Adapter, same network as the Windows VM

### Static IP

```bash
sudo ip addr add 192.168.56.20/24 dev eth1
sudo ip link set eth1 up
```

(This is non-persistent across reboots; make it permanent via NetworkManager
or `/etc/network/interfaces` if you want it to survive a restart.)

### Verify connectivity both directions

```bash
ping -c 4 192.168.56.10          # from Kali
```
```powershell
ping 192.168.56.20               # from the Windows VM
```

### Allow SMB from Kali only

```powershell
New-NetFirewallRule -DisplayName "Lab SMB In (Kali only)" -Direction Inbound -Protocol TCP -LocalPort 445 -RemoteAddress 192.168.56.20 -Action Allow -Profile Any
```

### Create a dedicated low-privilege test target

Don't use your admin account as the brute-force target. Create a separate,
standard-privilege account:

```powershell
$pw = Read-Host -AsSecureString "Password for svc-backup"
New-LocalUser -Name "svc-backup" -Password $pw -Description "Brute-force scenario target account"
```

### Verify SMB is reachable

```bash
sudo nmap -p 445 192.168.56.10
```

Expected: `445/tcp open microsoft-ds`. If `filtered`, see the Private
network profile fix in Section 2.

### Note: WMI/DCOM-based remote execution is intentionally NOT opened
This lab deliberately exposes only SMB (445) from Kali to the Windows VM,
not RPC/DCOM (135 + dynamic range). This means tools like `wmiexec` or
`mmcexec` will authenticate successfully but fail to execute remotely
(`rpc_s_access_denied`). This is expected and was treated as a finding in
its own right — see `lessons-learned.md`. Scenarios requiring remote code
execution in this lab were instead run directly on the Windows VM, which
produces identical endpoint telemetry.

## 8. Verification Checklist

Before running any attack scenarios, confirm:

- [ ] `Get-Service SplunkForwarder, Sysmon64` both show `Running`
- [ ] `index=windows | stats count by source` shows all four sources
- [ ] VM and host timezones match
- [ ] `lab-user` is the active account; any account sharing the computer's
      name is disabled
- [ ] `svc-backup` exists as a dedicated low-privilege test account
- [ ] Kali can ping and reach port 445 on the Windows VM
- [ ] A clean snapshot exists to reset to after running scenarios
