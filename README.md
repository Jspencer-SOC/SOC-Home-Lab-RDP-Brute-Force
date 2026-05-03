# SOC Home Lab — RDP Brute Force Attack Detection & Response

> A hands-on Security Operations Center (SOC) lab simulating a real-world RDP brute force attack, detected with Wazuh SIEM, and remediated live on a Windows Server 2022 target. Also includes File Integrity Monitoring, Vulnerability Detection, CIS Benchmarking, and Threat Hunting.

---

## Table of Contents
- [Lab Overview](#lab-overview)
- [Environment & Network Topology](#environment--network-topology)
- [Tools Used](#tools-used)
- [Lab Setup](#lab-setup)
- [Attack Phase](#attack-phase--rdp-brute-force)
- [Detection Phase](#detection-phase)
- [Remediation Phase](#remediation-phase)
- [File Integrity Monitoring](#file-integrity-monitoring-fim)
- [Vulnerability Detection](#vulnerability-detection)
- [CIS Benchmark Assessment](#cis-benchmark-assessment)
- [Threat Hunting](#threat-hunting)
- [Key Findings & IOCs](#key-findings--iocs)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Lessons Learned](#lessons-learned)
- [References](#references)

---

## Lab Overview

This project simulates a realistic SOC analyst workflow in a fully isolated VirtualBox home lab. It covers:

1. **RDP Brute Force Attack** — Simulated using Hydra against Windows Server 2022
2. **Real-time SIEM Detection** — All events captured and analyzed in Wazuh
3. **Live Remediation** — Lockout policy and firewall rules applied mid-attack
4. **File Integrity Monitoring** — Wazuh FIM detects file changes on the victim
5. **Vulnerability Scanning** — 34 Critical and 1,190 High CVEs identified
6. **CIS Benchmarking** — Windows Server 2022 scored 26% on CIS Benchmark v2.0.0
7. **Threat Hunting** — nmap scan and software installs detected post-attack

---

## Environment & Network Topology

Network Topology

### VM Specifications

| Machine | OS | IP Address | Role |
|---|---|---|---|
| Ubuntu-26 | Ubuntu 26.04 LTS | 10.0.2.15 | Wazuh SIEM Manager |
| HackerUbuntu | Ubuntu 26.04 LTS | 10.0.2.6 | Attacker |
| Windows2022 | Windows Server 2022 Std Eval | 10.0.2.5 | Victim / Monitored Host |

---

## Tools Used

| Tool | Purpose |
|---|---|
| **VirtualBox** | Isolated lab virtualization |
| **Wazuh** | SIEM — alerting, FIM, vuln detection, threat hunting |
| **Hydra v9.6** | RDP brute force simulation |
| **freerdp** | RDP client used by Hydra |
| **nmap** | Network reconnaissance from attacker VM |
| **rockyou.txt** | Password wordlist (~14.3M passwords) |
| **PowerShell** | Live remediations on victim |
| **winget** | Software installs for realistic telemetry |

---

## Lab Setup

### Wazuh Agent — ossec.conf (Base)

The Wazuh agent on the Windows victim was configured to monitor Security Event Logs and system directories:

![ossec.conf base](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/ossec-conf-base.png.png)

### Wazuh Agent — FIM Custom Directory

A custom real-time monitored directory was added:

![ossec.conf FIM](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/ossec-conf-fim.png.png))

```xml
<directories realtime="yes">C:\Users\Administrator\Hackers</directories>
```

### Software Installed on Victim

Apps installed via winget to generate realistic Wazuh telemetry:

![winget install](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/winget-install.png.png)

```powershell
winget install --id=Notepad++.Notepad++ -e
winget install --id=Google.Chrome -e
winget install --id=Microsoft.Teams -e
winget install --id=Dropbox.Dropbox -e
```

---

## Attack Phase — RDP Brute Force

### Attacker Command

```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://10.0.2.5 -t 1
```

| Flag | Purpose |
|---|---|
| `-l Administrator` | Target the built-in Administrator account |
| `-P rockyou.txt` | 14.3M password wordlist |
| `rdp://10.0.2.5` | RDP URI syntax (required — bare IP fails) |
| `-t 1` | Single thread (multiple threads break RDP) |

> **Lesson learned:** Initial command used `10.0.2.5 rdp` (wrong) instead of `rdp://10.0.2.5` (correct). The URI prefix and `-t 1` flag are both mandatory for Hydra RDP attacks.

### Attack Rate
```
[STATUS] 26.00 tries/min — 14,344,398 total passwords in wordlist
```

---

## Detection Phase

### Wazuh Live Alert View

![Wazuh alerts](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/wazuh-alerts-3712hits.png.png)

**3,712 events** captured. Every attempt is fully attributed to the attacker.

### Key Windows Event IDs

| Event ID | Meaning |
|---|---|
| **4625** | Failed logon — bulk brute force indicator |
| **4616** | System time changed — background noise |
| **60122** | Wazuh rule: Logon Failure / unknown user or bad password |

### Status Codes Reference

| Code | Field | Meaning |
|---|---|---|
| `0xc000006a` | subStatus | Wrong password |
| `0xc000006d` | status | General logon failure |
| `0xc0000234` | subStatus | Account locked out |
| `0x0` | status | Success — never observed (attack failed) |

### Full Log Entry (Indicators of Compromise Breakdown)

```
data.win.eventdata.ipAddress:            10.0.2.6       ← Attacker IP
data.win.eventdata.workstationName:      HackerUbuntu   ← Attacker hostname
data.win.eventdata.targetUserName:       Administrator  ← Target account
data.win.eventdata.authenticationPackage: NTLM
data.win.eventdata.logonType:            3              ← Network logon
data.win.eventdata.subStatus:            0xc000006a     ← Wrong password
data.win.eventdata.status:               0xc000006d     ← Logon failure
data.win.eventdata.processId:            0x0            ← No process spawned
```

### SubStatus Timeline

![SubStatus timeline](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/wazuh-substatus-timeline.png.png)

Dense column of `0xc000006a` codes — stops abruptly after remediation.

### EventID View

![EventID view](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/wazuh-eventid-view.png.png)

### Attack Timeline

| Time | Event |
|---|---|
| 20:57 | Hydra attack starts |
| 20:57–21:10 | Sustained 4625 wave at ~26/min |
| 21:10 | Lockout policy applied live |
| 21:14 | Last auth attempt in Wazuh |
| 21:22 | Hydra exits — `all children disabled` |

---

## Remediation Phase

All remediations applied **live while the attack was running.**

### 1. Account Lockout Policy

```powershell
net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:15
gpupdate /force
```

![Account locked](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/account-locked.png.png)

> **Key finding:** Built-in Administrator is exempt from lockout by default on Windows Server. A `secedit` GPO override + `gpupdate /force` was required to enforce it — an important real-world hardening caveat.

### 2. Firewall IP Block

```powershell
New-NetFirewallRule -DisplayName "Block HackerUbuntu" `
  -Direction Inbound -Protocol TCP `
  -LocalPort 3389 -RemoteAddress 10.0.2.6 -Action Block
```

![Firewall rule](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/firewall-rule.png.png)

### 3. Enable Lockout Auditing

```powershell
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
```

---

## File Integrity Monitoring (FIM)

A test file `test-02.txt` was created inside `C:\Users\Administrator\Hackers\`:

![FIM test file](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/fim-test-file.png.png)

Wazuh generated an alert for the file creation event. In a real scenario, this would detect:
- Attacker dropping a payload post-compromise
- Malware writing files to sensitive directories
- Unauthorized changes to config files

---

## Vulnerability Detection

### Windows Server 2022 (Victim)

![Vuln detection Windows](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/vuln-detection-windows.png.png)

| Severity | Count |
|---|---|
| Critical | 34 |
| High | 1,190 |
| Medium | 538 |
| Low | 14 |
| **Total** | **1,776** |

Top CVEs: CVE-2020-16009, CVE-2021-21118 through CVE-2021-21121

### HackerUbuntu (Attacker)

![Vuln detection attacker](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/vuln-detection-attacker.png.png)

| Severity | Count |
|---|---|
| Critical | 5 |
| High | 20 |
| Medium | 14 |

> Even the attacker machine had critical vulnerabilities (Firefox CVEs). No system should be assumed safe.

---

## CIS Benchmark Assessment

![CIS benchmark](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/cis-benchmark.png.png)

**CIS Microsoft Windows Server 2022 Benchmark v2.0.0**

| Result | Count |
|---|---|
| Passed | 96 |
| Failed | 263 |
| **Score** | **26%** |

**Key Failed Control — CIS ID 27000:**
> *"Ensure 'Enforce password history' is set to 24 or more passwords"*

A 26% CIS score means the system is severely under-hardened with a large attack surface.

---

## Threat Hunting

### Wazuh Threat Hunting — Application & Service Activity

![Threat hunting 1](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/threat-hunting-1.png.png)
![Threat hunting 2](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/threat-hunting-2.png.png)

| Rule ID | Description | Level |
|---|---|---|
| 60610 | Windows installer began installation | 3 |
| 61138 | New Windows Service Created | 5 |
| 61104 | Service startup type changed | 3 |
| 60132 | System time changed | 5 |
| 60122 | Logon Failure / bad password | 5 |
| 60612 | Application installed (Chrome, Teams, Dropbox) | 3 |

Software installs trigger service creation and installer events — exactly what malware installation looks like.

### Nmap Scan Detected

![Nmap scan](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/nmap-scan-wazuh.png.png)

A subsequent nmap scan from HackerUbuntu was captured by Wazuh:

```
predecoder.hostname:   HackerUbuntu
data.command:          /usr/bin/nmap -sV -Pn 10.0.2.5
rule.mitre.id:         T1548.003
rule.mitre.tactic:     Privilege Escalation, Defense Evasion
```

This shows Wazuh detecting **reconnaissance activity**, not just auth failures.

---

## Key Findings & IOCs

| IOC Type | Value |
|---|---|
| Attacker IP | `10.0.2.6` |
| Attacker Hostname | `HackerUbuntu` |
| Target Account | `Administrator` |
| Target Port | `3389` (RDP) |
| Auth Protocol | `NTLM / NtLmSsp` |
| Logon Type | `3` (Network logon) |
| SubStatus | `0xc000006a` (wrong password) |
| Status | `0xc000006d` (logon failure) |
| Event ID | `4625` (hundreds of occurrences) |
| Attack Rate | ~26 attempts/minute |
| Total Events | 3,713 logged |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Brute Force: Password Guessing | T1110.001 |
| Credential Access | Brute Force | T1110 |
| Discovery | Network Service Discovery | T1046 |
| Initial Access | Valid Accounts | T1078 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | T1548.003 |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 |

---

## Lessons Learned

### Vulnerabilities Found
1. RDP exposed with no IP restrictions; anyone can connect via the internet
2. No account lockout policy configured
3. Built-in Administrator account exposed over RDP
4. CIS Benchmark score of only 26%
5. 1,190 high-severity unpatched CVEs
6. Account lockout auditing is disabled by default
7. Built-in Administrator is exempt from lockout without GPO override

### What Worked
1. Wazuh detected every attempt in real time
2. Full attacker attribution in every log entry
3. Live remediation stopped the attack within minutes
4. FIM detected file creation immediately
5. Threat hunting revealed nmap reconnaissance and software installs

### Real-World Recommendations
- Disable RDP entirely if not needed; use VPN + jump box
- Restrict RDP to specific IPs via firewall
- Rename or disable the built-in Administrator account
- Enforce MFA for all remote access
- Apply all Critical/High patches immediately
- Target CIS Benchmark score above 80%
- Configure Wazuh Active Response for auto IP-blocking
- Enable FIM on all sensitive directories
- Monitor for new service creation and unauthorized software

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Microsoft Event ID 4625](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [CIS Windows Server 2022 Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*Lab conducted April 27 – May 2, 2026. All activity performed on systems I own, in an isolated VirtualBox environment, for educational purposes only.*
