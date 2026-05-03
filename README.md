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
- [Cryptology Concepts Applied](#cryptology-concepts-applied-encryption--hashing)
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

![Network Topology](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/796b65dc96977efc4021cb9ad486950943336674/Screenshots/ossec-conf-fim.png.png))

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

![Firewall rule](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/b4b5e58e1ed4e51c8554fa04f3436d89aed5cbe8/Screenshots/net-accounts-before-lockout.png)

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
![Nmap scan cmd](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/74a2286f8d6aeed25aba4ecc8f2f6d015f78a657/Screenshots/nmap-results.png.png)

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

## Cryptology Concepts Applied Encryption & Hashing

> This section connects concepts from cryptology coursework to real observations made during this lab.

---

### NTLM Authentication & MD4 Hashing

Every failed login attempt captured in Wazuh showed:
```
data.win.eventdata.authenticationPackage: NTLM
data.win.eventdata.logonProcessName:      NtLmSsp
```
![Failed Logs](https://github.com/Jspencer-SOC/SOC-Home-Lab-RDP-Brute-Force/blob/2ec3007bb3f25e3832eb4bdc7784e4e16c81e77c/Screenshots/NTLM%20%26%20NtLMSsp%20documentation.png)

**NTLM (NT LAN Manager)** is Microsoft's legacy authentication protocol. When a user logs in, Windows does not transmit the plaintext password — instead, it transmits a **hash** of the password computed using the **MD4 algorithm.**

| Property | Value |
|---|---|
| Algorithm | MD4 |
| Output size | 128-bit hash |
| Status | Cryptographically broken |
| Vulnerability | Collision attacks, rainbow table attacks, offline cracking |

**MD4 was retired from cryptographic use** because it fails the core requirement of a secure hash function — it is computationally feasible to find two inputs that produce the same hash (a collision), and modern hardware can compute billions of MD4 hashes per second, making offline cracking extremely fast.

---

### How This Relates to the Brute Force Attack

Hydra's RDP brute force works at the **authentication protocol level** — it sends plaintext password guesses over the network and lets the server compute and compare the hash. This means:

1. Hydra submits a password guess → `password123`
2. Windows computes the MD4 hash → `2b1b7b2fa1f1d8f6a3de142289c01f23`
3. Windows compares it to the stored NTLM hash in the SAM database
4. If they don't match → `subStatus: 0xc000006a` (wrong password)
5. Hydra tries the next password in rockyou.txt

**rockyou.txt is cryptographically significant** — it originated from a 2009 data breach in which 32 million user passwords were stored in **plaintext** (no hashing at all). This wordlist is effective because it represents real passwords people actually use, making it devastating against systems with weak or common passwords.

---

### Offline Hash Cracking (Post-Compromise Scenario)

If the attacker had successfully logged in and dumped the Windows SAM (Security Account Manager) database, the attack would shift from **online brute forcing** to **offline hash cracking:**

```bash
# Example: Cracking an NTLM hash with hashcat
hashcat -m 1000 -a 0 <ntlm_hash> /usr/share/wordlists/rockyou.txt
```

**Online vs Offline attack comparison:**

| Property | Online (Hydra RDP) | Offline (hashcat) |
|---|---|---|
| Speed | ~26 attempts/min (rate limited by RDP) | Billions of hashes/second |
| Detectability | High — generates 4625 events in SIEM | Zero — no network traffic |
| Lockout risk | Yes — account lockout applies | No — no auth attempts made |
| Requirement | Live network access | Access to hash dump only |

This is why **password hashing algorithm strength matters enormously** — a weak algorithm like MD4 means that even if an attacker only gets the hash (not the plaintext), they can crack it offline with no detection.

---

### Cryptographic Fixes — Stronger Authentication

**1. Replace NTLM with Kerberos**

Kerberos uses **AES-256 encryption** for ticket-based authentication — significantly more resistant to offline cracking than NTLM's MD4 hashing. In a domain environment, Kerberos should always be preferred over NTLM.

**2. Enable NLA (Network Level Authentication)**

NLA adds **TLS encryption** before the RDP session is established:
```powershell
# Enable NLA on Windows Server
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
  -Name "UserAuthentication" -Value 1
```

Without NLA, credential negotiation happens inside an unencrypted RDP session. With NLA, credentials are protected by TLS before any session data is exchanged.

**3. Certificate-Based Authentication**

Replaces password authentication entirely with **asymmetric cryptography:**
- Server holds a **public key**
- User holds a **private key** (stored on a smart card or TPM)
- Authentication proves possession of the private key without transmitting it
- An attacker with no private key cannot authenticate, regardless of how many guesses they attempt — **brute force becomes mathematically impossible**

**4. Strong Password Hashing (for stored credentials)**

If passwords must be stored, use modern algorithms:

| Algorithm | Type | Recommended |
|---|---|---|
| MD4 (NTLM) | Fast hash | Broken |
| MD5 | Fast hash | Broken |
| SHA-1 | Fast hash | No longer in use |
| bcrypt | Slow hash | Recommended |
| Argon2 | Memory-hard | Best practice |

**Slow hashing algorithms** (bcrypt, Argon2) are specifically designed to be computationally expensive — even if an attacker obtains a hash, cracking it takes months instead of seconds.

---

### Summary — Cryptology Lessons from This Lab

| Observation | Cryptology Concept |
|---|---|
| NTLM used in every auth attempt | Hashing algorithms underpin authentication |
| MD4 is broken and fast to crack | Hash function security requirements |
| rockyou.txt derived from plaintext breach | Importance of hashing passwords |
| Offline cracking far faster than online | Online vs offline attack surface |
| NLA recommendation | Encryption in transit (TLS) |
| Certificate auth recommendation | Asymmetric cryptography / PKI |
| Kerberos recommendation | Modern authenticated key exchange |

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


## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)
- [Microsoft Event ID 4625](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Microsoft NTLM Authentication Documentation](https://docs.microsoft.com/en-us/windows/win32/secauthn/microsoft-ntlm)
- [NIST on MD4/MD5 Deprecation](https://csrc.nist.gov/projects/hash-functions)
- [The RockYou Data Breach — Background](https://techcrunch.com/2009/12/14/rockyou-hack-security-myspace-facebook-passwords/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Microsoft — NLA for RDP](https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access)
- [NIST Guidelines on Password Hashing — SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Hashcat Documentation](https://hashcat.net/wiki/)

---

*Lab conducted April 27 – May 2, 2026. All activity performed on systems I own, in an isolated VirtualBox environment, for educational purposes only.*
*Lab guidance and write-up assistance provided with the help of Claude AI (Anthropic).*
