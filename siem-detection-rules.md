# 🎯 SIEM Detection Rules & Windows Logging Cheatsheet

> **Purpose:** A comprehensive reference guide for SOC Analysts covering detection rules, Windows/Sysmon event IDs, and PowerShell artifacts.

---

## 1️⃣ Common Detection Rules

| Rule Name | Condition | Event ID | SOC Priority |
|-----------|-----------|----------|--------------|
| **Event Log Cleared** | Log source = WinEventLog AND EventID = 104 | 104 | 🔴 Critical |
| **Whoami Execution** | EventID = 4688 AND NewProcessName contains "whoami" | 4688 | 🔴 High |
| **Multiple Failed Logins** | Failed logins > 5 in 10 seconds | 4625 | 🟡 Medium |
| **Successful Login After Failures** | Success after multiple failures | 4624 + 4625 | 🔴 High |
| **USB Device Connected** | USB plug-in detected | 20001/20003 | 🟡 Medium |
| **Large Outbound Transfer** | Outbound traffic > 25 MB | Network logs | 🔴 High |
| **PowerShell Execution** | PowerShell script executed | 4104 | 🟡 Medium |
| **User Added to Backup Operators** | EventID = 4732 AND TargetUserName = "Backup Operators" | 4732 | 🔴 Critical |
| **File Downloaded from Internet (Mark of the Web)** | EventID = 15 AND Contents contains "http" | 15 | 🟡 Medium |
| **Suspicious DNS Query** | EventID = 22 AND QueryName contains suspicious TLD (`.top`, `.click`) | 22 | 🟡 Medium |

---

## 2️⃣ Key Windows Event IDs

| Event ID | Description | SOC Use Case |
|----------|-------------|--------------|
| **104** | Event log cleared | Detect log tampering |
| **4624** | Successful login | Track user access, check Logon Type (2=Interactive, 3=Network, 10=RDP) |
| **4625** | Failed login | Detect brute force attacks |
| **4688** | Process creation | Detect suspicious commands (requires Audit Policy enabled) |
| **4104** | PowerShell script | Detect malicious scripts (Script Block Logging) |
| **4720** | User account created | Detect unauthorized backdoor accounts |
| **4732** | User added to privileged group | Detect privilege escalation (e.g., added to Administrators) |

---

## Logon Types Reference (Critical for SOC)

| Logon Type | Name | Description | SOC Use Case |
|------------|------|-------------|--------------|
| **2** | Interactive | User at console | Normal login |
| **3** | Network | Network logon (SMB, WinRM) | 🔴 Detect lateral movement, botnets |
| **4** | Batch | Scheduled tasks | 🟡 Check malicious tasks |
| **5** | Service | Windows services | Normal |
| **7** | Unlock | Screen unlock | Normal |
| **8** | NetworkCleartext | Cleartext password | 🔴 Critical: password exposed |
| **9** | NewCredentials | runas /netonly | 🟡 Check suspicious |
| **10** | RemoteInteractive | RDP interactive | 🔴 Detect unauthorized RDP |
| **11** | CachedInteractive | Cached credentials | Normal |

**Pro Tip:** Focus on Type 3 and 10 from external IPs = High priority alerts!

---

## 3️⃣ Sysmon Event IDs (The Gold Standard)

| Event ID | Name | Purpose | SOC Red Flags |
|----------|------|---------|---------------|
| **1** | Process Creation | Advanced process execution logging | Uncommon paths (`C:\Temp`, `C:\Users\Public`), Weird parent-child (e.g., Word → PowerShell), Unsigned binaries, Malicious Hashes (VirusTotal) |
| **3** | Network Connection | Logs outbound/inbound connections | Connections to external IPs on non-standard ports (4444, 7777), Known malicious IPs |
| **11** | File Creation | Logs files created/overwritten | Files in staging dirs, Executables/scripts (.exe, .ps1, .bat) |
| **15** | FileCreateStreamHash | Tracks "Mark of the Web" (Zone.Identifier) | Detects files downloaded from internet, Contents field reveals source URL |
| **22** | DNS Query | Logs DNS resolution requests | Queries to suspicious TLDs (.top, .click), DGA-like domains (e.g., hkfasfsafg.click) |

**Pro Tip:** Always use **Logon ID** to correlate suspicious login (4624) with malicious process execution (Sysmon 1).

---

## 4️⃣ PowerShell Artifacts & Logging

| Artifact / Event ID | Location / Source | Purpose | SOC Use Case |
|---------------------|-------------------|---------|--------------|
| **ConsoleHost_history.txt** | `C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\` | Plain text file recording every command typed | First place to check for manual attacker commands. Survives reboots. |
| **Event ID 4104** | Windows PowerShell → Operational | Script Block Logging | Captures full script content and execution context, even if obfuscated |

**Key Commands to Watch:**
- `Invoke-WebRequest`, `IEX` → File download
- `Get-ComputerInfo`, `Get-LocalUser` → Discovery/Reconnaissance
- `Invoke-Command`, `Enter-PSSession` → Lateral movement

---

## 5️⃣ Rule Tuning

### False Positive Tuning
- **Problem**: Alert triggers on legitimate admin activity
- **Solution**: Add exclusion for admin accounts or specific IPs
- **Example**: Exclude "IT-Admin" group from brute force detection

### True Positive Actions
1. Investigate the alert in detail
2. Contact asset owner
3. If confirmed malicious:
   - Isolate infected host
   - Block suspicious IP
   - Escalate to Tier 2

---

## 💡 Pro Tips for SOC Analysts

1. **Correlation is Key:** Never look at an event in isolation. Use **Logon ID** to tie suspicious login (4624) to subsequent malicious actions (4720, Sysmon 1).
2. **Build the Process Tree:** Use Sysmon Event ID 1 `ProcessId` and `ParentProcessId` to reconstruct attack chain (e.g., `explorer.exe` → `winword.exe` → `cmd.exe` → `malware.exe`).
3. **Context over Noise:** Focus on anomalies. Legitimate process in legitimate path = OK. Legitimate process (powershell.exe) in unusual path (C:\Temp\) = Red flag.
4. **Check All Users:** PowerShell history exists for every user. Check `C:\Users\<USERNAME>\` for all suspicious accounts, not just Administrator.


---
|_|_|_|
|----------------------------------------------|-------------------------------------------------------------------------------------------------------|------------|----------|
| **Suspicious LNK/Phishing Execution** | Parent=`explorer.exe` AND Child=`powershell.exe`/`cmd.exe` AND CommandLine contains `DownloadFile` or `http` | Sysmon 1 | 🔴 Critical |
| **Executable Launched from Removable Media** | Image path starts with removable drive letters (e.g., `E:\`, `F:\`) AND Parent=`explorer.exe` | Sysmon 1 | 🔴 High |
| **Suspicious File Creation in Downloads** | TargetFilename contains `\Downloads\` AND ends with `.lnk`, `.exe`, `.scr`, or `.ps1` | Sysmon 11 | 🟡 Medium |

---
*Built from hands-on practice: TryHackMe "Windows Logging for SOC" & LetsDefend scenarios.*
