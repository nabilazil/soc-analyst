# 🎯 SIEM Detection Rules Examples

Essential detection rules every SOC Analyst should know.

## Common Detection Rules

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

## Key Windows Event IDs

| Event ID | Description | SOC Use Case |
|----------|-------------|--------------|
| **104** | Event log cleared | Detect log tampering |
| **4624** | Successful login | Track user access |
| **4625** | Failed login | Detect brute force |
| **4688** | Process creation | Detect suspicious commands |
| **4104** | PowerShell script | Detect malicious scripts |
| **4720** | User account created | Detect unauthorized accounts |
| **4732** | User added to privileged group | Detect privilege escalation |

## Rule Tuning

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


## Process Monitoring (Sysmon vs Windows Default)

| Event ID | Source | Description | SOC Red Flags |
|----------|--------|-------------|---------------|
| **4688** | Security Log | Process Creation (Default) | Suspicious command line, but lacks hash/signature details. |
| **1** | Sysmon Log | Advanced Process Creation | **The Gold Standard.** Check for: Uncommon paths (`C:\Temp`), Weird parent-child (e.g., Word -> PowerShell), Unsigned binaries, Malicious Hashes (VirusTotal). |

**Pro Tip:** Always use the **Logon ID** to correlate the initial suspicious login (4624) with the malicious process execution (Sysmon 1).
