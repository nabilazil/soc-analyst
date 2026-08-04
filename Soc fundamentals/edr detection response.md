# 🛡️ EDR: Advanced Detection & Response Capabilities

How modern EDRs detect and neutralize threats beyond traditional Antivirus.

## 1. Advanced Detection Techniques
| Technique | How it Works | Real-World SOC Example |
|-----------|--------------|------------------------|
| **Behavioral Detection** | Observes process relationships and actions, not just file signatures. | Flags `winword.exe` spawning `powershell.exe` (unusual parent-child). |
| **Anomaly Detection** | Learns endpoint baseline; flags deviations. | A user account suddenly modifying auto-start Registry keys at 3 AM. |
| **IOC Matching** | Cross-references activity with global Threat Intelligence feeds. | Matches a downloaded file's hash with a known ransomware campaign. |
| **MITRE ATT&CK Mapping** | Tags alerts with specific Tactic & Technique IDs. | Maps "Scheduled Task creation" to `T1053.005` (Persistence). |
| **Machine Learning** | Identifies complex, multi-stage attack chains that bypass single rules. | Detects fileless malware executing entirely in memory. |

## 2. Manual & Automated Response Actions
When an alert is confirmed as a **True Positive**, the SOC Analyst can take immediate action via the EDR console:

| Response Action | When to Use It | SOC Impact |
|-----------------|----------------|------------|
| **Isolate Host** | Severe compromise (e.g., Ransomware, Active C2). | Cuts network access (except to EDR console) to prevent lateral movement. |
| **Terminate Process** | Specific malicious process identified, but host must stay online. | Kills the malicious process (e.g., `miner.exe`) without disrupting business operations. |
| **Quarantine File** | Suspicious file dropped on disk. | Moves file to a secure, non-executable vault for later analysis. |
| **Remote Access (RTR)** | Deep investigation needed. | Opens a live shell to run custom commands, gather logs, or execute scripts. |
| **Artefacts Collection** | Post-incident forensics or legal reporting. | Remotely dumps Memory, Event Logs, or Registry hives without touching the physical machine. |

## 🔑 Key Takeaway for SOC L1
EDR is not just an alerting tool; it is an **investigation and containment platform**. Always verify the MITRE ATT&CK mapping and process tree before executing a response action like Host Isolation.
