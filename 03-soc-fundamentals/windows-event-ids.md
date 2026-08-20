## 🕵️‍♂️ Key Hunting Keywords (Process Creation - EventCode 1/4688)

When specific Event IDs (like 4698) are missing (e.g., in Sysmon), search for these executable names in the `CommandLine` or `Image` fields to detect malicious activity:

| Keyword | Attacker Goal | Detection Logic |
|---------|---------------|-----------------|
| **`schtasks`** | Persistence (Scheduled Tasks) | `EventCode=1` AND `CommandLine="*schtasks*"` |
| **`powershell`** | Script Execution / Download | Look for encoded commands (`-enc`, `-e`) or web requests (`IEX`, `DownloadString`) |
| **`net user`** | Backdoor Account Creation | `EventCode=1` AND `CommandLine="*net user*"` |
| **`net localgroup`** | Privilege Escalation | Look for additions to "Administrators" group |
| **`whoami` / `ipconfig`** | Reconnaissance | Often the first commands run after initial access |
