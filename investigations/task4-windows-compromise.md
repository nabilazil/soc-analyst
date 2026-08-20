# 🔍 Task 4: Windows Compromise Investigation (WIN-105)

**Scenario:** Suspicious network connection on port 5678 on host WIN-105.

---

## 🎯 Investigation Steps

### Step 1: Identify Malicious Process (Network Connection)
**Goal:** Find which process initiated the connection to port 5678.

**Query:**
```spl
index=task4 EventCode=3 ComputerName=WIN-105 DestinationPort=5678 
| table _time ComputerName Image SourceIp DestinationIp DestinationPort
```

**Finding:**
- **Malicious Process:** `C:\Windows\Temp\SharePoInt.exe`
- **Red Flags:** 
  - Running from `C:\Windows\Temp\` (unusual location for legitimate software).
  - **Masquerading:** "SharePoInt" (capital P) vs legitimate "SharePoint".
- **Destination IP:** 10.10.114.80:5678

---

### Step 2: Get MD5 Hash of Malicious Process
**Goal:** Extract hash for threat intelligence and further analysis.

**Query:**
```spl
index=task4 EventCode=1 ComputerName=WIN-105 Image=*SharePoInt* 
| table _time Image Hashes
```

**Finding:**
- **MD5 Hash:** `770d14ffa142f09730b415506249e7d1` *(Note: converted to lowercase for TryHackMe validation).*

---

### Step 3: Identify Persistence Mechanism (Scheduled Task)
**Goal:** Find how the attacker maintained access (Persistence).

**Query (Method 1 - EventCode 4698):**
```spl
index=task4 EventCode=4698 ComputerName=WIN-105 
| table _time TaskName CreatorUserName TaskContent
```

**Query (Method 2 - Process Creation with schtasks):**
```spl
index=task4 "schtasks" ComputerName=WIN-105 
| table _time CommandLine
```

**Finding:**
- **Malicious Scheduled Task:** `Office365 Install`
- **Technique:** Persistence via scheduled task (MITRE ATT&CK: T1053.005).

---

## 📚 Key Learnings

1. **Event Codes Used:**
   - **Sysmon EventCode 3:** Network connections.
   - **Sysmon EventCode 1:** Process creation (includes file hashes).
   - **Windows EventCode 4698:** Scheduled task creation.

2. **Detection Techniques:**
   - **Masquerading:** Attackers use names similar to legitimate software (e.g., SharePoInt vs SharePoint).
   - **Unusual Paths:** Malware often runs from `C:\Windows\Temp\` or `C:\Users\Public\`.
   - **Persistence:** Scheduled tasks are a common method for maintaining access across reboots.

3. **SOC Workflow:**
   - Start with the initial alert (port 5678).
   - Identify the malicious process (`SharePoInt.exe`).
   - Extract the hash for Threat Intelligence (TI).
   - Find the persistence mechanism (`Office365 Install` task).

---

## 🎯 Flags Captured
- **Malicious Process:** `SharePoInt.exe`
- **MD5 Hash:** `770d14ffa142f09730b415506249e7d1`
- **Scheduled Task:** `Office365 Install`
