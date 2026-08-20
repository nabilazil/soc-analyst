# 🔍 Task 4: Windows Compromise Investigation (WIN-105)

**Scenario:** Suspicious network connection on port 5678 on host WIN-105

---

## 🎯 Investigation Steps

### Step 1: Identify Malicious Process (Network Connection)
**Goal:** Find which process initiated connection to port 5678

**Query:**
```spl
index=task4 EventCode=3 ComputerName=WIN-105 DestinationPort=5678 
| table _time ComputerName Image SourceIp DestinationIp DestinationPort

Malicious Process: C:\Windows\Temp\SharePoInt.exe
Red Flags:
Running from C:\Windows\Temp\ (unusual location)
Masquerading: "SharePoInt" (capital P) vs legitimate "SharePoint"
Destination IP: 10.10.114.80:5678
Step 2: Get MD5 Hash of Malicious Process
Goal: Extract hash for threat intelligence
Query:
