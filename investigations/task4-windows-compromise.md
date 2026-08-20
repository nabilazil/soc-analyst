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
