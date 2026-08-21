#  Task 5: Linux Compromise Investigation (Ubuntu Server)

**Scenario:** Alert indicating possible persistence through the creation of a new remote-ssh user on an Ubuntu server.

---

## 🎯 Investigation Steps

### Step 1: Identify Initial Access (SSH Brute Force)
**Goal:** Find the source IP and the success of the brute-force attack.

**Query:**
```spl
index=task5 source="auth.log" sshd "jack-brown" ("Accepted password" OR "Failed password")
| table _time, src_ip, user, message
| sort + _time
'''
