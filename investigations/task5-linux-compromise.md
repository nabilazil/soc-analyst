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
```
Finding:
Attacker IP: 10.14.94.82
Red Flags:
4 failed login attempts right before the successful login.
Classic Brute-Force attack leading to initial access.


### Step 2: Identify Privilege Escalation
Goal: Determine which user escalated privileges to root before creating the backdoor.

Query:
```spl
index=task5 source="auth.log" ("su" OR "sudo") 
| table _time, user, message
| sort + _time
```
Finding:
User: jack-brown
Technique: Executed sudo /usr/bin/su to switch from a normal user (uid=1003) to root (uid=0).


### Step 3: Identify Defense Evasion (Anti-Forensics)
Goal: Identify attempts to cover tracks.

Query:
```spl
index=task5 source="auth.log" "truncate"
| table _time, message
```
Finding:
Command: /usr/bin/truncate -s 0 /var/log/syslog
Red Flags: Attempted to wipe system logs to hide malicious activity (SIEM already ingested them centrally).


### Step 4: Identify Persistence Mechanism
Goal: Find how the attacker maintains access.

Query:
```spl
index=task5 sourcetype=syslog process=CRON
```



# Key Learnings

1. **Log Sources Used:**
   - auth.log: Authentication events (SSH logins, sudo, su).
   - syslog: General system events (CRON jobs, services).

2. **Detection Techniques:**
   - Brute Force: Multiple "Failed password" followed by "Accepted password" from the same IP.
   - Privilege Escalation: Tracking "sudo" and "su" commands in auth.log.
   - Anti-Forensics: Detecting log clearing commands like "truncate".
   - Persistence: Monitoring CRON jobs for suspicious scripts (python, perl, bash).

3. **SOC Workflow:**
   - Start with the initial alert (new user creation).
   - Identify the attacker IP and brute-force attempts.
   - Track privilege escalation to root.
   - Find the persistence mechanism (malicious cron job).

4. **🎯 Flags Captured**
   - Account Creation Timestamp: 2025-08-12 09:52:57
   - User Who Escalated: jack-brown
   - Attacker IP: 10.14.94.82
   - Failed Login Attempts: 4
   - Persistence Port: 7654
