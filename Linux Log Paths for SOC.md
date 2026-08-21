# 🔍 Linux Log Paths for SOC Analysts

Essential log locations and hunting keywords every SOC Analyst should know for incident investigation and SIEM querying.

---

## 📂 Critical Log Files

| Path | Type | SOC Use Case |
|------|------|--------------|
| `/var/log/auth.log` (Debian/Ubuntu) <br> `/var/log/secure` (RHEL/CentOS) | Authentication | Detect brute force, unauthorized SSH access, `sudo`/`su` abuse, and new user creation (`useradd`). |
| `/var/log/syslog` (Debian/Ubuntu) <br> `/var/log/messages` (RHEL/CentOS) | System | General system events, service starts/stops, and background processes. |
| `/var/log/apache2/` or `/var/log/nginx/` | Web Server | Detect SQL injection, XSS, directory traversal, and suspicious User-Agents. |
| `/var/log/kern.log` | Kernel | Kernel panics, hardware issues, and potential kernel-level exploits. |
| `/var/log/cron` or `/var/log/syslog` (CRON entries) | Scheduled Jobs | Detect malicious cron persistence (e.g., reverse shells executing every 5 mins). |
| `/var/log/dpkg.log` or `/var/log/yum.log` | Package Mgmt | Detect unauthorized software installation or removal by attackers. |
| `/var/log/boot.log` | System Boot | Analyze boot process and startup services. |

---

## 💻 Quick Local Commands

```bash
# Monitor authentication logs in real-time
tail -f /var/log/auth.log

# Search for failed SSH attempts (Brute Force)
grep "Failed password" /var/log/auth.log

# Search for successful root access via sudo/su
grep -E "sudo|su" /var/log/auth.log | grep "session opened"

# Check for new user creation
grep "new user" /var/log/auth.log

# Check cron job executions
grep "CRON" /var/log/syslog
```
## 🔑 Key Linux Hunting Keywords (SIEM / Splunk)

When analyzing Linux logs in a SIEM (e.g., Splunk), use these keywords combined with `source="auth.log"` or `sourcetype=syslog` to detect malicious activity:

| Keyword | Detection Purpose | Primary Log Source |
|---------|-------------------|--------------------|
| `"Failed password"` | SSH Brute Force attacks | `auth.log` |
| `"Accepted password"` | Successful SSH logins | `auth.log` |
| `"sudo"` | Privilege escalation attempts | `auth.log` |
| `"su"` | User switching to root | `auth.log` |
| `"useradd"` / `"usermod"` | New account creation or modification (Persistence) | `auth.log` |
| `"CRON"` | Scheduled tasks (Persistence mechanism) | `syslog` |
| `"truncate"` / `"rm -rf"` | Log clearing or file destruction (Anti-Forensics) | `auth.log` / `syslog` |
| `"python"` / `"perl"` / `"bash -i"` | Reverse shell execution indicators | `syslog` |
