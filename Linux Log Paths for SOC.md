# 🔍 Linux Log Paths for SOC Analysts

Essential log locations every SOC Analyst should know for incident investigation.

## Critical Log Files

| Path | Type | SOC Use Case |
|------|------|--------------|
| `/var/log/auth.log` or `/var/log/secure` | Authentication | Detect brute force, unauthorized SSH access, sudo abuse |
| `/var/log/apache2/` or `/var/log/httpd/` | Web Server | Detect SQL injection, XSS, directory traversal attacks |
| `/var/log/syslog` | System | General system events and errors |
| `/var/log/kern.log` | Kernel | Kernel exploits, hardware issues |
| `/var/log/cron` | Scheduled Jobs | Detect malicious cron persistence |
| `/var/log/dpkg.log` or `/var/log/yum.log` | Package Mgmt | Detect unauthorized software installation |
| `/var/log/boot.log` | System Boot | Analyze boot process |

## Quick Commands

```bash
# Monitor authentication logs in real-time
tail -f /var/log/auth.log

# Monitor web server logs
tail -f /var/log/apache2/access.log

# Search for failed SSH attempts
grep "Failed password" /var/log/auth.log

# Check cron jobs
cat /var/log/cron
