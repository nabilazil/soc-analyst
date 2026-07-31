# soc-analyst-toolkit
🔐 Security tools &amp; labs for SOC analysis.

## 🔍 OSINT & Recherche

# Shodan

## 📖 Overview
Shodan is a search engine for Internet-connected devices. Unlike Google (which searches websites), Shodan scans the internet for devices, open ports, and services (like webcams, routers, servers, and industrial control systems).

## 🎯 Why a SOC Analyst Needs It
- **Attack Surface Management**: Discover if your organization's assets (IPs, domains) are exposed to the public internet.
- **Vulnerability Hunting**: Search for specific CVEs (e.g., `vuln:CVE-2021-44228`) to see if your infrastructure is at risk.
- **Incident Response**: Investigate malicious IPs to see what services they are running or if they are part of a botnet.
- **Shadow IT Discovery**: Find forgotten or unauthorized servers belonging to your company.

## 🛠️ Essential Search Filters (SOC Focus)

| Filter | Description | Example |
|--------|-------------|---------|
| `country:` | Search by country code (ISO 2-letter) | `country:MA` |
| `org:` | Search by organization or company name | `org:"Maroc Telecom"` |
| `port:` | Search for specific open ports | `port:3389` (RDP) or `port:22` (SSH) |
| `product:` | Search for specific software/service | `product:"Apache httpd"` |
| `version:` | Search for specific software version | `version:"2.4.49"` |
| `vuln:` | Search for devices with a specific CVE | `vuln:CVE-2021-41773` |
| `os:` | Search by operating system | `os:"Windows"` |

## 💡 Practical SOC Examples

1. **Find exposed RDP servers in Morocco** (High risk for brute-force):
   ```text
   port:3389 country:MA
