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

------------------------------------------------------------------------------------------------------------------------------------

# VirusTotal

## 📖 Overview
VirusTotal is a free online service that analyzes files, URLs, domains, and IP addresses for malware. It aggregates results from multiple antivirus engines and security tools to provide a comprehensive threat detection report.

## 🎯 Why a SOC Analyst Needs It
- **File Analysis**: Check if suspicious files (attachments, downloads) are malicious
- **IOC Verification**: Validate Indicators of Compromise (IPs, domains, URLs, hashes)
- **Threat Intelligence**: Get detection ratios and community comments on threats
- **Incident Response**: Quickly triage suspicious artifacts during investigations
- **YARA Rules**: Detect malware using custom YARA rule matching

## 🛠️ Key Features (SOC Focus)

| Feature | Description |
|---------|-------------|
| **File Scan** | Upload files (up to 650MB) to check against 70+ antivirus engines |
| **URL/Domain Scan** | Analyze suspicious URLs and domains for phishing/malware |
| **IP Address Analysis** | Check IP reputation and associated threats |
| **Hash Lookup** | Search by MD5, SHA-1, or SHA-256 without uploading files |
| **VirusTotal Intelligence** | Advanced search and hunting (premium feature) |
| **Community Comments** | Read analyst comments and threat reports |

## 💡 Practical SOC Examples

1. **Check a suspicious file hash** (without uploading):
   - Go to "Search" tab
   - Enter hash: `e99a18c428cb38d5f260853678922e03`
   - Review detection ratio (e.g., 45/70 engines detected it)

2. **Analyze a suspicious URL**:
   - Go to "URL" tab
   - Paste: `http://suspicious-site.com/malware.exe`
   - Check for phishing, malware, or C2 indicators

3. **Investigate a malicious IP**:
   - Go to "IP Address" tab
   - Enter: `185.220.101.1`
   - Review:
     - Detection ratio
     - Country/ASN info
     - Associated domains
     - Passive DNS data

4. **Check domain reputation**:
   - Go to "Domain" tab
   - Enter: `malicious-domain.com`
   - Review:
     - Categories (phishing, malware, C2)
     - Subdomains
     - Communicating files
     - Referrer files

5. **Use VirusTotal API** (for automation):
   ```bash
   # Check file hash via API
   curl --request GET --url https://www.virustotal.com/api/v3/files/{hash} \
   --header 'x-apikey: YOUR_API_KEY'
