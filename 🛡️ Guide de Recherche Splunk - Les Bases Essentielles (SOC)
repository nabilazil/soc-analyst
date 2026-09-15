# 🔎 SOC Investigation — Suspicious Email Link

> **TryHackMe | Splunk | Email Security | Log Analysis**

## 📌 Scenario

An inbound email triggered a security alert because it contained an external link.

**Objective:**
Determine whether the URL was accessed by an endpoint and whether the connection was **allowed or blocked**.

---

## 🚨 Alert

```text
Subject: Action Required: Finalize Your Onboarding Profile
Sender: onboarding@hrconnex.thm
Recipient: j.garcia@thetrydaily.thm
URL: https://hrconnex.thm/onboarding/15400654060/j.garcia
Direction: Inbound
Attachment: None
```

---

## 🧭 Investigation Flow

```text
📧 Email Alert
      │
      ▼
🔗 Extract URL
      │
      ▼
🛡️ Search Proxy Logs
      │
      ▼
🌐 Correlate Network Activity
      │
      ▼
✅ Determine: Allowed / Blocked / No Evidence
```

---

## 🔍 Investigation

### 1. Identify the URL

The email contained the following external URL:

```text
https://hrconnex.thm/onboarding/15400654060/j.garcia
```

The presence of a URL alone does not confirm malicious activity.

---

### 2. Search Proxy Logs

Initial search:

```spl
index=proxy hrconnex.thm
```

**Result:**

```text
0 events
```

A second check was performed:

```spl
index=proxy
```

**Result:**

```text
0 events
```

⚠️ **Important:** A `0 events` result does not automatically mean the alert is a false positive.

The analyst must first verify that:

* the correct index is being searched;
* proxy logs are actually available;
* the time range is correct;
* the relevant fields contain the expected URL/domain.

---

## 🧠 What I Learned

### Data Sources

| Source      | Used to investigate                            |
| ----------- | ---------------------------------------------- |
| 📧 Email    | Sender, recipient, links, attachments          |
| 🛡️ Proxy   | Web/URL access and allowed/blocked requests    |
| 🌐 Network  | Connections between endpoints and destinations |
| 🔥 Firewall | Allowed/blocked network traffic                |
| 💻 Endpoint | Activity occurring directly on the host        |

### Key SOC Principle

> **No evidence is not the same as evidence of no activity.**

Before closing an alert, the analyst must verify that the correct telemetry was available and searched correctly.

---

## 🛠️ Skills Practiced

`Splunk` `SPL` `SIEM` `Email Analysis` `Proxy Logs` `Network Logs` `Log Correlation` `Alert Triage` `False Positive Analysis`

---

## 📚 Lab

**Platform:** TryHackMe
**Focus:** SOC / SIEM Investigation
**Tool:** Splunk
