# 🌐 HTTP Log Analysis using Splunk

## 📌 Project Overview
This project demonstrates how to analyze HTTP web logs using **Splunk** to detect suspicious activity, monitor traffic behavior, and identify potential security threats.

The focus is on real-world SOC (Security Operations Center) log analysis techniques such as error detection, anomaly identification, and malicious activity monitoring.

---

## 🎯 Project Objective
The main objectives of this project are:

- Ingest and analyze HTTP logs using Splunk
- Detect client-side errors (4xx) and server-side errors (5xx)
- Identify suspicious user agents (bots, scanners, scripts)
- Detect large file transfers (possible data exfiltration)
- Identify suspicious URI access attempts (attack patterns)
- Build basic SOC-level log analysis skills

---

## 🛠️ Tools & Technologies

- 🟣 Splunk Enterprise / Splunk Free
- 📄 JSON-formatted Zeek HTTP logs
- 🔍 SPL (Search Processing Language)
- 🧠 Cybersecurity Log Analysis Concepts

---

## 🖥️ Dataset Information

- **Log Type:** HTTP Web Logs (Zeek-style format)
- **Format:** JSON
- **Fields include:**
  - Source IP (`id.orig_h`)
  - Destination IP (`id.resp_h`)
  - URI (`uri`)
  - Status Code (`status_code`)
  - User-Agent (`user_agent`)
  - Response Size (`resp_body_len`)
  - Timestamp (`ts`)

---

## 🔍 Analysis Tasks & SPL Queries

---

### 📊 Task 1: Top 10 Source IPs Generating Traffic
```spl
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10

👉 Identifies most active clients (possible scanning or bots)

🚨 Task 2: Detect Server Errors (5xx)
index=http_lab sourcetype="json" status_code>=500 status_code<600
| stats count as server_errors

👉 Helps detect server instability or attack attempts

🤖 Task 3: Detect Suspicious User Agents
index=http_lab sourcetype="json"
user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0")
| stats count by user_agent

👉 Identifies automated tools and possible attackers

📦 Task 4: Large File Transfers (>500 KB)
index=http_lab sourcetype="json" resp_body_len>500000
| table ts "id.orig_h" "id.resp_h" uri resp_body_len
| sort -resp_body_len

👉 Detects possible data exfiltration activity

⚠️ Task 5: Suspicious URI Access Attempts
index=http_lab sourcetype="json"
uri IN ("/admin","/shell.php","/etc/passwd")
| stats count by uri, "id.orig_h"

👉 Identifies attack attempts on sensitive endpoints
```
📊 Key Insights

From this analysis, the following behaviors can be detected:

High-volume traffic from specific IPs → possible scanning or bot activity
Server errors (5xx) → application issues or exploitation attempts
Suspicious user agents → automated attack tools
Large file transfers → potential data exfiltration
Sensitive URI access → probing or exploitation attempts

🚨 Security Relevance (SOC Perspective)
This project simulates real SOC analyst tasks:

Log ingestion and parsing
Threat hunting using SPL queries
Behavioral anomaly detection
Identifying attacker patterns
Monitoring web application security
