# 🌐 HTTP Log Analysis using Splunk

## 🎯 Objective
In this project, the goal is to analyze HTTP logs using Splunk and identify suspicious or abnormal web activity.

By completing this lab, you will:
- Learn how to ingest and analyze HTTP logs using Splunk
- Detect client errors (4xx) and server errors (5xx)
- Identify suspicious user behavior and automated attacks
- Detect large file transfers and unusual URI access attempts

---

## 🖥️ Lab Setup

### ✅ Requirements
- Splunk (already installed and accessible)
- JSON-formatted Zeek-style HTTP logs
- Basic understanding of Splunk Search Processing Language (SPL)

---

## 🌐 Dataset

- **Log File:** `http_logs.json`
- Format: JSON (Zeek HTTP logs)

---

## 📥 Data Ingestion Steps

1. Open Splunk Web
2. Go to **Settings → Add Data**
3. Click **Upload**
4. Select `http_logs.json`
5. Configure:
   - **Source Type:** `json` or `zeek:http`
   - **Index:** `http_lab` (or `main`)
6. Finish setup and confirm indexing

---

## 🔍 Lab Tasks & SPL Queries

### Task 1: Top 10 endpoints generating web traffic
```spl
index=http_lab sourcetype="json"
| stats count by "id.orig_h"
| sort -count
| head 10
