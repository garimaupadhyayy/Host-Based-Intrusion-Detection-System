# Host-Based Intrusion Detection System (HIDS)
<img width="1610" height="851" alt="Screenshot 2026-07-31 204737" src="https://github.com/user-attachments/assets/15efb39d-9e93-4764-b6d5-e1acd0394483" />

A Python-based **Real-Time Host-Based Intrusion Detection System (HIDS)** designed to monitor host activities, detect suspicious behavior, and visualize security events through an interactive Security Operations Center (SOC) dashboard.
The system continuously monitors **network activity, running processes, authentication logs, and file integrity**, generating real-time alerts categorized by severity to help identify potential security threats.

## 🚀 Features

- 🌐 Real-Time Network Monitoring
  - Port scan detection
  - Suspicious DNS request detection
  - Network traffic monitoring

- ⚙️ Process Monitoring
  - Suspicious process detection
  - High CPU & memory usage alerts
  - New process monitoring

- 📄 Log Monitoring
  - Brute-force login detection
  - Error spike detection
  - Suspicious keyword monitoring

- 📁 File Integrity Monitoring
  - File creation detection
  - File modification detection
  - File deletion detection
  - SHA-256 integrity verification

- 📊 Interactive SOC Dashboard
  - Live alert feed
  - Severity breakdown
  - Module health monitoring
  - Alert search & filtering
  - Export alerts to CSV

## 🏗️ Project Architecture

```
                 +---------------------------+
                 |      HIDS Dashboard       |
                 |       Flask Server        |
                 +------------+--------------+
                              |
        --------------------------------------------------
        |               |              |                 |
        ▼               ▼              ▼                 ▼
 Network Monitor   Process Monitor  Log Monitor   File Integrity
        |               |              |                 |
        ---------------- Alert Engine -------------------
                              |
                              ▼
                     Live Dashboard Alerts
```

## 🛠️ Technology Stack

- Python
- Flask
- HTML
- CSS
- JavaScript
- REST API
- File System Monitoring
- SHA-256 Hashing
- Threading


## 📂 Project Structure

```
HIDS_PROJECT/
│
├── dashboard/
│   ├── dashboard.html
│   └── server.py
│
├── network_monitor/
├── process_monitor/
├── log_monitor/
├── file_integrity/
│
├── run_dashboard.py
├── app.py
├── requirements.txt
└── README.md
```

## ⚡ Installation

Clone the repository

```bash
git clone https://github.com/garimaupadhyayy/Host-Based-Intrusion-Detection-System.git
```

Navigate to the project

```bash
cd Host-Based-Intrusion-Detection-System
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Run Dashboard

```bash
python run_dashboard.py
```

Open

```
http://127.0.0.1:5000
```

## 📷 Dashboard Preview

> Add screenshots here

- Dashboard Overview
- Live Alert Feed
- Severity Breakdown
- Module Monitoring


## 🔍 Detection Modules

| Module | Description |
|---------|-------------|
| Network Monitor | Detects suspicious network activity including port scans and DNS anomalies |
| Process Monitor | Monitors running processes and resource abuse |
| Log Monitor | Detects brute-force attacks and suspicious log events |
| File Integrity Monitor | Detects file creation, deletion and unauthorized modifications |

## 📈 Alert Severity Levels

- 🔴 Critical
- 🟠 High
- 🔵 Medium
- 🟢 Low
---

## ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub.
