# Network-connection-monitor

# 🌐 Network Connection Monitor and Risk Analysis System

A Python-based desktop application for monitoring active network connections, identifying TCP and UDP connections, analyzing connection information, and providing a basic rule-based risk classification.

## 📌 Project Overview

The **Network Connection Monitor and Risk Analysis System** is a network monitoring application developed using Python.

The application continuously monitors network connections on a computer and displays useful information such as:

* Local IP address
* Local port
* Remote IP address
* Remote port
* Network protocol
* Connection status
* Process ID (PID)
* Risk classification

The system also provides filtering, searching, CSV export, statistics, and a graphical dashboard.

> **Note:** The risk classification in this project is a simple educational, rule-based analysis. It is not intended to replace professional IDS/IPS or security monitoring systems.

---

## 🎯 Objectives

* Monitor active network connections in real time.
* Identify TCP and UDP connections.
* Display local and remote network information.
* Display connection status and process ID.
* Provide basic rule-based risk analysis.
* Allow users to search and filter connections.
* Export monitoring data to CSV files.
* Provide statistical information through a dashboard.
* Visualize TCP/UDP and risk-analysis results using charts.

---

## ✨ Features

### 🔍 Network Monitoring

The application continuously monitors active network connections and displays:

| Information | Description                               |
| ----------- | ----------------------------------------- |
| Protocol    | TCP or UDP                                |
| Local IP    | Local machine IP address                  |
| Local Port  | Port used by the local machine            |
| Remote IP   | Destination IP address when available     |
| Remote Port | Destination port when available           |
| Status      | Current connection status                 |
| PID         | Process ID associated with the connection |
| Risk        | Basic risk classification                 |

### 🔄 Protocol Filtering

Users can filter connections by:

* ALL
* TCP
* UDP

### 🔎 Search

The search feature allows users to search the monitoring table using:

* IP address
* Port
* Protocol
* Status
* PID
* Risk level

### ⚠️ Risk Analysis

Connections are classified using simple predefined rules:

* **NORMAL**
* **WARNING**
* **SUSPICIOUS**

The classification is intended for educational demonstration and basic monitoring.

### 📊 Dashboard

The dashboard displays:

* Total connections
* TCP connections
* UDP connections
* Unique IP addresses
* Normal connections
* Warning connections
* Suspicious connections

It also provides graphical charts for:

* TCP vs UDP connections
* Connection risk analysis

### 📁 CSV Export

Network monitoring information can be exported into CSV format for further analysis.

---

## 🛠️ Technologies Used

### Programming Language

* Python

### Libraries

* `Tkinter` — Graphical User Interface
* `psutil` — Network connection monitoring
* `Matplotlib` — Data visualization
* `csv` — CSV file handling
* `threading` — Background monitoring
* `datetime` — Time information

### Development Tools

* Visual Studio Code
* Git
* GitHub

---

## 💻 System Requirements

### Hardware

* Computer/Laptop
* Minimum 4 GB RAM
* Network connection

### Software

* Windows / Linux / macOS
* Python 3.x
* Visual Studio Code or any Python IDE
* Git

---

## 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/krishnaveni8747-hub/Network-connection-monitor.git
```

### 2. Open the project folder

```bash
cd Network-connection-monitor
```

### 3. Install required libraries

```bash
pip install psutil matplotlib
```

### 4. Run the application

```bash
python network_monitor_gui.py
```

---

## ▶️ How to Use

### Step 1 — Start the application

Run:

```bash
python network_monitor_gui.py
```

### Step 2 — Start monitoring

Click:

**START**

The application will continuously monitor active network connections.

### Step 3 — Select protocol

Use the protocol dropdown:

```text
ALL
TCP
UDP
```

### Step 4 — Search

Enter an IP address, port, protocol, PID, status, or risk level in the search box.

### Step 5 — Stop monitoring

Click:

**STOP**

The collected information will remain available in the table.

### Step 6 — Export data

Click:

**EXPORT CSV**

The monitoring information will be saved as:

```text
network_report.csv
```

### Step 7 — View dashboard

Click:

**DASHBOARD**

The application displays network statistics and charts.

---

## 🏗️ System Architecture

```text
                  ┌───────────────────────┐
                  │         USER          │
                  └───────────┬───────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │   Tkinter GUI         │
                  │                       │
                  │ Start / Stop / Search │
                  │ Filter / Export       │
                  └───────────┬───────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │      psutil           │
                  │                       │
                  │ Network Connections   │
                  └───────────┬───────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │ Connection Analysis   │
                  │                       │
                  │ IP / Port / Protocol  │
                  │ Status / PID          │
                  └───────────┬───────────┘
                              │
                              ▼
                  ┌───────────────────────┐
                  │    Risk Analysis      │
                  │                       │
                  │ Normal / Warning      │
                  │ Suspicious            │
                  └───────────┬───────────┘
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
       ┌──────────────────┐      ┌──────────────────┐
       │   CSV Export     │      │    Dashboard     │
       │                  │      │                  │
       │ Network Report   │      │ Charts & Stats   │
       └──────────────────┘      └──────────────────┘
```

---

## 📦 Project Structure

```text
Network-connection-monitor/
│
├── network_monitor_gui.py
├── .gitignore
├── README.md
│
├── captured_connections.csv
└── network_report.csv
```

> Generated CSV files can be excluded from Git tracking using `.gitignore` if they contain local network information.

---

## 📸 Screenshots

### Main Monitoring Window

Add your screenshot here:

```text
screenshots/main_window.png
```

### TCP Monitoring

Add your TCP screenshot here:

```text
screenshots/tcp_monitoring.png
```

### UDP Monitoring

Add your UDP screenshot here:

```text
screenshots/udp_monitoring.png
```

### Dashboard

Add your dashboard screenshot here:

```text
screenshots/dashboard.png
```

---

## 🔐 Privacy and Security Note

The application displays network information from the local computer.

Users should avoid publishing captured network logs containing sensitive IP addresses, ports, or other private information in public repositories.

The risk analysis feature is intended for **educational purposes** and does not provide guaranteed detection of malicious activity.

---

## 🚀 Future Enhancements

Possible future improvements include:

* Real-time packet-level analysis
* Advanced intrusion detection
* Machine-learning-based anomaly detection
* IP reputation checking
* Geo-location visualization
* Network traffic graphs
* Alert notifications
* Protocol-specific analysis
* Process name identification
* Detailed network activity reports
* Database-based storage

---

## 📚 Learning Outcomes

Through this project, the following concepts are demonstrated:

* Computer Networks
* TCP/IP networking
* UDP communication
* Network connection monitoring
* Python programming
* GUI development
* Multithreading
* Data processing
* CSV file handling
* Data visualization
* Basic network security concepts
* Git and GitHub

---

## 👩‍💻 Author

**Krishnaveni S**

Computer Science and Engineering Student

---

## 📄 License

This project is developed for educational and academic purposes.
