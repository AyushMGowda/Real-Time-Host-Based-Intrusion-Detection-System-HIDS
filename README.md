# Real-Time Host-Based Intrusion Detection System (HIDS)

A Python-based real-time security monitoring system with a modern GUI that detects suspicious process behavior, brute-force login attempts, and anomalous system activity on Windows.

This project combines process monitoring, Windows Security Event Log analysis, and behavioral detection logic to simulate a lightweight Host-Based Intrusion Detection System (HIDS).

---

## 🚀 Features

### 🔎 Process Monitoring Engine
- Real-time tracking of all running processes
- Process creation detection
- Sustained high CPU anomaly detection
- Per-process alert suppression (cooldown logic)

### 🛡 Suspicious Process Detection
- Detects execution of high-risk binaries:
  - `cmd.exe` → MITRE T1059 (Command Execution)
  - `powershell.exe` → MITRE T1059
  - `wmic.exe` → MITRE T1047
  - `rundll32.exe` → MITRE T1218
- MITRE ATT&CK technique mapping included in alerts

### 🔐 Brute-Force Attack Detection
- Monitors Windows Security Log (Event ID 4625)
- Detects multiple failed logins within 2-minute window
- Flags possible brute-force attacks
- Escalates to CRITICAL if login succeeds after failures
- Stateful event tracking (no duplicate reprocessing)

### 📊 Resource Anomaly Detection
- System-wide CPU and Memory threshold monitoring
- Threshold-based alerting
- State-aware recovery detection

### 🎛 Modern Security Dashboard
- Real-time severity counters (INFO / MEDIUM / HIGH / CRITICAL)
- Dark-themed security console UI
- Event filtering:
  - All Events
  - Process Events
  - Resource Usage
  - Security Alerts
- Color-coded severity logging

### 📁 Log Management
- Structured logging (timestamp, severity, category)
- CSV export support
- Log clearing and reset functionality

---

## 🧠 Detection Techniques Used

- Sliding time-window correlation (brute-force detection)
- Stateful Windows Event Log tracking (RecordNumber-based)
- Alert suppression (cooldown logic)
- Behavioral process detection
- MITRE ATT&CK mapping for attack classification

---

## 🛠 Requirements

- Python 3.8+
- Windows OS
- Administrative privileges (required for Security Log access)

### Dependencies

Install manually:

```bash
pip install psutil pywin32
```
```bash
git clone https://github.com/AyushMGowda/Real-Time-Host-Based-Intrusion-Detection-System-HIDS.git
```
```bash
cd Real-Time-Host-Based-Intrusion-Detection-System-HIDS
```
```bash
python -m venv venv
```
```bash
venv\Scripts\activate
```
```bash
pip install -r requirements.txt
```

### Running the Application
Run as Administrator in system terminal:

```bash
python security_logger.py
```
