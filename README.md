# Advanced USB & Mobile Endpoint Monitoring Framework

A Windows-based **Endpoint Monitoring & DLP Framework** designed to track:

- USB Mass Storage devices
- Mobile devices using MTP (Android / iOS)
- File transfers between system ↔ USB
- File modification, deletion, and renaming
- Forensic-ready audit reporting

---

## 🚀 Features

### 🔌 USB Device Monitoring
- Detects USB insert/remove events
- Captures VID, PID, Serial Number
- Maintains full USB history

### 📱 Mobile (MTP) Detection
- Detects Android & iOS devices
- Bypasses traditional drive-letter limitation
- Works for Samsung, Xiaomi, Oppo, Vivo, Apple, etc.

### 📂 File Activity Monitoring (DLP)
- SYSTEM → USB copy detection
- USB → SYSTEM copy detection
- File modification, rename, deletion tracking
- Snapshot-based forensic logic

### 🧾 Audit Report Generation
- One-click report export
- Time-stamped forensic logs
- Compliance & investigation ready

### 🖥 GUI Interface
- Built using Tkinter
- Multi-tab professional layout
- Real-time logging

---

## 🛠 Requirements

- Windows OS
- Python 3.9+
- Administrator privileges (recommended)

No external Python libraries required.

---

## ▶ How to Run

```bash
git clone https://github.com/yourusername/Advanced-Endpoint-Monitoring-Framework.git
cd Advanced-Endpoint-Monitoring-Framework/src
python advanced_endpoint_monitor.py
