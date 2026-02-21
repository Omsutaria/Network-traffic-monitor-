# 📡 Network Traffic Monitoring & Anomaly Detection

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Wireshark](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square)
![Nmap](https://img.shields.io/badge/Tool-Nmap-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

> A Python-based network analysis project that parses PCAP capture files, detects anomalous traffic patterns (port scans, SYN floods, suspicious IPs), and generates structured incident reports.

---

## 🎯 What It Does

- 📥 **Load PCAP files** exported from Wireshark
- 🔍 **Detect anomalies** — port scans, SYN flood patterns, repeated failed connections
- 🚩 **Flag suspicious IPs** based on connection frequency thresholds
- 📄 **Generate a formatted incident report** in `.txt` format ready for documentation
- 📊 **Summary statistics** — total packets, protocol breakdown, top talkers

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python 3 | Core analysis scripts |
| `scapy` | PCAP file parsing & packet inspection |
| `collections` | Counting & frequency analysis |
| Wireshark | Capturing live traffic (external tool) |
| Nmap | Network scanning for lab setup |

---

## 🚀 Getting Started

```bash
# 1. Clone the repository
git clone https://github.com/OmSutaria/network-traffic-monitor.git
cd network-traffic-monitor

# 2. Install dependencies
pip install scapy

# 3. Run the analyser on a PCAP file
python analyser.py --file captures/sample_capture.pcap

# 4. Generate a report
python analyser.py --file captures/sample_capture.pcap --report
```

---

## 📂 Project Structure

```
network-traffic-monitor/
│
├── analyser.py              # Main analysis script
├── anomaly_detector.py      # Detection logic (port scan, SYN flood)
├── report_generator.py      # Formats and exports incident reports
├── captures/
│   └── sample_capture.pcap  # Sample PCAP file for testing
├── reports/
│   └── sample_report.txt    # Example generated report
└── README.md
```

---

## 📄 Sample Incident Report Output

```
================================================
  NETWORK ANOMALY REPORT
  Generated : 2025-08-10 16:45:00
  PCAP File : sample_capture.pcap
================================================

SUMMARY
  Total Packets Analysed : 4,821
  Flagged Events         : 3
  Unique IPs Seen        : 47

⚠️  ANOMALY #1 — Possible Port Scan
  Source IP   : 192.168.1.105
  Ports Hit   : 22, 23, 80, 443, 3306, 8080, 8443
  Time Window : 00:00:03
  Severity    : HIGH

⚠️  ANOMALY #2 — SYN Flood Pattern
  Source IP   : 10.0.0.88
  SYN Packets : 312 in 5 seconds
  Severity    : CRITICAL

RECOMMENDATION
  Investigate 192.168.1.105 — review firewall logs and block if unauthorised.
  Rate-limit or blackhole 10.0.0.88 at the perimeter firewall.
================================================
```

---

## 💡 How the Detection Works

**Port Scan Detection:**
If a single source IP connects to more than 10 unique destination ports within a 5-second window, it's flagged as a potential port scan.

**SYN Flood Detection:**
If more than 200 SYN packets arrive from the same source IP within 5 seconds with no corresponding ACK responses, it's flagged as a SYN flood attempt.

---

## ⚠️ Disclaimer

For educational and lab use only. Always have proper authorisation before capturing or analysing network traffic.

---

## 👤 Author

**Om M. Sutaria**
📧 omsutaria.om@gmail.com | 🔗 [GitHub](https://github.com/OmSutaria)

---

## 📜 License

MIT License
