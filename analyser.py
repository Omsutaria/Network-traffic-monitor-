"""
=====================================================
  Network Traffic Monitor & Anomaly Detector
  Author : Om M. Sutaria
  GitHub : https://github.com/OmSutaria/network-traffic-monitor
=====================================================
  Analyses network log files and simulated traffic data
  to detect anomalies: port scans, brute force attempts,
  high-frequency connections, and suspicious IPs.

  Works with:
    - Simulated traffic (built-in demo)
    - CSV-format network logs
    - Text-based connection logs

  Run: python analyser.py
  Run demo: python analyser.py --demo
=====================================================
"""

import sys
import os
import csv
import json
import re
from datetime import datetime
from collections import defaultdict, Counter


# ── COLOURS ─────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"; BOLD = "\033[1m"
    CYAN   = "\033[96m"; GREEN = "\033[92m"
    YELLOW = "\033[93m"; RED   = "\033[91m"
    GRAY   = "\033[90m"; WHITE = "\033[97m"
    BLUE   = "\033[94m"

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7)
    except Exception:
        for a in vars(C):
            if not a.startswith("_"): setattr(C, a, "")


# ── THRESHOLDS ───────────────────────────────────────────────
PORTSCAN_THRESHOLD   = 10   # unique ports from 1 IP in time window → port scan
BRUTEFORCE_THRESHOLD = 20   # failed connections from 1 IP → brute force
HIGHFREQ_THRESHOLD   = 100  # total connections from 1 IP → high frequency
SUSPICIOUS_PORTS     = {4444, 31337, 12345, 6667, 9001}  # common backdoor/C2 ports
RISKY_PORTS = {
    21: "FTP (unencrypted)",   23: "Telnet (unencrypted)",
    3389: "RDP",               5900: "VNC",
    445: "SMB (EternalBlue)",  1433: "MS SQL",
    3306: "MySQL",             27017: "MongoDB",
}


# ── TRAFFIC RECORD ───────────────────────────────────────────
class Connection:
    __slots__ = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                 "bytes_sent", "status", "flags"]
    def __init__(self, timestamp, src_ip, dst_ip, dst_port,
                 protocol="TCP", bytes_sent=0, status="ESTABLISHED", flags=""):
        self.timestamp  = timestamp
        self.src_ip     = src_ip
        self.dst_ip     = dst_ip
        self.dst_port   = int(dst_port)
        self.protocol   = protocol
        self.bytes_sent = int(bytes_sent)
        self.status     = status
        self.flags      = flags


# ── DEMO DATA GENERATOR ──────────────────────────────────────
def generate_demo_traffic():
    """Generate realistic demo traffic including embedded anomalies."""
    import random
    random.seed(42)
    connections = []
    base = datetime(2025, 8, 10, 14, 0, 0)

    def ts(offset_s):
        from datetime import timedelta
        return (base + timedelta(seconds=offset_s)).strftime("%Y-%m-%d %H:%M:%S")

    # Normal web traffic
    normal_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12",
                  "192.168.1.20", "10.0.0.5", "10.0.0.8"]
    normal_ports = [80, 443, 8080, 8443, 53, 587]
    for i in range(180):
        ip   = random.choice(normal_ips)
        port = random.choice(normal_ports)
        connections.append(Connection(ts(i * 2), ip, "203.0.113.1", port,
                                      bytes_sent=random.randint(200, 5000),
                                      status="ESTABLISHED"))

    # ANOMALY 1 — Port scan from 192.168.1.105
    scan_ports = [21,22,23,25,80,110,135,139,143,443,445,1433,3306,3389,5900]
    for i, port in enumerate(scan_ports):
        connections.append(Connection(ts(10 + i), "192.168.1.105",
                                      "192.168.1.1", port,
                                      bytes_sent=64, status="SYN_SENT", flags="SYN"))

    # ANOMALY 2 — Brute force SSH from 10.0.0.88
    for i in range(25):
        connections.append(Connection(ts(50 + i), "10.0.0.88",
                                      "192.168.1.50", 22,
                                      bytes_sent=128, status="FAILED", flags="RST"))

    # ANOMALY 3 — Suspicious backdoor port
    connections.append(Connection(ts(200), "203.0.113.99", "192.168.1.20",
                                  4444, bytes_sent=1024, status="ESTABLISHED"))

    # ANOMALY 4 — High frequency from single IP
    for i in range(120):
        connections.append(Connection(ts(300 + i), "172.16.0.99",
                                      "192.168.1.1", 80,
                                      bytes_sent=512, status="ESTABLISHED"))

    # ANOMALY 5 — Connection to risky port (RDP exposed)
    connections.append(Connection(ts(250), "198.51.100.5", "192.168.1.10",
                                  3389, bytes_sent=2048, status="ESTABLISHED"))

    return connections


# ── CSV LOADER ───────────────────────────────────────────────
def load_from_csv(filepath):
    """
    Load connections from a CSV file.
    Expected columns: timestamp, src_ip, dst_ip, dst_port, protocol, bytes_sent, status
    """
    connections = []
    with open(filepath, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                connections.append(Connection(
                    timestamp  = row.get("timestamp", ""),
                    src_ip     = row.get("src_ip", "0.0.0.0"),
                    dst_ip     = row.get("dst_ip", "0.0.0.0"),
                    dst_port   = row.get("dst_port", 0),
                    protocol   = row.get("protocol", "TCP"),
                    bytes_sent = row.get("bytes_sent", 0),
                    status     = row.get("status", "ESTABLISHED"),
                    flags      = row.get("flags", ""),
                ))
            except Exception:
                continue
    return connections


# ── ANOMALY DETECTION ENGINE ─────────────────────────────────
class AnomalyDetector:
    def __init__(self, connections):
        self.connections = connections
        self.anomalies   = []

    def run_all(self):
        self._detect_port_scans()
        self._detect_brute_force()
        self._detect_high_frequency()
        self._detect_suspicious_ports()
        self._detect_risky_services()
        return self.anomalies

    def _detect_port_scans(self):
        # Group unique destination ports per source IP
        ip_ports = defaultdict(set)
        for c in self.connections:
            ip_ports[c.src_ip].add(c.dst_port)
        for ip, ports in ip_ports.items():
            if len(ports) >= PORTSCAN_THRESHOLD:
                self.anomalies.append({
                    "type":     "PORT SCAN",
                    "severity": "HIGH",
                    "src_ip":   ip,
                    "detail":   f"{len(ports)} unique ports probed: {sorted(ports)[:10]}{'...' if len(ports)>10 else ''}",
                    "recommendation": "Investigate source IP. Block at firewall if unauthorised. Review IDS rules."
                })

    def _detect_brute_force(self):
        ip_fails = Counter()
        for c in self.connections:
            if c.status in ("FAILED", "RST", "REJECTED"):
                ip_fails[c.src_ip] += 1
        for ip, count in ip_fails.items():
            if count >= BRUTEFORCE_THRESHOLD:
                self.anomalies.append({
                    "type":     "BRUTE FORCE ATTEMPT",
                    "severity": "CRITICAL",
                    "src_ip":   ip,
                    "detail":   f"{count} failed connection attempts detected",
                    "recommendation": "Block IP immediately. Enable account lockout policy. Review auth logs."
                })

    def _detect_high_frequency(self):
        ip_count = Counter(c.src_ip for c in self.connections)
        for ip, count in ip_count.items():
            if count >= HIGHFREQ_THRESHOLD:
                self.anomalies.append({
                    "type":     "HIGH FREQUENCY TRAFFIC",
                    "severity": "MEDIUM",
                    "src_ip":   ip,
                    "detail":   f"{count} total connections from this IP",
                    "recommendation": "Investigate for DoS/DDoS or misconfigured client. Consider rate limiting."
                })

    def _detect_suspicious_ports(self):
        seen = set()
        for c in self.connections:
            if c.dst_port in SUSPICIOUS_PORTS and c.src_ip not in seen:
                seen.add(c.src_ip)
                self.anomalies.append({
                    "type":     "SUSPICIOUS PORT ACTIVITY",
                    "severity": "CRITICAL",
                    "src_ip":   c.src_ip,
                    "detail":   f"Connection to port {c.dst_port} — known backdoor/C2 port",
                    "recommendation": "Isolate affected host immediately. Check for malware/RAT. Escalate to IR team."
                })

    def _detect_risky_services(self):
        seen = set()
        for c in self.connections:
            key = (c.src_ip, c.dst_port)
            if c.dst_port in RISKY_PORTS and key not in seen:
                seen.add(key)
                service = RISKY_PORTS[c.dst_port]
                self.anomalies.append({
                    "type":     "RISKY SERVICE EXPOSED",
                    "severity": "MEDIUM",
                    "src_ip":   c.src_ip,
                    "detail":   f"Port {c.dst_port} ({service}) accessible from {c.src_ip}",
                    "recommendation": f"Restrict {service} access via firewall. Use VPN if remote access required."
                })


# ── REPORT GENERATOR ─────────────────────────────────────────
class ReportGenerator:
    SEV_COLOR = {"CRITICAL": C.RED+C.BOLD, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.GREEN}

    def __init__(self, connections, anomalies, source_label="Demo Traffic"):
        self.connections  = connections
        self.anomalies    = anomalies
        self.source_label = source_label
        self.timestamp    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_report(self):
        total    = len(self.connections)
        unique_ips = len(set(c.src_ip for c in self.connections))
        total_bytes = sum(c.bytes_sent for c in self.connections)
        critical = sum(1 for a in self.anomalies if a["severity"] == "CRITICAL")
        high     = sum(1 for a in self.anomalies if a["severity"] == "HIGH")
        medium   = sum(1 for a in self.anomalies if a["severity"] == "MEDIUM")

        print(f"\n{C.BLUE}{'═'*60}{C.RESET}")
        print(f"{C.BOLD}{C.WHITE}  NETWORK TRAFFIC ANOMALY REPORT{C.RESET}")
        print(f"{C.GRAY}  Author    : Om M. Sutaria{C.RESET}")
        print(f"{C.GRAY}  GitHub    : github.com/OmSutaria/network-traffic-monitor{C.RESET}")
        print(f"{C.BLUE}{'═'*60}{C.RESET}")
        print(f"  Source    : {self.source_label}")
        print(f"  Generated : {self.timestamp}")
        print(f"{C.BLUE}{'─'*60}{C.RESET}")
        print(f"  {C.BOLD}SUMMARY{C.RESET}")
        print(f"  Total Connections : {C.WHITE}{total}{C.RESET}")
        print(f"  Unique Source IPs : {C.WHITE}{unique_ips}{C.RESET}")
        print(f"  Total Data        : {C.WHITE}{total_bytes:,} bytes{C.RESET}")
        print(f"  Anomalies Found   : {C.WHITE}{len(self.anomalies)}{C.RESET}  "
              f"({C.RED+C.BOLD}Critical: {critical}{C.RESET}  "
              f"{C.RED}High: {high}{C.RESET}  "
              f"{C.YELLOW}Medium: {medium}{C.RESET})")

        if not self.anomalies:
            print(f"\n  {C.GREEN}✔  No anomalies detected.{C.RESET}\n")
            return

        print(f"\n{C.BLUE}{'─'*60}{C.RESET}")
        print(f"  {C.BOLD}ANOMALY DETAILS{C.RESET}\n")
        for i, a in enumerate(self.anomalies, 1):
            sev_color = self.SEV_COLOR.get(a["severity"], C.WHITE)
            print(f"  {C.BOLD}[{i}] {clr(a['type'], sev_color)}{C.RESET}  —  "
                  f"Severity: {clr(a['severity'], sev_color)}")
            print(f"       Source IP      : {C.CYAN}{a['src_ip']}{C.RESET}")
            print(f"       Detail         : {a['detail']}")
            print(f"       Recommendation : {C.GREEN}{a['recommendation']}{C.RESET}")
            print()

        print(f"{C.BLUE}{'═'*60}{C.RESET}\n")

    def save_report(self, filepath):
        total       = len(self.connections)
        unique_ips  = len(set(c.src_ip for c in self.connections))
        total_bytes = sum(c.bytes_sent for c in self.connections)
        lines = [
            "=" * 60,
            "  NETWORK TRAFFIC ANOMALY REPORT",
            f"  Author    : Om M. Sutaria",
            f"  GitHub    : github.com/OmSutaria/network-traffic-monitor",
            "=" * 60,
            f"  Source    : {self.source_label}",
            f"  Generated : {self.timestamp}",
            "-" * 60,
            "  SUMMARY",
            f"  Total Connections : {total}",
            f"  Unique Source IPs : {unique_ips}",
            f"  Total Data        : {total_bytes:,} bytes",
            f"  Anomalies Found   : {len(self.anomalies)}",
            "",
            "-" * 60,
            "  ANOMALY DETAILS",
            "",
        ]
        for i, a in enumerate(self.anomalies, 1):
            lines += [
                f"  [{i}] {a['type']}  —  Severity: {a['severity']}",
                f"       Source IP      : {a['src_ip']}",
                f"       Detail         : {a['detail']}",
                f"       Recommendation : {a['recommendation']}",
                "",
            ]
        lines += ["=" * 60, "  END OF REPORT", "=" * 60]
        with open(filepath, "w") as f:
            f.write("\n".join(lines))
        return filepath

    def save_json(self, filepath):
        data = {
            "generated": self.timestamp,
            "source":    self.source_label,
            "summary": {
                "total_connections": len(self.connections),
                "unique_ips":        len(set(c.src_ip for c in self.connections)),
                "anomaly_count":     len(self.anomalies),
            },
            "anomalies": self.anomalies,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        return filepath


def clr(text, color): return f"{color}{text}{C.RESET}"


# ── MAIN ─────────────────────────────────────────────────────
def main():
    args = sys.argv[1:]
    demo_mode   = "--demo" in args
    csv_file    = None
    output_dir  = "reports"

    for i, a in enumerate(args):
        if a == "--file" and i + 1 < len(args):
            csv_file = args[i + 1]
        if a == "--output" and i + 1 < len(args):
            output_dir = args[i + 1]

    os.makedirs(output_dir, exist_ok=True)

    print(f"{C.BLUE}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}   NETWORK TRAFFIC MONITOR{C.RESET}")
    print(f"{C.GRAY}   github.com/OmSutaria/network-traffic-monitor{C.RESET}")
    print(f"{C.BLUE}{'═'*60}{C.RESET}\n")

    if csv_file:
        if not os.path.exists(csv_file):
            print(f"  {C.RED}ERROR: File not found: {csv_file}{C.RESET}")
            sys.exit(1)
        print(f"  Loading from: {csv_file}")
        connections  = load_from_csv(csv_file)
        source_label = os.path.basename(csv_file)
    else:
        print(f"  {C.CYAN}No file specified — running built-in demo with simulated traffic.{C.RESET}")
        print(f"  (Use: python analyser.py --file your_log.csv)\n")
        connections  = generate_demo_traffic()
        source_label = "Built-in Demo Traffic (simulated)"

    print(f"  {C.GREEN}✔  Loaded {len(connections)} connection records.{C.RESET}")
    print(f"  Running anomaly detection...\n")

    detector  = AnomalyDetector(connections)
    anomalies = detector.run_all()

    reporter  = ReportGenerator(connections, anomalies, source_label)
    reporter.print_report()

    # Save reports
    ts_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    txt_path = os.path.join(output_dir, f"report_{ts_str}.txt")
    json_path= os.path.join(output_dir, f"report_{ts_str}.json")
    reporter.save_report(txt_path)
    reporter.save_json(json_path)
    print(f"  Reports saved:")
    print(f"    {C.CYAN}{txt_path}{C.RESET}")
    print(f"    {C.CYAN}{json_path}{C.RESET}\n")


if __name__ == "__main__":
    main()
