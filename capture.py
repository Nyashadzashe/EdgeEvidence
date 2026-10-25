import os 
import hashlib
import subprocess
from datetime import datetime, timedelta

def generate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

# ----------- FILE SETTINGS -----------
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
pcap_file = f"evidence/captureA_{timestamp}.pcap"
log_file = "custody_log.txt"
alert_file = "alerts.txt"

print("Capturing traffic...")

# Capture 30 seconds of traffic
os.system(f"sudo timeout 30 tcpdump -i eth0 -w {pcap_file}")

# ----------- HASH GENERATION -----------
print("Generating hash...")
hash_value = generate_hash(pcap_file)

hash_file = pcap_file + ".sha256"
with open(hash_file, "w") as hf:
    hf.write(hash_value)

with open(log_file, "a") as log:
    log.write(f"Evidence File: {pcap_file}\n")
    log.write(f"Captured At: {datetime.now()}\n")
    log.write(f"Hash: {hash_value}")
    log.write("-" * 50 + "\n")

print("Evidence logged.")

# ----------- SIMPLE SUSPICIOUS ACTIVITY DETECTOR -----------

# Count packets quickly
packet_count_output = os.popen(f"tcpdump -r {pcap_file} | wc -l").read()
packet_count = int(packet_count_output.strip())

scan_detector = os.popen(
    "tcpdump -nn -r " + pcap_file + 
    " 'tcp[tcpflags] & tcp-syn != 0' | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -1"
).read()
attacker_ip = None

if scan_detector:
    parts = scan_detector.strip().split()
    if len(parts) >= 2:
        attacker_ip = parts[1]

import json

traffic_stats = {
    "packets": packet_count,
    "attacker_ip": attacker_ip
}
with open("traffic_stats.json", "w") as f:
    json.dump(traffic_stats, f)

# If too many packets in 30 sec → suspicious
if packet_count > 500:
    with open(alert_file, "a") as alert:
        alert.write(f"[{datetime.now()}] HIGH TRAFFIC SPIKE: {packet_count} packets\n")

# If almost no traffic → possible stealth activity
if packet_count < 5:
    with open(alert_file, "a") as alert:
        alert.write(f"[{datetime.now()}] VERY LOW TRAFFIC: possible stealth behavior\n")

