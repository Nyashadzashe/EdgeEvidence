import os
import re
import json
from collections import Counter
from datetime import datetime

ALERT_FILE = "alerts.txt"
DEVICE_DB = "known_devices.json"
THRESHOLD = 50

print("Analyzing traffic...")

# Get latest PCAP file
files = [f for f in os.listdir("evidence") if f.endswith(".pcap")]
files.sort(reverse=True)

if not files:
    print("No pcap files found.")
    exit()

latest = files[0]
path = f"evidence/{latest}"

print(f"Reading: {latest}")

# Read packets
output = os.popen(f"tcpdump -nn -r {path}").read()

ips = re.findall(r'IP (\d+\.\d+\.\d+\.\d+)', output)
counts = Counter(ips)

# Load known devices database
if os.path.exists(DEVICE_DB):
    with open(DEVICE_DB, "r") as f:
        devices = json.load(f)
else:
    devices = {}

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

with open(ALERT_FILE, "a") as alert:

    for ip, count in counts.items():

        # Ignore invalid IP
        if ip == "0.0.0.0":
            continue

        # 🚨 NEW DEVICE DETECTED
        if ip not in devices:
            devices[ip] = {
                "first_seen": now,
                "last_seen": now,
                "times_seen": 1
            }
            msg = f"[{now}] NEW DEVICE detected: {ip}\n"
            print(msg)
            alert.write(msg)

        else:
            devices[ip]["last_seen"] = now
            devices[ip]["times_seen"] += 1


        # 🚨 HIGH TRAFFIC ALERT
        if count > THRESHOLD:
            msg = f"[{now}] HIGH TRAFFIC from {ip} ({count} packets)\n"
            print(msg)
            alert.write(msg)

# Save updated database
with open(DEVICE_DB, "w") as f:
    json.dump(devices, f, indent=4)

