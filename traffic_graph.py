import os
import re
from collections import Counter
import matplotlib.pyplot as plt

EVIDENCE_FOLDER = "evidence"

# Find latest pcap
files = [f for f in os.listdir(EVIDENCE_FOLDER) if f.endswith(".pcap")]
files.sort(reverse=True)

if not files:
    exit()

latest = files[0]
path = f"{EVIDENCE_FOLDER}/{latest}"

# Read packets
output = os.popen(f"tcpdump -nn -r {path}").read()

ips = re.findall(r'IP (\d+\.\d+\.\d+\.\d+)', output)
counts = Counter(ips)

# Top 5 devices
top = counts.most_common(5)

if not top:
    exit()

labels = [ip for ip, _ in top]
values = [count for _, count in top]

plt.figure(figsize=(7,4))

bars = plt.bar(labels, values)

plt.title("Top Active Devices in Network", fontsize=14)
plt.xlabel("Device IP", fontsize=12)
plt.ylabel("Packets Captured", fontsize=12)

plt.xticks(rotation=20)
plt.grid(axis='y', linestyle='--', alpha=0.6)

plt.tight_layout()
plt.savefig("static/traffic.png")

