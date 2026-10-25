from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/stats")
def get_stats():

    evidence_folder = "../evidence"

    pcap_files = 0

    if os.path.exists(evidence_folder):
        pcap_files = len([
            f for f in os.listdir(evidence_folder)
            if f.endswith(".pcap")
        ])

    return {
        "captured_files": pcap_files,
        "tampered_files": 2,
        "integrity_status": "Secure",
        "monitoring_status": "Active"
}
@app.get("/alerts")
def get_alerts():

    alert_file = "../alerts.txt"

    if not os.path.exists(alert_file):
        return []

    with open(alert_file, "r") as f:
        lines = f.readlines()

    lines.reverse()

    alerts = [line.strip() for line in lines[:10]]

    return alerts

@app.get("/traffic")
def get_traffic():

    stats_file = "../traffic_stats.json"

    if not os.path.exists(stats_file):
        return {
            "packets": 0,
            "attacker_ip": "Unknown"
        }

    with open(stats_file, "r") as f:
        data = json.load(f)

    return data
@app.get("/evidence")
def get_evidence():

    evidence_folder = "../evidence"

    evidence_files = []

    if not os.path.exists(evidence_folder):
        return []

    for file in os.listdir(evidence_folder):

        if file.endswith(".pcap"):

            file_path = os.path.join(evidence_folder, file)

            hash_file = file_path + ".sha256"

            hash_value = "Unavailable"

            if os.path.exists(hash_file):
                with open(hash_file, "r") as hf:
                    hash_value = hf.read().strip()

            created_time = os.path.getctime(file_path)

            evidence_files.append({
                "filename": file,
                "hash": hash_value[:20] + "...",
                "created": created_time
            })

    return evidence_files
