from flask import Flask, render_template_string, send_file
from integrity_monitor import check_integrity
import os
import hashlib
import zipfile
from datetime import datetime
import shutil
import os
import json

app = Flask(__name__)

EVIDENCE_FOLDER = "evidence"
DEVICE_DB = "known_devices.json"
ALERT_FILE = "alerts.txt"
NAME_DB = "device_names.json"

@app.route("/")
def home():

    check_integrity()

    # Load PCAP files
    files = []
    if os.path.exists(EVIDENCE_FOLDER):
        files =[f for f in os.listdir(EVIDENCE_FOLDER) if f.endswith(".pcap")]
        files.sort(reverse=True)

    # Load known devices
    devices = {}
    if os.path.exists(DEVICE_DB):
        with open(DEVICE_DB, "r") as f:
            devices = json.load(f)

    # Load device names
    names = {}
    if os.path.exists(NAME_DB):
        with open(NAME_DB, "r") as f:
            names = json.load(f)

    # Load alerts
    alerts = []
    if os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "r") as f:
            alerts = f.readlines()
            alerts.reverse()
            alerts = [a for a in alerts if "NO HASH FILE FOUND" not in a]

    # Load traffic statistics
    traffic_packets = 0
    attacker_ip = None

    if os.path.exists("traffic_stats.json"):
        with open("traffic_stats.json", "r") as f:
            data = json.load(f)
            traffic_packets = data.get("packets", 0)
            attacker_ip = data.get("attacker_ip",None)

    traffic_alert = None

    if traffic_packets > 1500:
        traffic_alert = "critical"
    elif traffic_packets > 500:
        traffic_alert = "suspicious"
    else:
        traffic_alert = None

    html = """
    <html>
    <head>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <title>EdgeEvidence SOC Dashboard</title>
        <style>
            body {
                background: #0b0f19;
                color: #e2e8f0;
                font-family: Arial, sans-serif;
                margin: 0;
            }

            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                width: 220px;
                height: 100%;
                background: #111827;
                padding: 20px;
            }

            .sidebar h2 {
                color: #38bdf8;
                margin-bottom: 30px;
            }

            .sidebar a {
                display: block;
                padding: 12px;
                margin-bottom: 10px;
                background: #1e293b;
                color: #cbd5f5;
                text-decoration: none;
                border-radius: 6px;
            }

            .sidebar a:hover {
                background: #334155;
            }

            .main {
                margin-left: 240px;
                padding: 25px;
            }

            .banner {
                background: #7f1d1d;
                padding: 12px;
                border-radius: 6px;
                text-align: center;
                margin-bottom: 20px;
                font-weight: bold;
            }

            .stats {
                display: flex;
                gap: 20px;
                margin-bottom: 25px;
            }

            .stat {
                flex: 1;
                padding: 20px;
                background: #1e293b;
                border-radius: 10px;
                text-align: center;
            }

            .stat span {
                font-size: 32px;
                display: block;
                margin-top: 10px;
            }

            .grid {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 20px;
                margin-top: 20px;
            }

            .panel {
                background: #1e293b;
                padding: 20px;
                border-radius: 10px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
            }

            th, td {
                padding: 8px;
                border-bottom: 1px solid #334155;
                text-align: left;
            }

            th {
                color: #38bdf8;
            }

            .alert {
                color: #f87171;
                margin-bottom: 6px;
            }

            .warning {
                background: #664d03;
                color: #ffe69c;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 10px;
            }

            .safe {
                background: #0f5132;
                color: #a3f7c2;
                padding: 10px;
                border-radius: 6px;
                margin-bottom: 10px;
            }

            button {
                padding: 8px 14px;
                background: #2563eb;
                color: white;
                border: none;
                border-radius: 6px;
                cursor: pointer;
            }

            button:hover {
                background: #1d4ed8;
            }
        </style>
    </head>
    <body>

        <div class="sidebar">
            <h2>EdgeEvidence</h2>
            <a href="/">Dashboard</a>
            <a href="/incidents">Active Incidents</a>
            <a href="/suspicious">Suspicious Events</a>
            <a href="/evidence">Evidence Files</a>
            <a href="/traffic">Traffic Intelligence</a>
        </div>

        <div class="main">
            <h1>🛡️ EdgeEvidence Security Dashboard</h1>

            {% if traffic_alert == "critical" %}
                <div class="banner">
                    ⚠ ACTIVE SECURITY INCIDENT – Possible Port Scan ({{traffic_packets}} packets)
                </div>
            {% elif traffic_alert == "suspicious" %}
                <div class="warning">
                    ⚠ Suspicious Network Activity ({{traffic_packets}} packets)
                </div>
            {% else %}
                <div class="safe">
                    ✔ SYSTEM SECURE
                </div>
            {% endif %}

            <div class="stats">
                <div class="stat">
                    Active Incidents
                    <span>{{incident_count}}</span>
                </div>
                <div class="stat">
                    Suspicious Events
                    <span>{{suspicious_count}}</span>
                </div>
                <div class="stat">
                    Evidence Files
                    <span>{{evidence_count}}</span>
                </div>
            </div>

            <div class="grid">
                <div class="panel">
                    <h2>📡 Known Devices</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Device</th>
                                <th>IP</th>
                                <th>First Seen</th>
                                <th>Last Seen</th>
                                <th>Times</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ip, data in devices.items() %}
                                <tr>
                                    <td>{{names.get(ip, "Unknown")}}</td>
                                    <td>{{ip}}</td>
                                    <td>{{data.first_seen}}</td>
                                    <td>{{data.last_seen}}</td>
                                    <td>{{data.times_seen}}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>

                <div class="panel">
                    <h2>🚨 Alerts</h2>
                    <div id="alerts-box">
                        {% for alert in alerts[:10] %}
                            <div class="alert">{{alert}}</div>
                        {% endfor %}
                    </div>
                </div>
            </div>

            <div class="panel" style="margin-top:20px;">
                <h2>📊 Traffic Intelligence</h2>
                <button onclick="toggleGraph()">Show / Hide Traffic Graph</button>
                <div id="trafficGraph" style="display:none; margin-top:15px;">
                    <img id="trafficImg" src="/static/traffic.png" style="width:100%;">
                </div>
            </div>

            <div class="panel" style="margin-top:20px;">
                <h2>📁 Captured PCAP Files</h2>
                <ul>
                    {% for file in files %}
                        <li>
                            {{file}}
                            <a href="/export/{{file}}" style="margin-left:10px;">Export Case</a>
                        </li>
                    {% endfor %}
                </ul>
            </div>
        </div>

        <script>
            function toggleGraph() {
                let g = document.getElementById("trafficGraph");
                g.style.display = (g.style.display == "none") ? "block" : "none";
            }

            function fetchAlerts() {
                fetch('/get_alerts')
                    .then(response => response.text())
                    .then(data => {
                        document.getElementById("alerts-box").innerHTML = data;
                    });
            }

            setInterval(fetchAlerts, 30000);

            function refreshTraffic() {
                const img = document.getElementById("trafficImg");
                img.src = "/static/traffic.png?t=" + new Date().getTime();
                }

            setInterval(refreshTraffic, 5000);
        </script>

    </body>
    </html>
    """

    # Python
    incident_count = 0
    suspicious_count = 0
    evidence_count = len(files)

    if traffic_alert == "critical":
        incident_count += 1
    elif traffic_alert == "suspicious":
        suspicious_count += 1

    return render_template_string(
        html, 
        files=files, 
        devices=devices, 
        alerts=alerts, 
        names=names,
        traffic_packets=traffic_packets,
        traffic_alert=traffic_alert,
        incident_count=incident_count,
        suspicious_count=suspicious_count,
        evidence_count=evidence_count
    )

@app.route("/incidents")
def incidents():

    incidents = []

    if os.path.exists("alerts.txt"):
        with open("alerts.txt") as f:
            for line in f:
                if "CRITICAL" in line or "Port Scan" in line:
                    incidents.append(line)
    if not incidents:
        incidents.append("No Active Incidents Detected. ")

    return "<br>".join(incidents)

@app.route("/suspicious")
def suspicious():

    suspicious = []

    if os.path.exists("alerts.txt"):
        with open("alerts.txt") as f:
            for line in f:
                if "MEDIUM" in line and "NO HASH FILE FOUND" not in line:
                    suspicious.append(line)
    if not suspicious:
        suspicious.append("No Suspicious Events. ")

    return "<br>".join(suspicious)

@app.route("/evidence")
def evidence():

    files = os.listdir(EVIDENCE_FOLDER)

    return "<br>".join(files)

@app.route("/traffic")
def traffic():
    return """
    <html>
    <head>
        <title>Traffic Intelligence</title>

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

        <style>
            body{
                background:#0b0f19;
                color:white;
                font-family:Arial;
                text-align:center;
                padding:40px;
            }

            canvas{
                background:#111827;
                border-radius:10px;
                padding:20px;
                box-shadow:0px 0px 15px rgba(0,255,204,0.3);
            }
            h2{
                color:#38bdf8;
            }
        </style>

    </head>

    <body>

        <h2>📊 Live Network Traffic Monitor</h2>

        <canvas id="trafficChart" width="800" height="400"></canvas>

        <script>

            let ctx = document.getElementById('trafficChart').getContext('2d');

            let chart = new Chart(ctx,{
                type:'bar',
                data:{
                    labels:["Packets Captured"],
                    datasets:[{
                        label:"Traffic Volume",
                        data:[0],
                        backgroundColor:[
                            '#38bdf8',
                        ]
                    }]
                },
                options:{
                    responsive:true,
                    plugins:{
                        legend:{labels:{color:'white'}}
                    },
                    scales:{
                        x:{ticks:{color:'white'}},
                        y:{ticks:{color:'white'}}
                    }
                }
            });
            function updateTraffic() {
                fetch("/traffic_data")
                .then(response => response.json())
                .then(data => {
                    let packets = data.packets || 0;
                    chart.data.datasets[0].data = [packets];
                    chart.update();
                });
            }
            setInterval(updateTraffic, 3000);
            updateTraffic();

        </script>

    </body>
    </html>
    """

@app.route("/traffic_data")
def traffic_data():

    data = {}
    if os.path.exists("traffic_stats.json"):
        with open("traffic_stats.json") as f:
            data = json.load(f)

    return data

@app.route('/get_alerts')
def get_alerts():
    if os.path.exists(ALERT_FILE):
        with open("alerts.txt") as f:
            lines = f.readlines()
            lines.reverse()
    else:
        lines = []

    formatted = ""
    for line in reversed(lines[-20:]):
        if "CRITICAL" in line:
            formatted += f"<div class='critical'>{line}</div>"
        elif "MEDIUM" in line:
            formatted += f"<div class='medium'>{line}</div>"
        else:
            formatted += f"<div class='normal'>{line}</div>"

    return formatted

@app.route("/export/<filename>")
def export(filename):
    evidence_path = os.path.join("evidence", filename)
    hash_path = evidence_path + ".sha256"

    if not os.path.exists(evidence_path):
        return "File not found", 404

    # Recalculate SHA256
    sha256 = hashlib.sha256()
    with open(evidence_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    recalculated_hash = sha256.hexdigest()

    stored_hash = "NOT FOUND"
    integrity_status = "UNKNOWN"

    if os.path.exists(hash_path):
        with open(hash_path, "r") as hf:
            stored_hash = hf.read().strip()

        if stored_hash == recalculated_hash:
            integrity_status = "VERIFIED"
        else:
            integrity_status = "FAILED (Possible Tampering)"
    else:
        integrity_status = "NO HASH FILE FOUND"

    case_summary = f"""
EdgeEvidence Digital Forensic Report
====================================

Evidence File: {filename}
Export Time: {datetime.now()}

Stored Hash: {stored_hash}
Recalculated Hash: {recalculated_hash}

Integrity Status: {integrity_status}
"""

    zip_filename = filename.replace(".pcap", "_case.zip")
    zip_path = os.path.join("evidence", zip_filename)

    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write(evidence_path, arcname=filename)

        if os.path.exists(hash_path):
            zipf.write(hash_path, arcname=os.path.basename(hash_path))

        zipf.writestr("case_summary.txt", case_summary)

    return send_file(zip_path, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
