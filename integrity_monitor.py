import os
import shutil
import json
import hashlib
from datetime import datetime
import smtplib
import time
import sys
from cloud_uploader import upload_old_evidence
from email.mime.text import MIMEText

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "nyashadzashencubear@gmail.com"
EMAIL_PASSWORD = "oudwzqijafhwirce"
ALERT_RECIPIENT = "nyashadzashencubear@gmail.com"


EVIDENCE_FOLDER = "evidence"
ALERT_FILE = "alerts.txt"

ALERTED_LOG = "alerted_files.txt"

def system_banner():
    print("\n" + "="*60)
    print(" EDGE EVIDENCE FORENSIC MONITOR v2.0")
    print("="*60)
    print("[✔] Evidence Folder Monitoring Enabled")
    print("[✔] SHA256 Integrity Validation Active")
    print("[✔] Email Alert System Online")
    print("[✔] Case Auto-Generation Enabled")
    print("[✔] Chain of Custody Logging Enabled")
    print("="*60 + "\n")
    time.sleep(1)

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def log_alert(message):
    with open(ALERT_FILE, "a") as f:
        f.write(f"[{datetime.now()}] {message}\n")

def create_case(file_name, hash_value):
    case_id = "CASE-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    case_path = os.path.join("cases", case_id)

    os.makedirs(case_path)
    os.makedirs(os.path.join(case_path, "evidence"))
    os.makedirs(os.path.join(case_path, "hashes"))

    # Move evidence file
    src = os.path.join("evidence", file_name)
    dst = os.path.join(case_path, "evidence", file_name)
    shutil.move(src, dst)

    # Save hash file
    with open(os.path.join(case_path, "hashes", file_name + ".sha256"), "w") as f:
        f.write(hash_value)

# Create custody log
    with open(os.path.join(case_path, "custody_log.txt"), "w") as f:
        f.write(f"[{datetime.now()}] Case created automatically due to tampering.\n")

    # Create metadata
    metadata = {
        "case_id": case_id,
        "file": file_name,
        "created_at": str(datetime.now()),
        "reason": "Tampering detected"
    }

    with open(os.path.join(case_path, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=4)

    return case_id

def send_email_alert(subject, message):
    try:
        msg = MIMEText(message)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = ALERT_RECIPIENT

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, ALERT_RECIPIENT, msg.as_string())
        server.quit()

        print("Email alert sent successfully.")

    except Exception as e:
        print("Email Sending failed:", e)

def mark_alerted(filename):
    with open(ALERTED_LOG, "a") as f:
        f.write(filename + "\n")

def calculate_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def check_integrity():
    if not os.path.exists(EVIDENCE_FOLDER):
        return

    for file in os.listdir(EVIDENCE_FOLDER):
        if file.endswith(".pcap"):
            evidence_path = os.path.join(EVIDENCE_FOLDER, file)
            hash_path = evidence_path + ".sha256"

            if os.path.exists(hash_path):
                recalculated = calculate_hash(evidence_path)

                with open(hash_path, "r") as hf:
                    stored = hf.read().strip()

                if recalculated != stored:
                    case_id = create_case(file, recalculated)
                    alert_msg = f"[CRITICAL] HASH MISMATCH\nFile: {file}\nCase ID: {case_id}\nTimestamp: {datetime.now()}"
                    print(alert_msg)
                    log_alert(alert_msg)
                    send_email_alert("CRITICAL: Evidence Tampering Detected", alert_msg)
                    mark_alerted(file)

    for hash_file in os.listdir(EVIDENCE_FOLDER):
        if hash_file.endswith(".sha256"):
            original = hash_file.replace(".sha256", "")
            original_path = os.path.join(EVIDENCE_FOLDER, original)

            if not os.path.exists(original_path):
                alert_msg = f"[CRITICAL] EVIDENCE FILE DELETED\nMissing File: {original}\nTimestamp: {datetime.now()}"
                print(alert_msg)
                log_alert(alert_msg)
                send_email_alert("CRITICAL: Evidence Deleted",alert_msg)
                mark_alerted(file)
            else:
                alert_msg = f"[MEDIUM] NO HASH FILE FOUND\nFile: {file}\nTimestamp: {datetime.now()}"
                print(alert_msg)
                log_alert(alert_msg)
                send_email_alert("Evidence Tampering Detected", alert_msg)
                mark_alerted(file)
                upload_old_evidence()

def generate_report():
    total = 0
    valid = 0
    tampered = 0

    for file in os.listdir(EVIDENCE_FOLDER):
        if file.endswith(".pcap"):
            total += 1
            evidence_path = os.path.join(EVIDENCE_FOLDER, file)
            hash_path = evidence_path + ".sha256"

            if os.path.exists(hash_path):
                recalculated = calculate_hash(evidence_path)
                with open(hash_path, "r") as hf:
                    stored = hf.read().strip()
                if recalculated == stored:
                    valid += 1
                else:
                    tampered += 1
            else:
                tampered += 1

    print("\n====== INTEGRITY REPORT ======")
    print(f"Total Evidence Files: {total}")
    print(f"Valid Files: {valid}")
    print(f"Tampered/Missing: {tampered}")
    print("==============================\n")

if __name__ == "__main__":
    system_banner()
    if "--report" in sys.argv:
        generate_report()
    else:
        check_integrity()
