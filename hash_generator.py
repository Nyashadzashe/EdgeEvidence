import os
import hashlib

EVIDENCE_FOLDER = "evidence"

def calculate_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

for file in os.listdir(EVIDENCE_FOLDER):
    if file.endswith(".pcap"):
        evidence_path = os.path.join(EVIDENCE_FOLDER, file)
        hash_path = evidence_path + ".sha256"

        if not os.path.exists(hash_path):
            h = calculate_hash(evidence_path)
            with open(hash_path, "w") as hf:
                hf.write(h)
            print("Created hash for:", file)
