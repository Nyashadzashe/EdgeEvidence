import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

CAPTURE_DIR = Path("/var/lib/edgeevidence/captures")
COMPLETED_LIST = CAPTURE_DIR / "completed_captures.txt"
MANIFEST = CAPTURE_DIR / "evidence_manifest.json"
ALERTS = CAPTURE_DIR / "integrity_alerts.log"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def log_alert(message):
    timestamp = datetime.now(timezone.utc).isoformat()
    with ALERTS.open("a") as output:
        output.write(f"{timestamp} {message}\n")
    print(f"INTEGRITY ALERT: {message}")


def main():
    if not COMPLETED_LIST.exists():
        print("No completion list found; nothing to hash.")
        return

    try:
        records = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else []
    except (json.JSONDecodeError, OSError) as exc:
        raise SystemExit(f"Cannot read manifest safely: {exc}")

    if not isinstance(records, list):
        raise SystemExit("Manifest format is unexpected; refusing to overwrite it.")

    known = {item.get("file"): item for item in records if isinstance(item, dict)}
    names = COMPLETED_LIST.read_text().splitlines()
    changed = False

    for entry in names:
        path = Path(entry.strip())
        if not path.is_absolute():
            path = CAPTURE_DIR / path

        if path.parent != CAPTURE_DIR or path.suffix != ".pcapng":
            continue
        if not path.is_file():
            continue

        # Require unchanged size and modification time across a short interval.
        try:
            before = path.stat()
            time.sleep(2)
            after = path.stat()
        except OSError as exc:
            print(f"Skipping inaccessible capture {path.name}: {exc}")
            continue

        if (before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns):
            print(f"Skipping capture that is still changing: {path.name}")
            continue

        digest = sha256_file(path)
        final_stat = path.stat()
        if (final_stat.st_size != after.st_size or
                final_stat.st_mtime_ns != after.st_mtime_ns):
            print(f"Skipping capture changed during hashing: {path.name}")
            continue

        previous = known.get(path.name)
        sidecar = path.with_name(path.name + ".sha256")

        if previous:
            if previous.get("sha256") != digest:
                log_alert(
                    f"Previously recorded hash differs for {path.name}; "
                    "manual investigation required"
                )
                previous["status"] = "REVIEW_REQUIRED"
                previous["observed_sha256"] = digest
                previous["last_checked_at"] = datetime.now(
                    timezone.utc
                ).isoformat()
                changed = True
            continue

        # Do not overwrite an existing sidecar whose provenance is unknown.
        if sidecar.exists():
            print(f"Existing sidecar preserved for review: {sidecar.name}")
            continue

        sidecar.write_text(f"{digest}  {path.name}\n")
        record = {
            "file": path.name,
            "size_bytes": final_stat.st_size,
            "sha256": digest,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "status": "hashed"
        }
        records.append(record)
        known[path.name] = record
        changed = True
        print(f"Hashed completed capture: {path.name}")

    if changed:
        temporary = MANIFEST.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(records, indent=2) + "\n")
        os.replace(temporary, MANIFEST)
        print(f"Manifest updated: {MANIFEST}")
    else:
        print("No new manifest records required.")


if __name__ == "__main__":
    main()
