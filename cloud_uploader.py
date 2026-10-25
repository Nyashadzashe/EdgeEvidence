import hashlib
import json
import time
from pathlib import Path

from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

BASE_DIR = Path(__file__).resolve().parent
CAPTURE_DIR = Path("/var/lib/edgeevidence/captures")
COMPLETED_LIST = CAPTURE_DIR / "completed_captures.txt"
UPLOADED_LOG = BASE_DIR / "uploaded_files.json"
SETTINGS_FILE = BASE_DIR / "settings.yaml"
CREDENTIALS_FILE = BASE_DIR / "credentials.json"

def get_drive():
    try:
        auth = GoogleAuth(settings_file=str(SETTINGS_FILE))
        auth.LoadCredentialsFile(str(CREDENTIALS_FILE))
        if auth.credentials is None:
            raise RuntimeError("Saved Google Drive credentials not found")
        if auth.access_token_expired:
            auth.Refresh()
            auth.SaveCredentialsFile(str(CREDENTIALS_FILE))
        else:
            auth.Authorize()
        return GoogleDrive(auth)
    except Exception as exc:
        print(f"[Cloud ERROR] Authentication failed: {exc}")
        return None

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def load_history():
    try:
        return json.loads(UPLOADED_LOG.read_text())
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Upload history is invalid; refusing to overwrite: {exc}")

def save_history(history):
    temp = UPLOADED_LOG.with_suffix(".json.tmp")
    temp.write_text(json.dumps(history, indent=2) + "\n")
    temp.replace(UPLOADED_LOG)

def list_remote_files(drive):
    remote = {}
    page_token = None
    while True:
        params = {
            "q": "trashed = false",
            "maxResults": 1000,
            "orderBy": "createdDate",
        }
        if page_token:
            params["pageToken"] = page_token
        response = drive.ListFile(params).GetList()
        for item in response:
            remote.setdefault(item.get("title", ""), []).append(item)
        # PyDrive2 ListFile.GetList handles its own pagination in common versions.
        # Stop if the returned page is empty to avoid an endless loop.
        if not response or len(response) < 1000:
            break
        # If a backend version does not expose page tokens, don't guess one.
        break
    return remote

def upload_or_reuse(drive, path, history, remote):
    digest = sha256_file(path)
    key = str(path)
    name = path.name

    # Reuse a remote file with this name to avoid creating duplicates.
    matches = remote.get(name, [])
    if matches:
        item = matches[0]
        history[key] = {
            "sha256": digest,
            "drive_id": item.get("id"),
            "filename": name,
            "status": "existing_remote_reused",
        }
        save_history(history)
        print(f"[Cloud] Reusing existing remote filename: {name}")
        return True

    item = drive.CreateFile({"title": name})
    item.SetContentFile(str(path))
    item.Upload()

    drive_id = item.get("id")
    if not drive_id:
        print(f"[Cloud ERROR] Upload returned no Drive ID: {name}")
        return False

    history[key] = {
        "sha256": digest,
        "drive_id": drive_id,
        "filename": name,
        "status": "uploaded",
    }
    save_history(history)
    remote.setdefault(name, []).append({"id": drive_id, "title": name})
    print(f"[Cloud] Uploaded: {name}")
    return True

def stable_file(path):
    try:
        first = path.stat()
        time.sleep(2)
        second = path.stat()
        return (
            first.st_size == second.st_size
            and first.st_mtime_ns == second.st_mtime_ns
            and second.st_size > 0
        )
    except OSError:
        return False

def main():
    if not CAPTURE_DIR.is_dir():
        print(f"[Cloud ERROR] Capture directory missing: {CAPTURE_DIR}")
        return

    if not COMPLETED_LIST.is_file():
        print("[Cloud] Completion list missing; no uploads attempted.")
        return

    try:
        history = load_history()
    except RuntimeError as exc:
        print(f"[Cloud ERROR] {exc}")
        return

    drive = get_drive()
    if drive is None:
        return

    remote = list_remote_files(drive)
    names = []
    for line in COMPLETED_LIST.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        path = Path(line)
        if not path.is_absolute():
            path = CAPTURE_DIR / path
        if path.parent == CAPTURE_DIR and path.suffix == ".pcapng":
            names.append(path.name)

    for name in dict.fromkeys(names):
        capture = CAPTURE_DIR / name
        sidecar = CAPTURE_DIR / (name + ".sha256")

        if not capture.is_file():
            print(f"[Cloud] Capture no longer local; skipping: {name}")
            continue
        if not stable_file(capture):
            print(f"[Cloud] Capture not stable; skipping: {name}")
            continue
        if not sidecar.is_file():
            print(f"[Cloud] No SHA-256 sidecar; skipping: {name}")
            continue

        try:
            actual_hash = sha256_file(capture)
            stored = sidecar.read_text().strip().split()
            sidecar_hash = stored[0] if stored else ""
            if actual_hash != sidecar_hash:
                print(f"[Cloud ERROR] Local sidecar mismatch; skipping pair: {name}")
                continue

            # Upload/reuse capture first; only then upload/reuse its sidecar.
            if not upload_or_reuse(drive, capture, history, remote):
                print(f"[Cloud] Sidecar skipped because capture upload failed: {name}")
                continue

            if not upload_or_reuse(drive, sidecar, history, remote):
                print(f"[Cloud ERROR] Sidecar upload failed: {sidecar.name}")
        except Exception as exc:
            print(f"[Cloud ERROR] {name}: {exc}")

if __name__ == "__main__":
    main()
