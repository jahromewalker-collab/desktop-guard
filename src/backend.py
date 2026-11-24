"""Read local security state and persist scan records."""
import json
import os
import re
import sqlite3
import stat
import subprocess
import uuid
from datetime import datetime
from pathlib import Path

HOME = Path.home()
DATA = Path(os.environ.get("XDG_DATA_HOME", HOME / ".local/share")) / "desktop-guard"
ADMIN = "/usr/lib/desktop-guard/admin"

def read(path):
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return ""

def capture(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, errors="replace",
                                timeout=8, env={**os.environ, "LC_ALL": "C"})
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""

def config_entries(path, key):
    return re.findall(r"^\s*" + re.escape(key) + r"\s+(.+?)\s*$", read(path), re.M)

def status():
    config = "/etc/clamav/clamd.conf"
    newest = max((p.stat().st_mtime for p in Path("/var/lib/clamav").glob("daily.c[vl]d")),
                 default=None)
    return {
        "watch": config_entries(config, "OnAccessIncludePath"),
        "exclude": config_entries(config, "OnAccessExcludePath"),
        "monitor": capture(["systemctl", "is-active", "clamav-clamonacc"]),
        "fresh": capture(["systemctl", "is-active", "clamav-freshclam"]),
        "database": datetime.fromtimestamp(newest).strftime("%d %b %Y %H:%M") if newest
                    else "Unavailable",
        "ufw": re.search(r"^ENABLED=(yes|no)\s*$", read("/etc/ufw/ufw.conf"), re.M),
    }

def scan_command(paths, full=False):
    command = ["/usr/bin/clamscan", "--recursive", "--stdout", "--infected",
               "--exclude-dir=^" + re.escape(str(DATA / "quarantine")) + "(/|$)"]
    if full:
        command += ["--cross-fs=no"]
        command += ["--exclude-dir=^/" + name + "(/|$)"
                    for name in ("proc", "sys", "dev", "run", "media", "mnt")]
    return command + ["--", *map(str, paths)]

def scan_result(output, code, scope):
    results = {"scope": scope, "time": datetime.now().isoformat(timespec="seconds"),
               "code": code, "details": output, "detections": []}
    for key, label in (("scanned", "Scanned files"), ("infected", "Infected files"),
                       ("errors", "Total errors")):
        match = re.search(r"^" + label + r":\s*(\d+)", output, re.M)
        results[key] = int(match[1]) if match else None
    for line in output.splitlines():
        if not line.endswith(" FOUND") or not line.startswith("/"):
            continue
        path, _, signature = line[:-6].rpartition(": ")
        if path:
            try:
                info = os.lstat(path)
                identity = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
            except OSError:
                identity = None
            results["detections"].append({"path": path, "signature": signature, "identity": identity})
    return results

class Store:
    def __init__(self, directory=DATA):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.vault = directory / "quarantine"
        self.vault.mkdir(exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(directory / "history.sqlite", timeout=5)
        self.db.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, data TEXT)")
        self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value INTEGER)")
        self.db.commit()

    def tray_enabled(self):
        row = self.db.execute("SELECT value FROM settings WHERE key = 'tray'").fetchone()
        return bool(row[0]) if row else True

    def save_tray(self, enabled):
        with self.db:
            self.db.execute("REPLACE INTO settings(key, value) VALUES ('tray', ?)", (int(enabled),))

    def save(self, result):
        with self.db:
            self.db.execute("INSERT INTO scans(data) VALUES (?)", (json.dumps(result),))

    def history(self):
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT data FROM scans ORDER BY id DESC LIMIT 100")]

    def quarantine(self, entry):
        path = Path(entry["path"])
        info = path.lstat()
        identity = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or identity != entry.get("identity")):
            raise ValueError("The file changed or cannot be safely quarantined.")
        folder = self.vault / uuid.uuid4().hex
        folder.mkdir(mode=0o700)
        metadata = folder / "info.json"
        metadata.write_text(json.dumps({**entry, "mode": stat.S_IMODE(info.st_mode)}))
        try:
            path.rename(folder / "file")
        except OSError:
            metadata.unlink()
            folder.rmdir()
            raise
        os.chmod(folder / "file", 0o600)

    def quarantined(self):
        for folder in sorted(self.vault.iterdir()):
            if folder.is_dir() and (folder / "file").is_file():
                try:
                    yield folder, json.loads((folder / "info.json").read_text())
                except (ValueError, OSError):
                    continue

    def resolve(self, folder, entry, restore):
        stored = folder / "file"
        if restore:
            target = Path(entry["path"])
            # Linking fails atomically if the original path has been taken.
            os.link(stored, target)
            try:
                target.chmod(entry["mode"])
            except OSError:
                target.unlink()
                raise
        stored.unlink()
        (folder / "info.json").unlink()
        folder.rmdir()
