"""Apply Desktop Guard's opt-in ClamAV Home profile."""
import fcntl
import os
import pwd
import re
import subprocess
import tempfile
from pathlib import Path

CONFIG = Path("/etc/clamav/clamd.conf")
OVERRIDE = Path("/etc/systemd/system/clamav-clamonacc.service.d/zz-desktop-guard.conf")
SERVICE = "clamav-clamonacc.service"
DAEMON = "clamav-daemon.service"
UNIT = """[Service]
ExecStart=
ExecStart=/usr/sbin/clamonacc --foreground --fdpass --log=/var/log/clamav/clamonacc.log
"""

def home_config(previous, home):
    existing = re.findall(r"^\s*OnAccessIncludePath[ \t]+(.+)$", previous, re.M)
    unrelated = [entry for entry in existing if not Path(entry.strip()).is_relative_to(home)]
    if unrelated or re.search(r"^\s*OnAccessMountPath\s+", previous, re.M):
        raise ValueError("The current ClamAV configuration has custom watched locations. Review it before changing coverage.")
    daemon_user = re.search(r"^\s*User[ \t]+(\S+)", previous, re.M)
    if not daemon_user or daemon_user[1] != "clamav":
        raise ValueError("This profile requires the standard Mint ClamAV daemon account.")
    keys = r"OnAccessIncludePath|OnAccessExcludeUname|OnAccessPrevention|OnAccessDisableDDD"
    lines = [line for line in previous.splitlines() if not re.match(r"\s*(?:" + keys + r")\s+", line)]
    excludes = {entry.strip() for entry in re.findall(r"^\s*OnAccessExcludePath[ \t]+(.+)$", previous, re.M)}
    for name in (".cache", ".local/share/Trash", ".local/share/Steam",
                 ".local/share/desktop-guard"):
        path = str(home / name)
        if path not in excludes:
            lines.append("OnAccessExcludePath " + path)
    lines += ["OnAccessIncludePath " + str(home), "OnAccessExcludeUname clamav",
              "OnAccessPrevention yes"]
    return "\n".join(lines) + "\n"

def atomic_write(path, content, mode, owner=None):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        name = Path(temporary.name)
        try:
            if owner is not None:
                os.fchown(temporary.fileno(), *owner)
            os.fchmod(temporary.fileno(), mode)
            temporary.write(content.encode())
            temporary.flush()
            os.fsync(temporary.fileno())
            os.replace(name, path)
        finally:
            name.unlink(missing_ok=True)

def systemctl(*args, checked=True):
    subprocess.run(["/usr/bin/systemctl", *args], check=checked, timeout=45)

def apply_home():
    uid = int(os.environ["PKEXEC_UID"])
    home = Path(pwd.getpwuid(uid).pw_dir)
    if uid == 0 or not home.is_absolute() or home == Path("/") or "\n" in str(home) or "\r" in str(home):
        raise ValueError("Unable to determine a supported home directory.")
    with open("/run/desktop-guard-clamav.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        previous = CONFIG.read_text()
        updated = home_config(previous, home)
        original_stat = CONFIG.stat()
        mode = original_stat.st_mode & 0o777
        owner = original_stat.st_uid, original_stat.st_gid
        before_unit = OVERRIDE.read_text() if OVERRIDE.exists() else None
        active = subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", SERVICE]).returncode == 0
        enabled = subprocess.run(["/usr/bin/systemctl", "is-enabled", "--quiet", SERVICE]).returncode == 0
        backup = CONFIG.with_name("clamd.conf.desktop-guard-backup")
        if not backup.exists():
            atomic_write(backup, previous, mode, owner)
        OVERRIDE.parent.mkdir(parents=True, exist_ok=True)
        try:
            atomic_write(CONFIG, updated, mode, owner)
            atomic_write(OVERRIDE, UNIT, 0o644)
            systemctl("daemon-reload")
            systemctl("restart", DAEMON)
            systemctl("enable", SERVICE)
            systemctl("restart", SERVICE)
            systemctl("is-active", "--quiet", SERVICE)
        except (OSError, subprocess.SubprocessError):
            atomic_write(CONFIG, previous, mode, owner)
            if before_unit is None:
                OVERRIDE.unlink(missing_ok=True)
            else:
                atomic_write(OVERRIDE, before_unit, 0o644)
            systemctl("daemon-reload", checked=False)
            systemctl("restart", DAEMON, checked=False)
            systemctl("restart" if active else "stop", SERVICE, checked=False)
            if not enabled:
                systemctl("disable", SERVICE, checked=False)
            raise
        print("ClamAV is configured to watch " + str(home))
