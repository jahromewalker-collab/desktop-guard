#!/bin/bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
chmod 755 "$stage"
install -d "$stage/DEBIAN" outputs
cat > "$stage/DEBIAN/control" <<'CONTROL'
Package: desktop-guard
Version: 0.1.1
Architecture: all
Section: utils
Priority: optional
Maintainer: Desktop Guard contributors
Depends: python3, python3-gi, python3-gi-cairo, gir1.2-gtk-3.0, pkexec, clamav, clamav-daemon, clamav-freshclam, rkhunter, ufw, gufw, timeshift, iproute2
Description: Desktop security dashboard for Linux Mint
 Manage on-demand scans and review protection, local firewall rules,
 network activity and system snapshots through a Cinnamon desktop app.
CONTROL
install -Dm755 src/desktop-guard "$stage/usr/lib/desktop-guard/desktop-guard"
install -Dm755 src/admin "$stage/usr/lib/desktop-guard/admin"
install -Dm644 src/watched.py "$stage/usr/lib/desktop-guard/watched.py"
install -Dm644 src/backend.py "$stage/usr/lib/desktop-guard/backend.py"
install -Dm644 assets/desktop-guard.png "$stage/usr/lib/desktop-guard/desktop-guard.png"
install -Dm644 assets/desktop-guard.png "$stage/usr/share/icons/hicolor/256x256/apps/desktop-guard.png"
install -Dm644 packaging/desktop-guard.desktop "$stage/usr/share/applications/desktop-guard.desktop"
install -Dm644 packaging/io.github.desktopguard.admin.policy "$stage/usr/share/polkit-1/actions/io.github.desktopguard.admin.policy"
install -Dm644 README.md "$stage/usr/share/doc/desktop-guard/README.md"
install -d "$stage/usr/bin"
ln -s /usr/lib/desktop-guard/desktop-guard "$stage/usr/bin/desktop-guard"
dpkg-deb --root-owner-group --build "$stage" outputs/desktop-guard_0.1.1_all.deb
