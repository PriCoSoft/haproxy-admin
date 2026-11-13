#!/usr/bin/env bash
# Build the haproxy-admin .deb from this source tree (Ubuntu/Debian, needs dpkg-deb; no root required).
#   bash packaging/build-deb.sh [output-dir]
# Optional local DNS provider plugins (bin/hpa_dns_*.py) are NOT packaged.
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$SRC/dist}"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' "$SRC/haproxy_admin/__init__.py")"
[ -n "$VERSION" ] || { echo "version not found" >&2; exit 1; }
PKG="haproxy-admin_${VERSION}_all"
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
R="$BUILD/$PKG"

# application
install -d "$R/opt/haproxy-admin/bin"
cp -r "$SRC/haproxy_admin" "$R/opt/haproxy-admin/haproxy_admin"
find "$R/opt/haproxy-admin" -name '__pycache__' -prune -exec rm -rf {} +
install -m 0755 "$SRC/bin/haproxy-admin-helper" "$SRC/bin/import-pfx.sh" "$R/opt/haproxy-admin/bin/"
install -m 0644 "$SRC/bin/hpa_dns.py" "$R/opt/haproxy-admin/bin/"

# system integration
install -d "$R/usr/lib/systemd/system" "$R/etc/sudoers.d" "$R/usr/share/haproxy-admin" "$R/usr/share/doc/haproxy-admin"
install -m 0644 "$SRC/deploy/haproxy-admin.service" "$R/usr/lib/systemd/system/haproxy-admin.service"
install -m 0440 "$SRC/deploy/sudoers-haproxy-admin" "$R/etc/sudoers.d/haproxy-admin"
install -m 0644 "$SRC/deploy/admin.conf.example" "$SRC/deploy/service.env.example" "$R/usr/share/haproxy-admin/"
install -m 0644 "$SRC/README.md" "$R/usr/share/doc/haproxy-admin/README.md"
install -m 0644 "$SRC/LICENSE" "$R/usr/share/doc/haproxy-admin/copyright"
find "$R" -type d -exec chmod 0755 {} +
find "$R/opt/haproxy-admin/haproxy_admin" -type f -exec chmod 0644 {} +

# control files
install -d "$R/DEBIAN"
SIZE="$(du -sk --exclude=DEBIAN "$R" | cut -f1)"
sed -e "s/@VERSION@/$VERSION/" -e "s/@SIZE@/$SIZE/" "$SRC/packaging/debian/control" > "$R/DEBIAN/control"
install -m 0644 "$SRC/packaging/debian/conffiles" "$R/DEBIAN/conffiles"
install -m 0755 "$SRC/packaging/debian/postinst" "$SRC/packaging/debian/prerm" "$SRC/packaging/debian/postrm" "$R/DEBIAN/"
sed -i 's/\r$//' "$R/DEBIAN/"* "$R/opt/haproxy-admin/bin/"* "$R/etc/sudoers.d/haproxy-admin" \
  "$R/usr/lib/systemd/system/haproxy-admin.service" "$R/usr/share/haproxy-admin/"*

mkdir -p "$OUT"
dpkg-deb --root-owner-group -Zxz --build "$R" "$OUT/$PKG.deb"
echo "built $OUT/$PKG.deb"
