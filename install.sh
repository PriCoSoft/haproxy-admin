#!/usr/bin/env bash
# Install / update haproxy-admin on Ubuntu 24.04. Run as root from the source directory.
# Existing configuration (/etc/haproxy-admin) is never overwritten. HAProxy itself is not touched.
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/haproxy-admin
ETC=/etc/haproxy-admin
STATE=/var/lib/haproxy-admin
LOGDIR=/var/log/haproxy-admin

[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

missing=""
for p in python3-flask python3-msal python3-jwt python3-cryptography gunicorn socat; do
  dpkg -s "$p" >/dev/null 2>&1 || missing="$missing $p"
done
[ -z "$missing" ] || { echo "Missing packages:$missing  ->  apt-get install --no-install-recommends$missing" >&2; exit 1; }

id haproxy-admin >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home \
  --shell /usr/sbin/nologin --user-group haproxy-admin
usermod -aG haproxy haproxy-admin

# application code (root-owned, not writable by the service user)
install -d -o root -g root -m 0755 "$APP" "$APP/bin"
rm -rf "$APP/haproxy_admin.new"
cp -r "$SRC/haproxy_admin" "$APP/haproxy_admin.new"
find "$APP/haproxy_admin.new" -name '__pycache__' -prune -exec rm -rf {} +
chown -R root:root "$APP/haproxy_admin.new"
chmod -R u=rwX,go=rX "$APP/haproxy_admin.new"
rm -rf "$APP/haproxy_admin.old"
[ -d "$APP/haproxy_admin" ] && mv "$APP/haproxy_admin" "$APP/haproxy_admin.old"
mv "$APP/haproxy_admin.new" "$APP/haproxy_admin"
install -o root -g root -m 0755 "$SRC/bin/haproxy-admin-helper" "$APP/bin/haproxy-admin-helper"
install -o root -g root -m 0755 "$SRC/bin/import-pfx.sh" "$APP/bin/import-pfx.sh"
install -o root -g root -m 0644 "$SRC/bin/hpa_dns.py" "$APP/bin/hpa_dns.py"
for f in "$SRC"/bin/hpa_dns_*.py; do   # optional local DNS provider plugins
  if [ -e "$f" ]; then install -o root -g root -m 0644 "$f" "$APP/bin/$(basename "$f")"; fi
done

# configuration (kept on update)
install -d -o root -g haproxy-admin -m 0750 "$ETC" "$ETC/tls"
[ -f "$ETC/admin.conf" ] || install -o root -g haproxy-admin -m 0640 "$SRC/deploy/admin.conf.example" "$ETC/admin.conf"
[ -f "$ETC/service.env" ] || install -o root -g root -m 0644 "$SRC/deploy/service.env.example" "$ETC/service.env"
if [ ! -f "$ETC/secret_key" ]; then
  head -c 48 /dev/urandom | base64 -w0 > "$ETC/secret_key"
  chown root:haproxy-admin "$ETC/secret_key"; chmod 0640 "$ETC/secret_key"
fi
if [ ! -f "$ETC/tls/cert.pem" ]; then
  echo "No TLS certificate yet - creating a temporary self-signed one (replace with import-pfx.sh)."
  fqdn="$(hostname -f)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc -days 30 \
    -subj "/CN=$fqdn" -addext "subjectAltName=DNS:$fqdn" \
    -keyout "$ETC/tls/key.pem" -out "$ETC/tls/cert.pem" 2>/dev/null
  chown root:haproxy-admin "$ETC/tls/key.pem" "$ETC/tls/cert.pem"; chmod 0640 "$ETC/tls/key.pem" "$ETC/tls/cert.pem"
fi

# state / logs / certificate directory
install -d -o root -g root -m 0700 "$STATE" "$STATE/backups" "$STATE/tmp"
install -d -o haproxy-admin -g haproxy-admin -m 0750 "$LOGDIR"
install -d -o root -g root -m 0700 /etc/haproxy/certs

# sudoers (validated before activation)
install -o root -g root -m 0440 "$SRC/deploy/sudoers-haproxy-admin" /etc/sudoers.d/haproxy-admin.new
if visudo -cf /etc/sudoers.d/haproxy-admin.new >/dev/null; then
  mv /etc/sudoers.d/haproxy-admin.new /etc/sudoers.d/haproxy-admin
else
  rm -f /etc/sudoers.d/haproxy-admin.new; echo "sudoers file invalid" >&2; exit 1
fi

install -o root -g root -m 0644 "$SRC/deploy/haproxy-admin.service" /etc/systemd/system/haproxy-admin.service
systemctl daemon-reload
systemctl enable haproxy-admin >/dev/null 2>&1
systemctl restart haproxy-admin
sleep 2
systemctl --no-pager --lines=5 status haproxy-admin || true
