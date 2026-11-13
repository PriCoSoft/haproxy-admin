#!/usr/bin/env bash
# Import a PFX/P12 (e.g. from the internal CA) as TLS certificate for the admin UI.
# The password is read interactively and only passed to openssl via environment.
#
#   import-pfx.sh <file.pfx> [extra-ca.cer ...]
#
# Extra CA files (PEM or DER) are appended to the chain if they are not self-signed roots.
set -euo pipefail

PFX="${1:?usage: import-pfx.sh <file.pfx> [issuing-ca.cer ...]}"
shift
DIR="/etc/haproxy-admin/tls"
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

read -rsp "PFX password: " PFXPASS; echo
export PFXPASS
umask 077
TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"; unset PFXPASS' EXIT

p12() { openssl pkcs12 -in "$PFX" -passin env:PFXPASS "$@" 2>/dev/null || openssl pkcs12 -legacy -in "$PFX" -passin env:PFXPASS "$@"; }

p12 -nokeys -clcerts -out "$TMPD/leaf.raw"
p12 -nocerts -noenc -out "$TMPD/key.raw"
p12 -nokeys -cacerts -out "$TMPD/ca.raw" || true

openssl x509 -in "$TMPD/leaf.raw" -out "$TMPD/cert.pem"
openssl pkey -in "$TMPD/key.raw" -out "$TMPD/key.pem"

# chain: CA certs from the PFX + extra files, skipping self-signed roots
add_ca() {
  local f="$1" pem="$TMPD/one.pem"
  openssl x509 -in "$f" -out "$pem" 2>/dev/null || openssl x509 -inform der -in "$f" -out "$pem"
  if [ "$(openssl x509 -in "$pem" -noout -subject)" = "subject=$(openssl x509 -in "$pem" -noout -issuer | sed 's/^issuer=//')" ]; then
    echo "skip root: $(openssl x509 -in "$pem" -noout -subject)"; return
  fi
  if ! grep -qF "$(sed -n 2p "$pem")" "$TMPD/cert.pem"; then cat "$pem" >> "$TMPD/cert.pem"; echo "chain: $(openssl x509 -in "$pem" -noout -subject)"; fi
}
if [ -s "$TMPD/ca.raw" ]; then
  csplit -s -z -f "$TMPD/pfxca-" "$TMPD/ca.raw" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || true
  for f in "$TMPD"/pfxca-*; do grep -q "BEGIN CERTIFICATE" "$f" && add_ca "$f"; done
fi
for f in "$@"; do add_ca "$f"; done

# sanity: key matches certificate
[ "$(openssl x509 -in "$TMPD/cert.pem" -noout -pubkey | openssl sha256)" = "$(openssl pkey -in "$TMPD/key.pem" -pubout | openssl sha256)" ] \
  || { echo "ERROR: key does not match certificate" >&2; exit 1; }

install -d -o root -g haproxy-admin -m 0750 "$DIR"
install -o root -g haproxy-admin -m 0640 "$TMPD/cert.pem" "$DIR/cert.pem"
install -o root -g haproxy-admin -m 0640 "$TMPD/key.pem" "$DIR/key.pem"
echo
openssl x509 -in "$DIR/cert.pem" -noout -subject -issuer -enddate -ext subjectAltName
echo "SHA-1 thumbprint (Entra): $(openssl x509 -in "$DIR/cert.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
echo
echo "Installed to $DIR. Restart the service: systemctl restart haproxy-admin"
