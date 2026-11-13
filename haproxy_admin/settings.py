"""Tool configuration (INI file, default /etc/haproxy-admin/admin.conf)."""
import configparser
import os
import re

DEFAULT_PATH = "/etc/haproxy-admin/admin.conf"

_PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
_PEM_KEY = re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----.+?-----END (?:RSA |EC )?PRIVATE KEY-----", re.S)


class Settings:
    def __init__(self, path=None):
        self.path = path or os.environ.get("HAPROXY_ADMIN_CONF", DEFAULT_PATH)
        cp = configparser.ConfigParser(inline_comment_prefixes=(";", "#"), interpolation=None)
        if not cp.read(self.path, encoding="utf-8"):
            raise RuntimeError(f"Configuration file not found: {self.path}")

        def get(section, key, default=""):
            value = cp.get(section, key, fallback="")
            value = (value or "").strip()
            return value if value else default

        # [server]
        self.hostname = get("server", "hostname")  # Entra app role required; empty = no role check
        self.public_url = get("server", "public_url").rstrip("/")
        self.secret_key_file = get("server", "secret_key_file", "/etc/haproxy-admin/secret_key")
        self.audit_log = get("server", "audit_log", "/var/log/haproxy-admin/audit.log")
        self.helper = get("server", "helper", "/opt/haproxy-admin/bin/haproxy-admin-helper")
        self.display_name = get("server", "display_name", os.uname().nodename if hasattr(os, "uname") else "haproxy")

        # [auth]
        self.auth_mode = get("auth", "mode", "entra").lower()
        self.tenant_id = get("auth", "tenant_id")
        self.client_id = get("auth", "client_id")
        self.client_secret_file = get("auth", "client_secret_file")
        self.client_cert_file = get("auth", "client_cert_file")
        self.client_key_file = get("auth", "client_key_file")
        self.session_hours = int(get("auth", "session_hours", "8"))

        # [haproxy]
        self.haproxy_config = get("haproxy", "config", "/etc/haproxy/haproxy.cfg")
        self.haproxy_socket = get("haproxy", "socket", "/run/haproxy/admin.sock")
        self.denylist = get("haproxy", "blocklist", "/etc/haproxy/blocklist.acl")
        self.log_file = get("haproxy", "log_file", "/var/log/haproxy.log")

        # [certs]
        self.cert_dir = get("certs", "cert_dir", "/etc/haproxy/certs")
        self.crt_list = get("certs", "crt_list", "/etc/haproxy/crt-list.txt")
        self.http01_port = int(get("certs", "http01_port", "8402"))

        if self.auth_mode not in ("entra", "none"):
            raise RuntimeError("auth.mode must be 'entra' or 'none'")
        if self.auth_mode == "entra":
            missing = [k for k in ("tenant_id", "client_id", "public_url") if not getattr(self, k)]
            if not (self.client_secret_file or self.client_cert_file):
                missing.append("client_secret_file or client_cert_file")
            if missing:
                raise RuntimeError("Missing Entra settings: " + ", ".join(missing))

    @property
    def redirect_uri(self):
        return self.public_url + "/auth/callback"

    def secret_key(self):
        with open(self.secret_key_file, "rb") as f:
            key = f.read().strip()
        if len(key) < 32:
            raise RuntimeError("secret_key too short")
        return key

    def client_credential(self):
        """Return an MSAL client credential: certificate (preferred) or client secret."""
        if self.client_cert_file:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization

            with open(self.client_cert_file, encoding="utf-8") as f:
                cert_text = f.read()
            key_path = self.client_key_file or self.client_cert_file
            with open(key_path, encoding="utf-8") as f:
                key_text = f.read()
            key_match = _PEM_KEY.search(key_text)
            if not key_match:
                raise RuntimeError(f"No private key found in {key_path}")
            key_pem = key_match.group(0)
            key = serialization.load_pem_private_key(key_pem.encode(), password=None)
            key_pub = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            for block in _PEM_CERT.findall(cert_text):
                cert = x509.load_pem_x509_certificate(block.encode())
                pub = cert.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                if pub == key_pub:
                    return {
                        "private_key": key_pem,
                        "thumbprint": cert.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303 (Entra uses SHA-1 thumbprints)
                    }
            raise RuntimeError("No certificate in client_cert_file matches the private key")
        with open(self.client_secret_file, encoding="utf-8") as f:
            return f.read().strip()
