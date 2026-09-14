"""TLS helpers for the SHARP-SMTP bridge.

Two TLS modes are supported:

1. CA-authorised certificate (recommended for production):
   set TLS_CERT_FILE and TLS_KEY_FILE to a certificate / key issued by a
   certificate authority (e.g. Let's Encrypt). They are loaded as-is.

2. Runtime self-signed certificate (default, zero setup):
   if no certificate files are configured, a self-signed certificate is
   generated with the ``openssl`` CLI on first start and cached in
   TLS_RUNTIME_DIR (default: ``certs/runtime``, which is git-ignored).
   It is regenerated automatically once it is about to expire.

No private key material is ever committed to the repository: the
``certs/`` directory is excluded via .gitignore.
"""

import os
import ssl
import subprocess

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CERT_ENV_CERT = "TLS_CERT_FILE"
CERT_ENV_KEY = "TLS_KEY_FILE"
RUNTIME_DIR_ENV = "TLS_RUNTIME_DIR"
CN_ENV = "TLS_COMMON_NAME"

DEFAULT_RUNTIME_DIR = os.path.join(_REPO_ROOT, "certs", "runtime")
DEFAULT_COMMON_NAME = "sharprelay-bridge"
CERT_LIFETIME_DAYS = 825
CERT_RENEWAL_MARGIN_SECONDS = 24 * 3600  # regenerate when < 24h remain


class TLSConfigurationError(RuntimeError):
    """Raised when TLS cannot be configured from the environment."""


def _cert_is_valid(cert_file: str) -> bool:
    """Return True if cert_file exists and stays valid for the renewal margin."""
    if not os.path.isfile(cert_file):
        return False
    result = subprocess.run(
        ["openssl", "x509", "-checkend", str(CERT_RENEWAL_MARGIN_SECONDS),
         "-noout", "-in", cert_file],
        capture_output=True,
    )
    return result.returncode == 0


def ensure_runtime_certificate(runtime_dir=None, common_name=None):
    """Generate (or reuse) a self-signed server certificate.

    Returns a ``(cert_file, key_file)`` tuple.
    """
    runtime_dir = runtime_dir or os.environ.get(RUNTIME_DIR_ENV) or DEFAULT_RUNTIME_DIR
    common_name = common_name or os.environ.get(CN_ENV) or DEFAULT_COMMON_NAME
    cert_file = os.path.join(runtime_dir, "server.crt")
    key_file = os.path.join(runtime_dir, "server.key")

    if _cert_is_valid(cert_file) and os.path.isfile(key_file):
        return cert_file, key_file

    os.makedirs(runtime_dir, exist_ok=True)
    # -nodes: keep the key unencrypted so the bridge can start unattended.
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key_file, "-out", cert_file,
            "-days", str(CERT_LIFETIME_DAYS),
            "-subj", f"/CN={common_name}",
            "-addext",
            "subjectAltName=DNS:localhost,DNS:sharprelay.local,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
    )
    os.chmod(key_file, 0o600)
    os.chmod(cert_file, 0o644)
    print(f"[tls] generated self-signed certificate (CN={common_name}) in {runtime_dir}")
    return cert_file, key_file


def get_server_ssl_context() -> ssl.SSLContext:
    """Build the server-side SSLContext according to the environment."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    cert_file = os.environ.get(CERT_ENV_CERT)
    key_file = os.environ.get(CERT_ENV_KEY)

    if bool(cert_file) != bool(key_file):
        raise TLSConfigurationError(
            f"{CERT_ENV_CERT} and {CERT_ENV_KEY} must be set together"
        )

    if cert_file:
        # CA-authorised mode: use the provided certificate as-is.
        if not (os.path.isfile(cert_file) and os.path.isfile(key_file)):
            raise TLSConfigurationError(
                f"TLS certificate or key not found: {cert_file!r} / {key_file!r}"
            )
        print(f"[tls] loading CA-authorised certificate: {cert_file}")
    else:
        # Runtime mode: generate a self-signed certificate on first start.
        cert_file, key_file = ensure_runtime_certificate()

    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return context
