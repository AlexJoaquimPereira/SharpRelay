# SharpRelay
Reference Implementation of a Compatibility Bridge Between SHARP and SMTP Email Protocols

## Requirements

* Python 3.9+ (standard library only — no third-party packages)
* The `openssl` CLI, used to generate a self-signed certificate at runtime

## Running

Run from the repository root so the packages resolve:

```sh
python3 -m bridge.proxy
```

The bridge listens for SHARP messages over TLS and converts them:

* recipients containing `@` are relayed to SMTP;
* recipients containing `#` (SHARP handles) are forwarded to the SHARP backend;
* a single message may contain both kinds.

## Configuration

All configuration is read from environment variables. No credentials are
stored in the repository.

| Variable | Default | Purpose |
| --- | --- | --- |
| `BRIDGE_HOST` | `0.0.0.0` | TLS listener address |
| `BRIDGE_PORT` | `5000` | TLS listener port |
| `SHARP_BACKEND_HOST` | `127.0.0.1` | upstream SHARP backend host |
| `SHARP_BACKEND_PORT` | `5002` | upstream SHARP backend port |
| `SHARP_BACKEND_TIMEOUT` | `30` | backend read timeout (seconds) |
| `SMTP_HOST` | – (required for e-mail relay) | outgoing SMTP server |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | – (required for e-mail relay) | SMTP username |
| `SMTP_PASS` | – (required for e-mail relay) | SMTP password / app password |
| `TLS_CERT_FILE` | – | CA-authorised certificate (with `TLS_KEY_FILE`) |
| `TLS_KEY_FILE` | – | private key for `TLS_CERT_FILE` |
| `TLS_RUNTIME_DIR` | `certs/runtime` | where the self-signed cert is cached |
| `TLS_COMMON_NAME` | `sharprelay-bridge` | CN of the generated certificate |

## TLS

Two modes are supported (`bridge/tls_utils.py`):

1. **CA-authorised certificate (recommended for production).** Set
   `TLS_CERT_FILE` and `TLS_KEY_FILE` to a certificate/key issued by a
   certificate authority (for example Let's Encrypt). They are loaded as-is
   and clients can verify them normally.
2. **Runtime self-signed certificate (default).** If no certificate is
   configured, one is generated with `openssl` on first start, cached in
   `certs/runtime/` (git-ignored, key mode `0600`) and regenerated
   automatically before it expires. Clients must either pin this
   certificate or disable verification, so use this mode for development
   and trusted networks only.

Private keys and certificates are never committed: `certs/`, `*.key`,
`*.crt` and `*.pem` are excluded by `.gitignore`.
