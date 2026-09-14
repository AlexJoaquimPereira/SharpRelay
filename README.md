# SharpRelay
Reference Implementation of a Compatibility Bridge Between SHARP and SMTP Email Protocols

## What it does

The bridge speaks the real protocol on both sides:

| Direction | Listener | Path |
| --- | --- | --- |
| e-mail/`SEND` -> SHARP | `BRIDGE_PORT` (TLS) | recipients like `user#domain` are delivered by the SHARP/1.3 client (`sharp/client.py`) |
| SHARP -> e-mail | `SHARP_LISTEN_PORT` (TCP) | the SHARP/1.3 server (`sharp/server.py`) accepts federated mail and relays it over SMTP (`bridge/relay.py`) |
| e-mail -> SMTP | `BRIDGE_PORT` (TLS) | recipients like `user@domain` are sent through the SMTP relay |

A single `SEND` message may mix both kinds of recipient; each is routed
independently and every branch is reported back in `details`.

## Requirements

* Python 3.9+ (standard library only — no third-party packages)
* The `openssl` CLI, used to generate a self-signed certificate at runtime
* A SHARP/1.3 server at the receiving end (or an SRV record for it)

## Running

Run from the repository root so the packages resolve:

```sh
python3 -m bridge.proxy
```

By default this serves SHARP/1.3 on port 5000 (where federated mail for your
domain arrives) and the TLS `SEND` ingress on port 5002. Point the
`_sharp._tcp.<your-domain>` SRV record at the SHARP listener so other SHARP
servers can find you.

## Configuration

All configuration is read from environment variables. No credentials are
stored in the repository.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SHARP_LISTEN_ENABLED` | `1` | serve SHARP/1.3 inbound |
| `SHARP_LISTEN_HOST` | `0.0.0.0` | SHARP/1.3 listener address |
| `SHARP_LISTEN_PORT` | `5000` | SHARP/1.3 listener port |
| `SHARP_LOCAL_DOMAINS` | – (accept any) | comma-separated domains this bridge accepts mail for |
| `SHARP_REQUIRE_HASHCASH` | `1` | reject `MAIL_TO` without a valid hashcash stamp |
| `SHARP_MIN_HASHCASH_BITS` | `5` | minimum proof-of-work bits (reference `TRIVIAL`) |
| `SHARP_VERIFY_SENDER_DOMAIN` | `1` | check the peer IP against the sender domain's SRV records |
| `BRIDGE_ENABLED` | `1` | serve the JSON `SEND` ingress |
| `BRIDGE_HOST` | `0.0.0.0` | `SEND` ingress address |
| `BRIDGE_PORT` | `5002` | `SEND` ingress port (TLS) |
| `SHARP_SERVER_ID` | sender address | identity sent in `HELLO` |
| `SHARP_HASHCASH_BITS` | `18` | proof-of-work generated for outbound delivery (reference `GOOD`) |
| `SHARP_DELIVERY_TIMEOUT` | `30` | per-step timeout (seconds) |
| `SHARP_REMOTE_HOST` | – | talk to this host instead of resolving SRV records |
| `SHARP_REMOTE_PORT` | `5000` | port for `SHARP_REMOTE_HOST` |
| `SHARP_DNS_TIMEOUT` | `5` | SRV lookup timeout (seconds) |
| `SHARP_BACKEND_HOST` | – | optional: legacy raw passthrough for non-`SEND` traffic |
| `SHARP_BACKEND_PORT` | `5002` | port for the legacy passthrough |
| `SMTP_HOST` | – (required for e-mail relay) | outgoing SMTP server |
| `SMTP_PORT` | `587` | SMTP port (STARTTLS) |
| `SMTP_USER` | – (required for e-mail relay) | SMTP username |
| `SMTP_PASS` | – (required for e-mail relay) | SMTP password / app password |
| `TLS_CERT_FILE` | – | CA-authorised certificate (with `TLS_KEY_FILE`) |
| `TLS_KEY_FILE` | – | private key for `TLS_CERT_FILE` |
| `TLS_RUNTIME_DIR` | `certs/runtime` | where the self-signed cert is cached |
| `TLS_COMMON_NAME` | `sharprelay-bridge` | CN of the generated certificate |

`BRIDGE_PORT` and `SHARP_LISTEN_PORT` must differ; the bridge refuses to
start otherwise.

## SHARP/1.3 interoperability

The implementation mirrors the reference server (`SHARP/main.js` and
`SHARP/dns-utils.js`):

* **Addresses** are `username#domain[:port]`; usernames use the reference
  regex and the 20 character limit.
* **Delivery** is the five-step exchange `HELLO` -> `MAIL_TO` -> `DATA` ->
  `EMAIL_CONTENT` -> `END_DATA`, one JSON object per line.
* **Hashcash** stamps are `1:<bits>:YYMMDDHHMMSS:<recipient>::<rand>:<counter>`
  and must hash (SHA-1) to `<bits>` leading zero bits. The recipient address
  is the resource, stamps expire after 24 hours and are single-use. Outbound
  messages use 18 bits (`GOOD`); inbound mail is accepted from 5 bits
  (`TRIVIAL`) upwards — raise `SHARP_MIN_HASHCASH_BITS` to demand more.
* **Discovery** uses `_sharp._tcp.<domain>` SRV records, falling back to
  `sharp.<domain>:5000`, cached for 60 seconds, as in the reference.
* **Sender verification** checks that the connecting IP is listed for the
  domain claimed in `HELLO`; disable `SHARP_VERIFY_SENDER_DOMAIN` only behind
  NAT or a proxy.
* **Limits** match the reference: 1 MiB per message, 10 MiB per connection.
* **Attachments** in SHARP are server-side keys, not bytes, so they are not
  bridged; everything else is delivered as UTF-8 MIME (text plus an HTML
  alternative when present).

SHARP's own transport is plain TCP, so the SHARP listener is not encrypted —
that is the protocol. Only the `SEND` ingress uses TLS.

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
