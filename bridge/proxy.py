"""Consolidated SHARP Proxy + SMTP Bridge.

The bridge runs two listeners:

* ``SHARP_LISTEN_PORT`` (default 5000, plain TCP) - a SHARP/1.3 server
  (sharp/server.py). Mail that other SHARP servers federate to this domain
  is accepted there and relayed to e-mail by bridge/relay.py.
* ``BRIDGE_PORT`` (default 5002, TLS) - the bridge's own JSON ``SEND``
  ingress. Recipients containing '@' are relayed over SMTP; recipients
  containing '#' are delivered over SHARP/1.3 by sharp/client.py, which
  resolves the destination through ``_sharp._tcp`` SRV records and generates
  the hashcash proof-of-work the recipient server requires.

SHARP's own transport is plain TCP, so the SHARP listener is not wrapped in
TLS; the SEND ingress keeps the runtime self-signed or CA-authorised
certificate from bridge/tls_utils.py.

Configuration (environment variables):
  BRIDGE_ENABLED / BRIDGE_HOST / BRIDGE_PORT
  SHARP_LISTEN_ENABLED / SHARP_LISTEN_HOST / SHARP_LISTEN_PORT
  SHARP_LOCAL_DOMAINS          domains served here (unset = accept any)
  SHARP_REQUIRE_HASHCASH       default on
  SHARP_MIN_HASHCASH_BITS      default 5 (reference TRIVIAL)
  SHARP_VERIFY_SENDER_DOMAIN   default on
  SHARP_BACKEND_HOST/PORT      optional legacy raw passthrough
  SMTP_* / TLS_*               see bridge/relay.py and bridge/tls_utils.py

SHARP is a copyright of @outpoot
"""

import asyncio
import json
import os

from bridge.relay import handle_send, relay_sharp_to_smtp
from bridge.tls_utils import get_server_ssl_context
from sharp.client import deliver_sharp_recipients
from sharp.protocol import HASHCASH_TRIVIAL_BITS
from sharp.server import SharpServer

READ_SIZE = 65536


def _env_flag(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() not in ("", "0", "false", "no", "off")


def _env_domains(name: str):
    raw = (os.environ.get(name) or "").replace(";", ",")
    return [part.strip().lower() for part in raw.split(",") if part.strip()]


BRIDGE_ENABLED = _env_flag("BRIDGE_ENABLED")
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "5002"))

SHARP_LISTEN_ENABLED = _env_flag("SHARP_LISTEN_ENABLED")
SHARP_LISTEN_HOST = os.environ.get("SHARP_LISTEN_HOST", "0.0.0.0")
SHARP_LISTEN_PORT = int(os.environ.get("SHARP_LISTEN_PORT", "5000"))

# Legacy raw passthrough to a bespoke backend; only used when the host is set.
SHARP_BACKEND_HOST = os.environ.get("SHARP_BACKEND_HOST")
SHARP_BACKEND_PORT = int(os.environ.get("SHARP_BACKEND_PORT", "5002"))
SHARP_BACKEND_TIMEOUT = float(os.environ.get("SHARP_BACKEND_TIMEOUT", "30"))


async def forward_to_sharp_backend(data: bytes) -> bytes:
    """Send raw bytes to a legacy backend and return its reply."""
    reader, writer = await asyncio.open_connection(
        SHARP_BACKEND_HOST, SHARP_BACKEND_PORT
    )
    try:
        writer.write(data)
        await writer.drain()
        return await asyncio.wait_for(
            reader.read(READ_SIZE), timeout=SHARP_BACKEND_TIMEOUT
        )
    finally:
        writer.close()
        await writer.wait_closed()


def _decode_backend_response(data: bytes):
    """Best-effort decode of a backend reply for inclusion in the response."""
    text = data.decode("utf-8", errors="replace").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _split_recipients(to_list):
    """Partition recipients into (e-mail, SHARP handles, invalid)."""
    emails, handles, invalid = [], [], []
    for recipient in to_list:
        if not isinstance(recipient, str) or not recipient.strip():
            invalid.append(recipient)
        elif "@" in recipient:
            emails.append(recipient)
        elif "#" in recipient:
            handles.append(recipient)
        else:
            invalid.append(recipient)
    return emails, handles, invalid


async def _respond(writer, payload) -> None:
    writer.write((json.dumps(payload) + "\n").encode())
    await writer.drain()


async def _process(data: bytes, writer) -> None:
    try:
        msg = json.loads(data.decode())
        if not isinstance(msg, dict):
            raise ValueError("payload must be a JSON object")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        await _respond(writer, {"type": "ERROR", "error": f"invalid payload: {exc}"})
        return

    if msg.get("type") != "SEND":
        if SHARP_BACKEND_HOST:
            # Legacy deployment: hand non-SEND traffic to the old backend.
            writer.write(await forward_to_sharp_backend(data))
            await writer.drain()
            return
        await _respond(writer, {
            "type": "ERROR",
            "error": "unsupported message type on the SEND ingress; "
                     f"SHARP/1.3 is served on port {SHARP_LISTEN_PORT}",
        })
        return

    to_list = msg.get("to") if isinstance(msg.get("to"), list) else []
    emails, handles, invalid = _split_recipients(to_list)
    msg_id = msg.get("id")

    if not emails and not handles:
        await _respond(writer, {
            "type": "ERROR", "id": msg_id,
            "error": "no valid recipients", "invalid": invalid,
        })
        return

    details = {}
    if emails:
        try:
            details["email"] = await handle_send(msg)
        except Exception as exc:
            details["email"] = {"type": "ERROR", "error": str(exc)}
    if handles:
        try:
            details["sharp"] = await deliver_sharp_recipients(msg, handles)
        except Exception as exc:
            details["sharp"] = {"type": "ERROR", "error": str(exc)}

    print(f"SEND {msg_id}: {len(emails)} e-mail, {len(handles)} SHARP recipient(s)")
    await _respond(writer, {"type": "OK", "id": msg_id, "details": details})


async def handle_connection(reader, writer) -> None:
    addr = writer.get_extra_info("peername")
    print(f"Connection from {addr}")
    try:
        data = await reader.read(READ_SIZE)
        await _process(data, writer)
    except Exception as exc:  # keep the bridge alive on per-connection errors
        print(f"Error handling {addr}: {exc!r}")
        try:
            await _respond(writer, {"type": "ERROR", "error": str(exc)})
        except Exception:
            pass
    finally:
        writer.close()
        await writer.wait_closed()


async def _relay_inbound_sharp(message) -> None:
    """SHARP/1.3 -> SMTP callback used by the SHARP listener."""
    result = await relay_sharp_to_smtp(
        message.sender, message.recipient, message.subject, message.body,
        content_type=message.content_type, html_body=message.html_body,
    )
    if result.get("type") == "ERROR":
        raise RuntimeError(result.get("error", "SMTP relay failed"))
    print(
        f"SHARP -> SMTP {message.sender} -> {message.recipient} "
        f"({message.hashcash_bits} hashcash bits)"
    )


async def _serve_tls_bridge() -> None:
    ssl_ctx = get_server_ssl_context()  # generates a runtime cert if needed
    server = await asyncio.start_server(
        handle_connection, BRIDGE_HOST, BRIDGE_PORT, ssl=ssl_ctx
    )
    print(f"SEND ingress (TLS) listening on {BRIDGE_HOST}:{BRIDGE_PORT}")
    async with server:
        await server.serve_forever()


async def start_bridge() -> None:
    if BRIDGE_ENABLED and SHARP_LISTEN_ENABLED and BRIDGE_PORT == SHARP_LISTEN_PORT:
        raise SystemExit(
            f"BRIDGE_PORT and SHARP_LISTEN_PORT are both {BRIDGE_PORT}; the SEND "
            "ingress and the SHARP/1.3 listener need different ports"
        )

    tasks = []
    if SHARP_LISTEN_ENABLED:
        sharp_server = SharpServer(
            SHARP_LISTEN_HOST, SHARP_LISTEN_PORT, _relay_inbound_sharp,
            local_domains=_env_domains("SHARP_LOCAL_DOMAINS"),
            require_hashcash=_env_flag("SHARP_REQUIRE_HASHCASH"),
            min_hashcash_bits=int(
                os.environ.get("SHARP_MIN_HASHCASH_BITS", str(HASHCASH_TRIVIAL_BITS))
            ),
            verify_sender_domain=_env_flag("SHARP_VERIFY_SENDER_DOMAIN"),
        )
        await sharp_server.start()
        print(f"SHARP/1.3 listener on {SHARP_LISTEN_HOST}:{SHARP_LISTEN_PORT}")
        tasks.append(sharp_server.serve_forever())

    if BRIDGE_ENABLED:
        tasks.append(_serve_tls_bridge())

    if not tasks:
        raise SystemExit(
            "BRIDGE_ENABLED and SHARP_LISTEN_ENABLED are both off; nothing to serve"
        )
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(start_bridge())
