"""Consolidated SHARP Proxy + SMTP Bridge.

Listens for SHARP protocol messages over TLS and:
  * relays messages addressed to e-mail recipients through SMTP, and
  * forwards messages addressed to SHARP handles ('#') to the SHARP backend.

TLS: a self-signed certificate is generated at runtime by default; for
production, point TLS_CERT_FILE / TLS_KEY_FILE at a CA-authorised
certificate (see bridge/tls_utils.py).

Configuration is read from environment variables:
  SHARP_BACKEND_HOST / SHARP_BACKEND_PORT   upstream SHARP backend
  BRIDGE_HOST / BRIDGE_PORT                 local TLS listener
  SHARP_BACKEND_TIMEOUT                     backend read timeout (seconds)
  TLS_CERT_FILE / TLS_KEY_FILE              CA-issued certificate (optional)

SHARP is a copyright of @outpoot
"""

import asyncio
import json
import os
import ssl

from bridge.relay import handle_send
from bridge.tls_utils import get_server_ssl_context

SHARP_BACKEND_HOST = os.environ.get("SHARP_BACKEND_HOST", "127.0.0.1")
SHARP_BACKEND_PORT = int(os.environ.get("SHARP_BACKEND_PORT", "5002"))
SHARP_BACKEND_TIMEOUT = float(os.environ.get("SHARP_BACKEND_TIMEOUT", "30"))
BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "5000"))

READ_SIZE = 65536


async def forward_to_sharp_backend(data: bytes) -> bytes:
    """Send raw bytes to the SHARP backend and return its reply."""
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
        # Non-SEND traffic is passed through to the SHARP backend untouched.
        writer.write(await forward_to_sharp_backend(data))
        await writer.drain()
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
            details["sharp"] = _decode_backend_response(
                await forward_to_sharp_backend(data)
            )
        except Exception as exc:
            details["sharp"] = {"type": "ERROR", "error": str(exc)}

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


async def start_bridge() -> None:
    ssl_ctx = get_server_ssl_context()  # generates a runtime cert if needed
    server = await asyncio.start_server(
        handle_connection, BRIDGE_HOST, BRIDGE_PORT, ssl=ssl_ctx
    )
    print(f"SHARP Proxy + SMTP Bridge listening on {BRIDGE_HOST}:{BRIDGE_PORT} (TLS)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_bridge())
