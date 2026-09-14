"""SHARP/1.3 client: deliver messages to a SHARP server.

The exchange mirrors ``sendEmailToRemoteServer()`` in the reference server:
one JSON object per line, each step acknowledged before the next is sent::

    HELLO -> MAIL_TO (hashcash) -> DATA -> EMAIL_CONTENT -> END_DATA

Delivery targets come from ``_sharp._tcp.<domain>`` SRV records (falling back
to ``sharp.<domain>:5000``), unless SHARP_REMOTE_HOST/SHARP_REMOTE_PORT pin a
single server. The proof-of-work is generated in a worker thread because it
blocks while searching for a nonce.

Configuration read from the environment:
  SHARP_SERVER_ID       identity sent in HELLO (defaults to the sender address)
  SHARP_HASHCASH_BITS   proof-of-work strength, default 18 (reference "GOOD")
  SHARP_DELIVERY_TIMEOUT per-step timeout in seconds, default 30
  SHARP_REMOTE_HOST     talk to this host instead of resolving SRV records
  SHARP_REMOTE_PORT     port for SHARP_REMOTE_HOST, default 5000
"""

import asyncio
import json
import os
from typing import Any, Dict, List, NamedTuple, Optional

from sharp.protocol import (
    DEFAULT_SHARP_PORT,
    HASHCASH_GOOD_BITS,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    SharpError,
    SharpServerTarget,
    generate_hashcash,
    is_valid_sharp_username,
    parse_sharp_address,
    resolve_sharp_targets,
    to_sharp_address,
)

DEFAULT_DELIVERY_TIMEOUT = float(os.environ.get("SHARP_DELIVERY_TIMEOUT", "30"))

# Rejections that will not improve by trying another SRV target.
DEFINITIVE_CODES = {400, 403, 413, 429, 451, 550}


class SharpDelivery(NamedTuple):
    recipient: str
    host: str
    port: int
    hashcash_bits: int
    responses: List[Dict[str, Any]]


async def _read_response(reader: asyncio.StreamReader, timeout: float) -> Dict[str, Any]:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
    except asyncio.TimeoutError:
        raise SharpError("timed out waiting for the SHARP server", 504)
    if not line:
        raise SharpError("SHARP server closed the connection", 500)
    try:
        response = json.loads(line.decode("utf-8", errors="replace").strip())
    except json.JSONDecodeError:
        raise SharpError("invalid JSON from SHARP server", 500)
    if not isinstance(response, dict):
        raise SharpError("unexpected SHARP response", 500)
    if response.get("type") == "ERROR":
        raise SharpError(
            response.get("message") or "SHARP server error",
            int(response.get("code") or 400),
        )
    if response.get("type") != "OK":
        raise SharpError(f"unexpected SHARP response type: {response.get('type')!r}", 500)
    return response


async def _exchange(target: SharpServerTarget, steps: List[Dict[str, Any]], timeout: float,
                    recipient: str, bits: int) -> SharpDelivery:
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(target.host, target.port), timeout
    )
    try:
        responses = []
        for step in steps:
            writer.write((json.dumps(step) + "\n").encode())
            await writer.drain()
            responses.append(await _read_response(reader, timeout))
        return SharpDelivery(recipient, target.host, target.port, bits, responses)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _remote_target(parsed, remote_host: Optional[str],
                   remote_port: Optional[int]) -> Optional[SharpServerTarget]:
    host = remote_host or os.environ.get("SHARP_REMOTE_HOST") or None
    if not host:
        return None
    port = remote_port
    if port is None and os.environ.get("SHARP_REMOTE_PORT"):
        port = int(os.environ["SHARP_REMOTE_PORT"])
    return SharpServerTarget(host, port or parsed.port or DEFAULT_SHARP_PORT)


async def deliver_sharp_message(from_addr: str, to_addr: str, subject: str, body: str,
                                content_type: str = "text/plain",
                                html_body: Optional[str] = None,
                                attachments=(), hashcash_bits: Optional[int] = None,
                                timeout: Optional[float] = None,
                                remote_host: Optional[str] = None,
                                remote_port: Optional[int] = None,
                                server_id: Optional[str] = None) -> SharpDelivery:
    """Deliver one message to a SHARP recipient over SHARP/1.3."""
    recipient = to_sharp_address(to_addr)
    parsed = parse_sharp_address(recipient)
    timeout = DEFAULT_DELIVERY_TIMEOUT if timeout is None else timeout
    bits = int(os.environ.get("SHARP_HASHCASH_BITS", HASHCASH_GOOD_BITS)) \
        if hashcash_bits is None else hashcash_bits

    identity = server_id or os.environ.get("SHARP_SERVER_ID") or to_sharp_address(from_addr)
    identity_username = parse_sharp_address(identity).username
    if not is_valid_sharp_username(identity_username):
        raise SharpError(f"invalid SHARP identity for HELLO: {identity!r}")

    content = {
        "type": "EMAIL_CONTENT",
        "subject": subject,
        "body": body,
        "content_type": content_type,
        "html_body": html_body,
        "attachments": list(attachments or ()),
    }
    if len(json.dumps(content).encode()) > MAX_MESSAGE_SIZE:
        raise SharpError("message exceeds the 1 MiB SHARP limit", 413)

    target = _remote_target(parsed, remote_host, remote_port)
    if target is not None:
        targets = [target]
    else:
        targets = await resolve_sharp_targets(parsed.domain)

    stamp = await asyncio.to_thread(generate_hashcash, recipient, bits)
    steps = [
        {"type": "HELLO", "server_id": identity, "protocol": PROTOCOL_VERSION},
        {"type": "MAIL_TO", "address": recipient, "hashcash": stamp},
        {"type": "DATA"},
        content,
        {"type": "END_DATA"},
    ]

    last_error: Optional[Exception] = None
    for candidate in targets:
        try:
            return await _exchange(candidate, steps, timeout, recipient, bits)
        except SharpError as exc:
            if exc.code in DEFINITIVE_CODES:
                raise
            last_error = exc
        except (OSError, asyncio.TimeoutError) as exc:
            last_error = exc
    raise SharpError(
        f"delivery of {recipient} failed: {last_error}",
        getattr(last_error, "code", 502) or 502,
    )


async def deliver_sharp_recipients(msg: dict, recipients, **overrides) -> Dict[str, Any]:
    """Deliver every SHARP recipient of a bridge message; never raises.

    Returns the same shape as the SMTP relay so the proxy can merge results.
    """
    delivered, failed, skipped = [], [], []
    for recipient in recipients:
        if not isinstance(recipient, str) or "#" not in recipient:
            skipped.append(recipient)
            continue
        try:
            result = await deliver_sharp_message(
                msg.get("from", ""),
                recipient,
                msg.get("subject", "No Subject"),
                msg.get("body", ""),
                content_type=msg.get("content_type", "text/plain"),
                html_body=msg.get("html_body"),
                attachments=msg.get("attachments") or (),
                **overrides,
            )
            delivered.append({
                "recipient": recipient,
                "server": f"{result.host}:{result.port}",
                "hashcash_bits": result.hashcash_bits,
            })
        except Exception as exc:
            failed.append({"recipient": recipient, "error": str(exc)})

    return {
        "type": "OK" if delivered or not failed else "ERROR",
        "delivered": delivered,
        "failed": failed,
        "skipped": skipped,
    }
