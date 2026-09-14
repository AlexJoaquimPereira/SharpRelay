"""SHARP/1.3 server: accept federated mail and hand it to a bridge callback.

The state machine mirrors the reference server in ``SHARP/main.js``: one JSON
object per line with the same flow and status codes::

    HELLO -> MAIL_TO (hashcash) -> DATA -> EMAIL_CONTENT -> END_DATA

Each accepted message is passed to ``on_message`` as a :class:`SharpInbound`;
the callback is responsible for converting it (the bridge relays it over
SMTP). Sender domains are verified against DNS exactly like the reference
server unless ``verify_sender_domain`` is disabled.

Configuration is provided by the caller (see bridge/proxy.py for the
environment variables that feed it).
"""

import asyncio
import json
from typing import Awaitable, Callable, List, NamedTuple, Optional

from sharp.protocol import (
    HASHCASH_TRIVIAL_BITS,
    MAX_BUFFER_SIZE,
    MAX_MESSAGE_SIZE,
    PROTOCOL_VERSION,
    SharpError,
    is_valid_sharp_username,
    parse_sharp_address,
    verify_hashcash,
    verify_sharp_sender_domain,
)


class SharpInbound(NamedTuple):
    sender: str          # server_id from HELLO, e.g. "alice#sender.example"
    recipient: str       # MAIL_TO address, e.g. "bob#example.com"
    subject: str
    body: str
    content_type: str
    html_body: Optional[str]
    attachments: List[str]
    hashcash_bits: int   # 0 when hashcash is not required
    peer: Optional[str]  # IP the message arrived from


class SharpServer:
    """Minimal SHARP/1.3 listener for the bridge's inbound direction."""

    def __init__(self, host: str, port: int,
                 on_message: Callable[[SharpInbound], Awaitable[None]],
                 local_domains=(), require_hashcash: bool = True,
                 min_hashcash_bits: int = HASHCASH_TRIVIAL_BITS,
                 verify_sender_domain: bool = True):
        self.host = host
        self.port = port
        self.on_message = on_message
        self.local_domains = {
            domain.strip().lower() for domain in local_domains
            if isinstance(domain, str) and domain.strip()
        }
        self.require_hashcash = require_hashcash
        self.min_hashcash_bits = min_hashcash_bits
        self.verify_sender_domain = verify_sender_domain
        self._server: Optional[asyncio.AbstractServer] = None

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> "SharpServer":
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, limit=MAX_MESSAGE_SIZE + 1024
        )
        return self

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def _handles_domain(self, domain: str) -> bool:
        return not self.local_domains or domain in self.local_domains

    # -- connection handling ----------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = peer[0] if peer else None
        print(f"SHARP connection from {peer_ip}:{peer[1]}" if peer else "SHARP connection")
        state = {
            "step": "HELLO",
            "peer_ip": peer_ip,
            "from": None,
            "to": None,
            "hashcash_bits": 0,
            "subject": "",
            "body": "",
            "content_type": "text/plain",
            "html_body": None,
            "attachments": [],
        }
        total = 0
        try:
            while True:
                try:
                    line = await reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    await self._send_error(writer, "Message too large", 413)
                    return
                if not line:
                    return
                total += len(line)
                if total > MAX_BUFFER_SIZE or len(line) > MAX_MESSAGE_SIZE:
                    await self._send_error(writer, "Message too large", 413)
                    return
                raw = line.strip()
                if not raw:
                    continue
                try:
                    command = json.loads(raw.decode("utf-8", errors="replace"))
                    if not isinstance(command, dict):
                        raise ValueError("not an object")
                except (json.JSONDecodeError, ValueError):
                    await self._send_error(writer, "Invalid JSON format")
                    return
                if await self._dispatch(command, state, writer):
                    return
        except Exception as exc:  # never take the listener down
            print(f"SHARP connection error: {exc!r}")
            try:
                await self._send_error(writer, "Internal server error", 500)
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, command: dict, state: dict,
                        writer: asyncio.StreamWriter) -> bool:
        """Handle one command; returns True when the connection is finished."""
        step = state["step"]
        if step == "HELLO":
            return await self._on_hello(command, state, writer)
        if step == "MAIL_TO":
            return await self._on_mail_to(command, state, writer)
        if step == "DATA":
            if command.get("type") != "DATA":
                await self._send_error(writer, "Expected DATA")
                return True
            state["step"] = "RECEIVING_DATA"
            await self._send_json(writer, {"type": "OK"})
            return False
        if step == "RECEIVING_DATA":
            return await self._on_content(command, state, writer)
        await self._send_error(writer, f"Unhandled state: {step}")
        return True

    async def _on_hello(self, command: dict, state: dict,
                        writer: asyncio.StreamWriter) -> bool:
        if command.get("type") != "HELLO":
            await self._send_error(writer, "Expected HELLO")
            return True
        if command.get("protocol") != PROTOCOL_VERSION:
            await self._send_error(
                writer, f"Unsupported protocol version: {command.get('protocol')}"
            )
            return True
        try:
            sender = parse_sharp_address(command.get("server_id", ""))
            if not is_valid_sharp_username(sender.username):
                raise SharpError("Invalid username format in server_id")
            if self.verify_sender_domain:
                await verify_sharp_sender_domain(sender.domain, state["peer_ip"])
        except SharpError as exc:
            await self._send_error(writer, f"Sender verification failed: {exc.message}",
                                   exc.code)
            return True
        state["from"] = command["server_id"]
        state["step"] = "MAIL_TO"
        await self._send_json(writer, {"type": "OK", "protocol": PROTOCOL_VERSION})
        return False

    async def _on_mail_to(self, command: dict, state: dict,
                          writer: asyncio.StreamWriter) -> bool:
        if command.get("type") != "MAIL_TO":
            await self._send_error(writer, "Expected MAIL_TO")
            return True
        address = command.get("address", "")
        try:
            recipient = parse_sharp_address(address)
            if not is_valid_sharp_username(recipient.username):
                raise SharpError("Invalid username format in recipient address")
        except SharpError as exc:
            await self._send_error(writer, f"Invalid recipient address format: {exc.message}")
            return True
        if not self._handles_domain(recipient.domain):
            await self._send_error(
                writer, f"This server does not handle mail for {recipient.domain}", 451
            )
            return True
        bits = 0
        if self.require_hashcash:
            try:
                bits = verify_hashcash(
                    command.get("hashcash", ""), address, self.min_hashcash_bits
                )
            except SharpError as exc:
                await self._send_error(writer, exc.message, 429)
                return True
        state["to"] = address
        state["hashcash_bits"] = bits
        state["step"] = "DATA"
        await self._send_json(writer, {"type": "OK"})
        return False

    async def _on_content(self, command: dict, state: dict,
                          writer: asyncio.StreamWriter) -> bool:
        command_type = command.get("type")
        if command_type == "EMAIL_CONTENT":
            state["subject"] = command.get("subject") or ""
            state["body"] = command.get("body") or ""
            state["content_type"] = command.get("content_type") or "text/plain"
            state["html_body"] = command.get("html_body")
            state["attachments"] = list(command.get("attachments") or [])
            await self._send_json(writer, {"type": "OK", "message": "Email content received"})
            return False
        if command_type == "END_DATA":
            message = SharpInbound(
                sender=state["from"] or "",
                recipient=state["to"] or "",
                subject=state["subject"],
                body=state["body"],
                content_type=state["content_type"],
                html_body=state["html_body"],
                attachments=state["attachments"],
                hashcash_bits=state["hashcash_bits"],
                peer=state["peer_ip"],
            )
            try:
                await self.on_message(message)
            except Exception as exc:
                await self._send_error(writer, f"Email processing failed: {exc}", 500)
                return True
            await self._send_json(writer, {"type": "OK", "message": "Email processed"})
            return True
        await self._send_error(writer, "Expected EMAIL_CONTENT or END_DATA")
        return True

    # -- helpers -----------------------------------------------------------

    @staticmethod
    async def _send_json(writer: asyncio.StreamWriter, payload: dict) -> None:
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()

    async def _send_error(self, writer: asyncio.StreamWriter, message: str,
                          code: int = 400) -> None:
        await self._send_json(writer, {"type": "ERROR", "message": message, "code": code})
