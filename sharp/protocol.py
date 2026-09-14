"""SHARP/1.3 protocol primitives: addresses, hashcash and server discovery.

Mirrors the reference server in outpoot/twoblade (``SHARP/main.js`` and
``SHARP/dns-utils.js``) so that addresses and stamps produced here are
accepted by a stock SHARP/1.3 server and vice versa:

* address grammar ``username#domain[:port]``, username validated with the
  reference regex and a 20 character limit;
* hashcash stamps ``1:<bits>:YYMMDDHHMMSS:<resource>::<rand>:<counter>``
  (SHA-1, ``<bits>`` leading zero bits) with the reference thresholds;
* discovery via ``_sharp._tcp.<domain>`` SRV records, falling back to
  ``sharp.<domain>:5000`` (A/AAAA), both cached for 60 seconds.

No third-party packages are required: the SRV lookup is a small DNS
client built on the standard library.
"""

import asyncio
import calendar
import hashlib
import os
import random
import re
import socket
import string
import struct
import time
from typing import List, NamedTuple, Optional, Sequence, Tuple

PROTOCOL_VERSION = os.environ.get("SHARP_PROTOCOL_VERSION", "SHARP/1.3")
DEFAULT_SHARP_PORT = int(os.environ.get("SHARP_DEFAULT_PORT", "5000"))

# HASHCASH_THRESHOLDS in SHARP/main.js
HASHCASH_GOOD_BITS = 18
HASHCASH_WEAK_BITS = 10
HASHCASH_TRIVIAL_BITS = 5
HASHCASH_REJECT_BITS = 3

# Limits enforced by the reference server.
MAX_MESSAGE_SIZE = 1 * 1024 * 1024   # 1 MiB per message
MAX_BUFFER_SIZE = 10 * 1024 * 1024   # 10 MiB per connection

MAX_USERNAME_LENGTH = 20
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-!$%&'*/?=^@.]+$")
ADDRESS_RE = re.compile(r"^(.+)#([^:]+)(?::(\d+))?$")

DNS_CACHE_TTL = 60  # seconds, mirrors DNS_CACHE_TTL in dns-utils.js
DNS_QUERY_TIMEOUT = float(os.environ.get("SHARP_DNS_TIMEOUT", "5"))


class SharpError(Exception):
    """SHARP protocol error carrying the HTTP-like status code."""

    def __init__(self, message: str, code: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code


class SharpAddress(NamedTuple):
    username: str
    domain: str
    port: Optional[int] = None


class SharpServerTarget(NamedTuple):
    host: str
    port: int
    priority: int = 0
    weight: int = 0


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------

def parse_sharp_address(text: str) -> SharpAddress:
    """Parse ``username#domain[:port]`` exactly like the reference server."""
    match = ADDRESS_RE.match(text.strip()) if isinstance(text, str) else None
    if not match:
        raise SharpError("Invalid SHARP address format")
    return SharpAddress(
        match.group(1).lower(),
        match.group(2).lower(),
        int(match.group(3)) if match.group(3) else None,
    )


def format_sharp_address(address: SharpAddress) -> str:
    suffix = f":{address.port}" if address.port else ""
    return f"{address.username}#{address.domain}{suffix}"


def is_valid_sharp_username(username: str) -> bool:
    return bool(username) and len(username) <= MAX_USERNAME_LENGTH and bool(
        USERNAME_RE.match(username)
    )


def to_sharp_address(text: str) -> str:
    """Normalise ``user#domain`` or ``user@domain`` to a SHARP address."""
    if not isinstance(text, str) or "@" not in text and "#" not in text:
        raise SharpError(f"not a SHARP or e-mail address: {text!r}")
    if "#" in text:
        return format_sharp_address(parse_sharp_address(text))
    local, _, domain = text.rpartition("@")
    return format_sharp_address(parse_sharp_address(f"{local}#{domain}"))


def sharp_address_to_email(text: str) -> str:
    """Map a SHARP address onto an SMTP mailbox (``user#domain`` -> ``user@domain``)."""
    address = parse_sharp_address(text)
    return f"{address.username}@{address.domain}"


# --------------------------------------------------------------------------
# Hashcash proof-of-work
# --------------------------------------------------------------------------

def _hashcash_date(timestamp: Optional[float] = None) -> str:
    return time.strftime("%y%m%d%H%M%S", time.gmtime(timestamp))


def leading_zero_bits(digest: bytes) -> int:
    """Number of leading zero bits, as hasLeadingZeroBits() in main.js."""
    count = 0
    for byte in digest:
        if byte == 0:
            count += 8
            continue
        count += 8 - byte.bit_length()
        break
    return count


def hashcash_work(stamp: str) -> int:
    """Proof-of-work actually present in a stamp (SHA-1 leading zero bits)."""
    return leading_zero_bits(hashlib.sha1(stamp.encode()).digest())


def generate_hashcash(resource: str, bits: int = HASHCASH_GOOD_BITS,
                      timestamp: Optional[float] = None) -> str:
    """Build a hashcash stamp for ``resource`` with at least ``bits`` zero bits.

    Blocks while searching for the nonce, so callers should run it in a
    thread (``asyncio.to_thread``) to keep the event loop free.
    """
    if bits < 0:
        raise ValueError("bits must not be negative")
    date = _hashcash_date(timestamp)
    rand = "".join(random.choices(string.ascii_letters + string.digits, k=12))
    counter = 0
    while True:
        stamp = f"1:{bits}:{date}:{resource}::{rand}:{counter}"
        if hashcash_work(stamp) >= bits:
            return stamp
        counter += 1


def verify_hashcash(stamp: str, resource: str,
                    min_bits: int = HASHCASH_TRIVIAL_BITS,
                    max_age_seconds: float = 24 * 60 * 60,
                    future_skew_seconds: float = 2 * 60) -> int:
    """Validate a stamp against ``resource``; returns the declared bits.

    Raises SharpError(429) on any problem, mirroring calculateSpamScore():
    malformed stamp, resource mismatch, date outside the window, fewer bits
    than ``min_bits`` or proof-of-work weaker than the stamp claims.
    """
    if not stamp:
        raise SharpError("Missing hashcash field", 429)

    parts = stamp.split(":")
    if len(parts) != 7:
        raise SharpError("Malformed hashcash stamp", 429)
    version, bits_text, date_text, header_resource, _ext, rand, counter = parts
    if version != "1" or not bits_text or not date_text or not header_resource \
            or not rand or not counter:
        raise SharpError("Malformed hashcash stamp", 429)
    if header_resource != resource:
        raise SharpError(
            f"Hashcash resource {header_resource!r} does not match {resource!r}", 429
        )

    try:
        declared_bits = int(bits_text)
        stamp_time = calendar.timegm(time.strptime(date_text, "%y%m%d%H%M%S"))
    except ValueError:
        raise SharpError("Malformed hashcash stamp", 429)

    now = time.time()
    if stamp_time > now + future_skew_seconds:
        raise SharpError("Hashcash token date is in the future", 429)
    if now - stamp_time > max_age_seconds:
        raise SharpError("Hashcash token expired", 429)

    if declared_bits < min_bits:
        raise SharpError(
            f"Insufficient proof of work: {declared_bits} bits, {min_bits} required", 429
        )
    if hashcash_work(stamp) < declared_bits:
        raise SharpError("Hashcash proof of work does not match its declaration", 429)
    return declared_bits


# --------------------------------------------------------------------------
# Server discovery (SRV, then sharp.<domain>)
# --------------------------------------------------------------------------

_SERVER_CACHE = {}


def system_nameservers() -> List[str]:
    servers = []
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "nameserver":
                    servers.append(fields[1])
    except OSError:
        pass
    return servers or ["1.1.1.1"]


def _encode_name(name: str) -> bytes:
    encoded = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii", errors="ignore")
        if not raw or len(raw) > 63:
            raise SharpError(f"invalid DNS name: {name!r}")
        encoded += bytes([len(raw)]) + raw
    return encoded + b"\x00"


def _decode_name(packet: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns (name, next offset)."""
    labels = []
    hops = 0
    end = None
    while True:
        if offset >= len(packet):
            raise SharpError("truncated DNS response")
        length = packet[offset]
        if length == 0:
            offset += 1
            return ".".join(labels), (end if end is not None else offset)
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise SharpError("truncated DNS pointer")
            if end is None:
                end = offset + 2
            hops += 1
            if hops > 20:
                raise SharpError("DNS compression loop")
            offset = ((length & 0x3F) << 8) | packet[offset + 1]
            continue
        offset += 1
        labels.append(packet[offset:offset + length].decode("ascii", errors="replace"))
        offset += length


def _parse_srv_records(packet: bytes) -> List[Tuple[int, int, int, str]]:
    if len(packet) < 12:
        raise SharpError("short DNS response")
    question_count, answer_count = struct.unpack("!HH", packet[4:8])
    offset = 12
    for _ in range(question_count):
        _, offset = _decode_name(packet, offset)
        offset += 4
    records = []
    for _ in range(answer_count):
        _, offset = _decode_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlength]
        if rtype == 33 and rclass == 1 and len(rdata) >= 7:
            priority, weight, port = struct.unpack("!HHH", rdata[:6])
            # The target name starts after priority/weight/port inside the RDATA.
            target, _ = _decode_name(packet, offset + 6)
            if target:
                records.append((priority, weight, port, target))
        offset += rdlength
    return records


def _dns_exchange(packet: bytes) -> bytes:
    """Send a DNS query to the system resolver, with TCP fallback on truncation."""
    for server in system_nameservers():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(DNS_QUERY_TIMEOUT)
                sock.sendto(packet, (server, 53))
                data, _ = sock.recvfrom(4096)
            if len(data) < 12 or data[:2] != packet[:2]:
                continue
            if struct.unpack("!H", data[2:4])[0] & 0x0200:  # TC: retry over TCP
                with socket.create_connection((server, 53), DNS_QUERY_TIMEOUT) as tcp:
                    tcp.sendall(struct.pack("!H", len(packet)) + packet)
                    size = struct.unpack("!H", _recv_exact(tcp, 2))[0]
                    data = _recv_exact(tcp, size)
            return data
        except (OSError, SharpError):
            continue
    raise SharpError("no DNS server answered the SRV query")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = b""
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise SharpError("DNS connection closed early")
        chunks += chunk
    return chunks


def _query_srv_records(name: str) -> List[Tuple[int, int, int, str]]:
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", 33, 1)  # SRV IN
    return _parse_srv_records(_dns_exchange(header + question))


async def _resolve_addresses(host: str) -> List[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


async def _lookup_sharp_servers(domain: str) -> List[Tuple[int, int, int, List[str]]]:
    """Resolve the SHARP servers of ``domain``: (priority, weight, port, ips)."""
    key = domain.lower()
    cached = _SERVER_CACHE.get(key)
    now = time.monotonic()
    if cached and now - cached[0] < DNS_CACHE_TTL:
        return cached[1]

    try:
        srv_records = await asyncio.to_thread(_query_srv_records, f"_sharp._tcp.{key}")
    except Exception:
        srv_records = []

    srv_records.sort(key=lambda record: (record[0], -record[1]))
    servers: List[Tuple[int, int, int, List[str]]] = []
    for priority, weight, port, target in srv_records:
        addresses = await _resolve_addresses(target)
        if addresses:
            servers.append((priority, weight, port, addresses))

    if not servers:  # fallback from dns-utils.js: sharp.<domain>:5000
        addresses = await _resolve_addresses(f"sharp.{key}")
        if addresses:
            servers.append((0, 0, DEFAULT_SHARP_PORT, addresses))

    if not servers:
        raise SharpError(f"no SHARP server could be resolved for {domain!r}", 451)

    _SERVER_CACHE[key] = (now, servers)
    return servers


async def resolve_sharp_targets(domain: str) -> List[SharpServerTarget]:
    """Ordered delivery targets for ``domain`` (SRV first, then fallback)."""
    servers = await _lookup_sharp_servers(domain)
    return [
        SharpServerTarget(addresses[0], port, priority, weight)
        for priority, weight, port, addresses in servers
    ]


async def verify_sharp_sender_domain(domain: str, peer_ip: Optional[str]) -> None:
    """Check that ``peer_ip`` is an authorised SHARP server for ``domain``.

    Mirrors verifySharpDomain() in dns-utils.js; raises SharpError on failure.
    """
    if not peer_ip:
        raise SharpError("No client IP provided")
    normalized = peer_ip[7:] if peer_ip.startswith("::ffff:") else peer_ip
    servers = await _lookup_sharp_servers(domain)
    authorised = set()
    for _priority, _weight, _port, addresses in servers:
        for address in addresses:
            authorised.add(address[7:] if address.startswith("::ffff:") else address)
    if normalized not in authorised:
        raise SharpError(
            f"IP {normalized} is not an authorized SHARP server for {domain}", 400
        )
