# Consolidated SHARP Proxy + SMTP Bridge
# Uses TLS for encrypted and secure communication
# SHARP is a copyright of @outpoot

import asyncio
import json
import ssl
from bridge.relay import handle_send

SHARP_BACKEND_HOST = '127.0.0.1'
SHARP_BACKEND_PORT = 5002
BRIDGE_PORT = 5000
CERT_FILE = 'certs/server.crt'
KEY_FILE = 'certs/server.key'

async def forward_to_sharp_backend(data: bytes) -> bytes:
    reader, writer = await asyncio.open_connection(SHARP_BACKEND_HOST, SHARP_BACKEND_PORT)
    writer.write(data)
    await writer.drain()
    response = await reader.read(65536)
    writer.close()
    await writer.wait_closed()
    return response

async def handle_connection(reader, writer):
    data = await reader.read(65536)
    addr = writer.get_extra_info('peername')
    print(f"Connection from {addr}")

    try:
        msg = json.loads(data.decode())
        if msg.get("type") == "SEND":
            to_list = msg.get("to", [])
            if any("@" in r or "#" not in r for r in to_list):
                await handle_send(msg)
                response = {"type": "OK", "id": msg.get("id")}
            else:
                response_data = await forward_to_sharp_backend(data)
                writer.write(response_data)
                await writer.drain()
                writer.close()
                return
        else:
            response_data = await forward_to_sharp_backend(data)
            writer.write(response_data)
            await writer.drain()
            writer.close()
            return
    except Exception as e:
        response = {"type": "ERROR", "error": str(e)}

    writer.write((json.dumps(response) + "\n").encode())
    await writer.drain()
    writer.close()

async def start_bridge():
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    server = await asyncio.start_server(handle_connection, '0.0.0.0', BRIDGE_PORT, ssl=ssl_ctx)
    print(f"SHARP Proxy + SMTP Bridge listening on port {BRIDGE_PORT}")
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio.run(start_bridge())
