from bridge.relay import handle_send

async def dispatch_sharp_message(msg: dict) -> dict:
    msg_type = msg.get('type')
    if msg_type == 'SEND':
        return await handle_send(msg)
    if msg_type == 'HELLO':
        return {"type": "OK", "msg": "HELLO accepted"}
    return {"type": "ERROR", "msg": f"Unknown message type: {msg_type}"}
