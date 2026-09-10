from smtp.sender import send_smtp_email

async def handle_send(msg: dict) -> dict:
    from_addr = msg.get('from', '').replace('#', '@')
    if not from_addr or '@' not in from_addr:
        from_addr = msg.get('from', '[unknown]').replace('#', '@')
    subject = msg.get('subject', 'No Subject')
    body = msg.get('body', '')
    to_list = msg.get('to') or []
    for recipient in to_list:
        if not isinstance(recipient, str):
            continue
        if '#' in recipient:
            # TODO: Implement SHARP-SHARP relay
            continue
        to_addr = recipient
        await send_smtp_email(from_addr, to_addr, subject, body,
                        smtp_host="smtp.example.com",
                        smtp_user="[EMAIL]",
                        smtp_pass="password")
    return {"type": "OK", "id": msg.get("id")}
