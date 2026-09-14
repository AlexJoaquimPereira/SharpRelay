"""SMTP side of the bridge.

Outbound (bridge message -> e-mail): recipients containing '@' are delivered
over SMTP. SHARP handles ('#') are delivered by sharp/client.py over
SHARP/1.3 and are reported here as skipped.

Inbound (SHARP/1.3 -> e-mail): relay_sharp_to_smtp() converts a message
accepted by sharp/server.py into SMTP mail, mapping user#domain to
user@domain.

SMTP credentials are read from the environment at call time and are never
hardcoded:
  SMTP_HOST   (required)  outgoing SMTP server, e.g. smtp.example.com
  SMTP_PORT   (optional)  defaults to 587 (STARTTLS)
  SMTP_USER   (required)  SMTP username
  SMTP_PASS   (required)  SMTP password / app password
"""

import os

from sharp.protocol import SharpError, sharp_address_to_email
from smtp.sender import send_smtp_email

REQUIRED_SMTP_VARS = ("SMTP_HOST", "SMTP_USER", "SMTP_PASS")


def _body_parts(msg: dict):
    """Split a bridge/SHARP message into (text, html) parts for MIME delivery."""
    body = msg.get("body") or ""
    html_body = msg.get("html_body")
    if not html_body and (msg.get("content_type") or "").lower() == "text/html":
        html_body, body = body, ""
    return body, html_body


def _smtp_config():
    missing = [name for name in REQUIRED_SMTP_VARS if not os.environ.get(name)]
    if missing:
        raise RuntimeError(
            "SMTP relay not configured; set environment variable(s): "
            + ", ".join(missing)
        )
    return (
        os.environ["SMTP_HOST"],
        int(os.environ.get("SMTP_PORT", "587")),
        os.environ["SMTP_USER"],
        os.environ["SMTP_PASS"],
    )


async def handle_send(msg: dict) -> dict:
    """Relay a SHARP SEND message to its e-mail recipients."""
    msg_id = msg.get("id")
    raw_from = msg.get("from", "")
    from_addr = raw_from.replace("#", "@").strip()
    if "@" not in from_addr:
        return {
            "type": "ERROR", "id": msg_id,
            "error": f"invalid 'from' address: {raw_from!r}",
        }

    subject = msg.get("subject", "No Subject")
    body, html_body = _body_parts(msg)
    to_list = msg.get("to") if isinstance(msg.get("to"), list) else []

    try:
        smtp_host, smtp_port, smtp_user, smtp_pass = _smtp_config()
    except RuntimeError as exc:
        return {"type": "ERROR", "id": msg_id, "error": str(exc)}

    delivered, failed, skipped = [], [], []
    for recipient in to_list:
        if not isinstance(recipient, str) or "@" not in recipient:
            # SHARP handles / invalid entries: not deliverable over SMTP.
            skipped.append(recipient)
            continue
        try:
            await send_smtp_email(
                from_addr, recipient, subject, body,
                smtp_host=smtp_host, smtp_port=smtp_port,
                smtp_user=smtp_user, smtp_pass=smtp_pass,
                html_body=html_body,
            )
            delivered.append(recipient)
        except Exception as exc:
            failed.append({"recipient": recipient, "error": str(exc)})

    return {
        "type": "OK",
        "id": msg_id,
        "from": from_addr,
        "delivered": delivered,
        "failed": failed,
        "skipped": skipped,
    }


async def relay_sharp_to_smtp(sender: str, recipient: str, subject: str, body: str,
                              content_type: str = "text/plain",
                              html_body=None) -> dict:
    """Convert an inbound SHARP/1.3 message into SMTP mail.

    Called by the SHARP listener (sharp/server.py) through bridge/proxy.py.
    SHARP addresses are mapped to mailboxes (user#domain -> user@domain).
    SHARP attachments are server-side keys and cannot be bridged, so they are
    ignored; everything else is delivered as MIME (text plus HTML when given).
    """
    try:
        from_addr = sharp_address_to_email(sender)
        to_addr = sharp_address_to_email(recipient)
    except SharpError as exc:
        return {"type": "ERROR", "recipient": recipient, "error": str(exc)}

    try:
        smtp_host, smtp_port, smtp_user, smtp_pass = _smtp_config()
    except RuntimeError as exc:
        return {"type": "ERROR", "recipient": to_addr, "error": str(exc)}

    text, html = _body_parts({
        "body": body, "html_body": html_body, "content_type": content_type,
    })
    try:
        await send_smtp_email(
            from_addr, to_addr, subject or "No Subject", text or "",
            smtp_host=smtp_host, smtp_port=smtp_port,
            smtp_user=smtp_user, smtp_pass=smtp_pass,
            html_body=html,
        )
    except Exception as exc:
        return {"type": "ERROR", "recipient": to_addr, "error": str(exc)}

    return {"type": "OK", "from": from_addr, "recipient": to_addr}
