"""Relay SHARP messages to e-mail recipients via SMTP.

Recipients containing '@' are delivered over SMTP. SHARP handles
(containing '#') are the SHARP backend's responsibility and are reported
back as skipped.

SMTP credentials are read from the environment at call time and are never
hardcoded:
  SMTP_HOST   (required)  outgoing SMTP server, e.g. smtp.example.com
  SMTP_PORT   (optional)  defaults to 587 (STARTTLS)
  SMTP_USER   (required)  SMTP username
  SMTP_PASS   (required)  SMTP password / app password
"""

import os

from smtp.sender import send_smtp_email

REQUIRED_SMTP_VARS = ("SMTP_HOST", "SMTP_USER", "SMTP_PASS")


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
    body = msg.get("body", "")
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
