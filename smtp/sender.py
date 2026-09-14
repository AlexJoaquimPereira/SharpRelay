"""Asynchronous SMTP delivery used by the SHARP -> e-mail relay.

The blocking smtplib work runs in an executor so the bridge's event loop
is never blocked. Messages are well-formed MIME (UTF-8) with Date and
Message-ID headers, and are submitted over STARTTLS.
"""

import asyncio
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

SMTP_CONNECT_TIMEOUT = 30  # seconds


def _send_sync(from_addr, to_addr, subject, body, smtp_host, smtp_port,
               smtp_user, smtp_pass, html_body=None):
    msg = EmailMessage()
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid()

    with smtplib.SMTP(smtp_host, smtp_port, timeout=SMTP_CONNECT_TIMEOUT) as server:
        server.ehlo()
        server.starttls(context=ssl.create_default_context())
        server.ehlo()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)


async def send_smtp_email(from_addr, to_addr, subject, body,
                          smtp_host, smtp_user, smtp_pass, smtp_port=587,
                          html_body=None):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, _send_sync, from_addr, to_addr, subject, body,
        smtp_host, smtp_port, smtp_user, smtp_pass, html_body,
    )
