import asyncio
import smtplib
from email.mime.text import MIMEText

def _send_sync(from_addr, to_addr, subject, body, smtp_host, smtp_user, smtp_pass):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = to_addr

    with smtplib.SMTP(smtp_host, 587) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_addr, [to_addr], msg.as_string())

async def send_smtp_email(from_addr, to_addr, subject, body, smtp_host, smtp_user, smtp_pass):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_sync, from_addr, to_addr, subject, body, smtp_host, smtp_user, smtp_pass)
