"""Outgoing email over SMTP (Settings > SMTP)."""

import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, make_msgid

from .web import HTTPError


def configured(settings):
    return bool(settings["smtp_host"] and settings["smtp_from"])


def send(settings, to, subject, body):
    """Send a plain-text message; raises HTTPError with a readable reason."""
    if not configured(settings):
        raise HTTPError(400, "Email is not set up: fill in Settings > SMTP first")
    msg = EmailMessage()
    msg["From"] = formataddr(("RussDesk", settings["smtp_from"]))
    msg["To"] = to
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=settings["smtp_from"].rpartition("@")[2] or None)
    msg.set_content(body)
    host, port = settings["smtp_host"], int(settings["smtp_port"] or 0)
    security = settings["smtp_security"]
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port or 465, timeout=20,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port or 587, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=ssl.create_default_context())
            if settings["smtp_user"]:
                server.login(settings["smtp_user"], settings["smtp_password"])
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPError(502, f"Could not send email: {exc}")
