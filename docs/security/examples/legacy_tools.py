"""Representative legacy implementations, with no security-framework imports.

The outbox is a local stand-in for an existing mail queue; no email is sent.
"""

from pathlib import Path

OUTBOX: list[dict[str, str]] = []


def read_report(path: str) -> str:
    """Read a UTF-8 report using the existing implementation."""
    return Path(path).read_text(encoding="utf-8")


def queue_mail(to: str, subject: str, body: str) -> str:
    """Enqueue a message using the existing implementation."""
    OUTBOX.append({"to": to, "subject": subject, "body": body})
    return f"queued for {to}"
