"""
Email parser for AI Analyzer.

Supports raw RFC 2822 messages, simple header/body blocks, and forwarded email
snippets copied from common mail clients.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_string
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parseaddr
from typing import Dict, List, Optional


_FORWARDED_SPLIT_RE = re.compile(r"^[-]{2,}\s*Forwarded message\s*[-]{2,}$", re.IGNORECASE | re.MULTILINE)
_URL_RE = re.compile(r"https?://[\w\-._~:/?#@!$&'()*+,;=%]+", re.IGNORECASE)
_SUSPICIOUS_TLDS = (
    ".tk",
    ".top",
    ".xyz",
    ".click",
    ".icu",
    ".ml",
    ".support",
    ".help",
    ".center",
)

_BRAND_KEYWORDS = {
    "banka": ("bank", "banka", "garanti", "akbank", "işbank", "isbank", "ziraat", "yapı kredi", "vakıfbank", "finansbank", "qnb"),
    "platform": ("google", "apple", "microsoft", "facebook", "instagram", "paypal", "amazon", "netflix", "twitter", "x.com"),
}


def _decode_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return value.strip()


def _extract_domain(address: Optional[str]) -> Optional[str]:
    if not address or "@" not in address:
        return None
    return address.split("@", 1)[1].strip().lower() or None


def _collect_addresses(message: Message, field_name: str) -> List[str]:
    values: List[str] = []
    for _, address in getaddresses(message.get_all(field_name, [])):
        if address:
            values.append(address.strip())
    return values


def _get_body_text(message: Message) -> str:
    if message.is_multipart():
        parts: List[str] = []
        for part in message.walk():
            content_type = (part.get_content_type() or "").lower()
            disposition = (part.get_content_disposition() or "").lower()
            if content_type == "text/plain" and disposition != "attachment":
                try:
                    payload = part.get_payload(decode=True)
                    charset = part.get_content_charset() or "utf-8"
                    if payload:
                        parts.append(payload.decode(charset, errors="replace"))
                except Exception:
                    text = part.get_payload()
                    if isinstance(text, str):
                        parts.append(text)
        return "\n".join(part.strip() for part in parts if part and part.strip())

    payload = message.get_payload(decode=True)
    if payload is not None:
        charset = message.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except Exception:
            return payload.decode("utf-8", errors="replace")

    raw_payload = message.get_payload()
    return raw_payload if isinstance(raw_payload, str) else ""


def _extract_attachments(message: Message) -> List[str]:
    attachments: List[str] = []
    if not message.is_multipart():
        return attachments

    for part in message.walk():
        filename = part.get_filename()
        if filename:
            decoded = _decode_value(filename)
            if decoded:
                attachments.append(decoded)
    return attachments


def _scan_header_signals(from_name: Optional[str], from_domain: Optional[str], reply_to: List[str], subject: Optional[str]) -> tuple[Dict[str, float], List[str]]:
    signals = {
        "reply_to_mismatch": 0.0,
        "display_name_mismatch": 0.0,
        "sender_domain_suspicious": 0.0,
        "subject_urgency": 0.0,
        "total": 0.0,
    }
    evidence: List[str] = []

    if reply_to and from_domain:
        reply_domains = {_extract_domain(address) for address in reply_to}
        reply_domains.discard(None)
        if reply_domains and any(domain != from_domain for domain in reply_domains):
            signals["reply_to_mismatch"] = 0.35
            evidence.append("Reply-To domaini gönderici domaini ile eşleşmiyor")

    if from_name and from_domain:
        from_name_lower = from_name.lower()
        if any(keyword in from_name_lower for keywords in _BRAND_KEYWORDS.values() for keyword in keywords):
            if not any(keyword in (from_domain or "") for keywords in _BRAND_KEYWORDS.values() for keyword in keywords):
                signals["display_name_mismatch"] = 0.40
                evidence.append("Görünen ad marka taklidi yapıyor")

    if from_domain:
        suspicious = False
        if from_domain.startswith("xn--") or any(from_domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
            suspicious = True
        if sum(ch == "-" for ch in from_domain) >= 2:
            suspicious = True
        if sum(ch.isdigit() for ch in from_domain) >= 3:
            suspicious = True
        if suspicious:
            signals["sender_domain_suspicious"] = 0.30
            evidence.append("Gönderici domaini şüpheli görünüyor")

    if subject:
        subject_lower = subject.lower()
        urgency_words = (
            "acil",
            "hemen",
            "şimdi",
            "süre doluyor",
            "son gün",
            "son tarih",
            "urgent",
            "immediately",
            "verify",
            "doğrula",
            "doğrulama",
            "uyarı",
        )
        if any(word in subject_lower for word in urgency_words):
            signals["subject_urgency"] = 0.25
            evidence.append("Konu satırı aciliyet sinyali içeriyor")

    signals["total"] = min(1.0, sum(value for key, value in signals.items() if key != "total"))
    return signals, evidence


@dataclass
class ParsedEmail:
    from_address: Optional[str] = None
    from_domain: Optional[str] = None
    display_name: Optional[str] = None
    to: List[str] = field(default_factory=list)
    reply_to: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    date: Optional[str] = None
    body_text: str = ""
    urls: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    email_signals: Dict[str, float] = field(default_factory=dict)
    email_evidence: List[str] = field(default_factory=list)


def parse_email(raw_message: str) -> ParsedEmail:
    """Parse an email-like string into structured fields and signals."""
    candidate = (raw_message or "").strip()
    if not candidate:
        return ParsedEmail()

    split_parts = _FORWARDED_SPLIT_RE.split(candidate, maxsplit=1)
    if len(split_parts) == 2 and split_parts[1].strip():
        candidate = split_parts[1].strip()

    message = message_from_string(candidate)

    display_name, from_address = parseaddr(_decode_value(message.get("From")) or "")
    from_address = from_address or None
    from_domain = _extract_domain(from_address)

    subject = _decode_value(message.get("Subject"))
    date = _decode_value(message.get("Date"))

    to = _collect_addresses(message, "To")
    reply_to = _collect_addresses(message, "Reply-To")
    cc = _collect_addresses(message, "Cc")
    body_text = _get_body_text(message).strip()
    urls = _URL_RE.findall(body_text)
    attachments = _extract_attachments(message)

    email_signals, email_evidence = _scan_header_signals(
        from_name=display_name or None,
        from_domain=from_domain,
        reply_to=reply_to,
        subject=subject,
    )

    return ParsedEmail(
        from_address=from_address,
        from_domain=from_domain,
        display_name=display_name or None,
        to=to,
        reply_to=reply_to,
        cc=cc,
        subject=subject,
        date=date,
        body_text=body_text,
        urls=urls,
        attachments=attachments,
        email_signals=email_signals,
        email_evidence=email_evidence,
    )