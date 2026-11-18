"""Transactional account recovery; no token is returned through the request API."""
import smtplib
from email.message import EmailMessage

from app.config import get_settings


def send_recovery(email, token):
    settings = get_settings()
    host, sender = settings.smtp_host, settings.smtp_from
    if not host or not sender:
        raise RuntimeError('E-posta kurtarma servisi yapılandırılmadı.')
    message = EmailMessage()
    message['Subject'] = 'AegisNexus hesap kurtarma'
    message['From'] = sender
    message['To'] = email
    message.set_content('Hesap kurtarma kodunuz (15 dakika geçerli):\n\n' + token + '\n\nBu işlemi siz başlatmadıysanız kodu paylaşmayın.')
    with smtplib.SMTP(host, settings.smtp_port, timeout=10) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)
