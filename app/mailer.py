"""Transactional account recovery; no token is returned through the request API."""
import os
import smtplib
from email.message import EmailMessage


def send_recovery(email, token):
    host = os.getenv('SMTP_HOST')
    sender = os.getenv('SMTP_FROM')
    if not host or not sender:
        raise RuntimeError('E-posta kurtarma servisi yapılandırılmadı.')
    message = EmailMessage()
    message['Subject'] = 'AegisNexus hesap kurtarma'
    message['From'] = sender
    message['To'] = email
    message.set_content('Hesap kurtarma kodunuz (15 dakika geçerli):\n\n' + token + '\n\nBu işlemi siz başlatmadıysanız kodu paylaşmayın.')
    with smtplib.SMTP(host, int(os.getenv('SMTP_PORT', '587')), timeout=10) as smtp:
        smtp.starttls()
        if os.getenv('SMTP_USER'):
            smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
        smtp.send_message(message)
