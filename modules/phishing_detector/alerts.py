"""
Alert System - Slack & Email Notifications
"""

import os
import sqlite3
from datetime import datetime
from typing import List, Dict
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AlertManager:
    def __init__(self):
        self.slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
        self.email_from = os.getenv('EMAIL_FROM', 'alerts@example.com')
        self.email_password = os.getenv('EMAIL_PASSWORD')
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', 587))
    
    def send_slack_alert(self, title: str, message: str, risk_level: str = "⚠️"):
        """
        Slack'e alert gönder
        """
        if not self.slack_webhook:
            return False
        
        # Risk level colors
        colors = {
            "🚨": "#FF0000",    # Critical (red)
            "🟠": "#FF9900",    # High (orange)
            "⚠️": "#FFFF00",    # Medium (yellow)
            "✅": "#00FF00",    # Safe (green)
        }
        
        payload = {
            "attachments": [{
                "color": colors.get(risk_level, "#CCCCCC"),
                "title": f"{risk_level} {title}",
                "text": message,
                "ts": int(datetime.utcnow().timestamp())
            }]
        }
        
        try:
            response = requests.post(self.slack_webhook, json=payload, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Slack alert failed: {e}")
            return False
    
    def send_email_alert(self, recipient: str, subject: str, html_body: str):
        """
        Email ile alert gönder
        """
        if not self.email_password:
            return False
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.email_from
            msg['To'] = recipient
            
            msg.attach(MIMEText(html_body, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.email_from, self.email_password)
                server.send_message(msg)
            
            return True
        except Exception as e:
            print(f"❌ Email alert failed: {e}")
            return False
    
    def alert_phishing_detected(self, url: str, score: int, details: List[str]):
        """
        Yeni phishing URL tespit edildi alert'i
        """
        risk_emoji = "🚨" if score < 30 else "🟠" if score < 60 else "⚠️"
        
        slack_message = f"""
*URL:* {url}
*Score:* {score}/100
*Risk:* {risk_emoji}
*Details:* {', '.join(details[:3])}
        """.strip()
        
        self.send_slack_alert(
            title="Phishing URL Detected",
            message=slack_message,
            risk_level=risk_emoji
        )
    
    def alert_whitelist_updated(self, domain: str, action: str):
        """
        Whitelist güncellendi alert'i
        """
        slack_message = f"Domain {action}: `{domain}`"
        
        self.send_slack_alert(
            title="Whitelist Updated",
            message=slack_message,
            risk_level="✅"
        )
    
    def send_daily_digest(self, stats: Dict, recipient: str = None):
        """
        Günlük özet email
        """
        if not recipient:
            recipient = os.getenv('ADMIN_EMAIL', 'admin@example.com')
        
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>📊 Aegis Nexus Daily Report</h2>
                <p>Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
                
                <h3>Statistics</h3>
                <ul>
                    <li><strong>Phishing URLs Found:</strong> {stats.get('phishing_count', 0)}</li>
                    <li><strong>Critical Threats:</strong> {stats.get('critical_count', 0)}</li>
                    <li><strong>Whitelist Domains:</strong> {stats.get('whitelist_count', 0)}</li>
                </ul>
                
                <p style="color: #666; font-size: 12px;">
                    This is an automated alert. Do not reply to this email.
                </p>
            </body>
        </html>
        """
        
        return self.send_email_alert(
            recipient=recipient,
            subject="Aegis Nexus - Daily Security Report",
            html_body=html
        )

# Singleton instance
_alert_manager = None

def get_alert_manager():
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
