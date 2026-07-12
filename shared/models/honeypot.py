"""
Honeypot Event Model - Ortak Model
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text

from app.database import Base


class HoneypotEvent(Base):
    """Honeypot olay kayıtları"""
    __tablename__ = "honeypot_events"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(128), index=True)
    user_agent = Column(String(512))
    path = Column(String(256))
    referer = Column(String(512), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
