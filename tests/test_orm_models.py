"""Victim Atlas ORM modelleri ve database.py fonksiyonları için testler.

PostgreSQL gerektirmedien, SQLAlchemy SQLite in-memory ile model doğrulaması yapar.
"""
import json
import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import APIKey, User, UserReport, UserRole


def _sqlite_engine():
    engine = create_engine("sqlite:///:memory:", echo=False)
    # SQLite için foreign key desteği
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, _):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    return engine


class TestORMModels(unittest.TestCase):
    """Tüm yeni ORM modellerinin oluşturma ve ilişki testleri."""

    @classmethod
    def setUpClass(cls):
        cls.engine = _sqlite_engine()
        # SQLite JSON desteği için native_json gerekmiyor, string olarak saklanır
        Base.metadata.create_all(cls.engine)
        cls.Session = sessionmaker(bind=cls.engine)

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()

    def test_user_create(self):
        with self.Session() as db:
            user = User(email="test@example.com", role=UserRole.free)
            db.add(user)
            db.commit()
            self.assertIsNotNone(user.id)
            self.assertEqual(user.email, "test@example.com")
            self.assertEqual(user.role, UserRole.free)
            self.assertTrue(user.is_active)

    def test_user_unique_email(self):
        with self.Session() as db:
            u1 = User(email="unique@example.com", role=UserRole.free)
            db.add(u1)
            db.commit()
            u2 = User(email="unique@example.com", role=UserRole.premium)
            db.add(u2)
            with self.assertRaises(Exception):
                db.commit()

    def test_api_key_create(self):
        with self.Session() as db:
            user = User(email="keytest@example.com", role=UserRole.premium)
            db.add(user)
            db.commit()
            key = APIKey(
                user_id=user.id,
                key_hash="abc123hash",
                key_prefix="aeg_",
                label="Kişisel",
                role=UserRole.premium,
                rate_limit_tier="premium",
            )
            db.add(key)
            db.commit()
            self.assertIsNotNone(key.id)
            self.assertEqual(key.user_id, user.id)
            self.assertTrue(key.is_active)





    def test_user_report_create(self):
        with self.Session() as db:
            user = User(email="report@example.com", role=UserRole.free)
            db.add(user)
            db.commit()
            report = UserReport(
                user_id=user.id,
                user_description="SMS ile dolandırıldım",
                ai_analysis={"attack_type": "smishing", "risk": "high"},
                protection_plan="1. Bankayı arayın\n2. Kartı dondurun",
                report_quota_month="2026-04",
            )
            db.add(report)
            db.commit()
            self.assertIsNotNone(report.id)
            self.assertEqual(report.user_id, user.id)




