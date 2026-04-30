"""Victim Atlas ORM modelleri ve database.py fonksiyonları için testler.

PostgreSQL gerektirmedien, SQLAlchemy SQLite in-memory ile model doğrulaması yapar.
"""
import json
import unittest
from datetime import datetime, timezone

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import (
    APIKey,
    AlertSubscription,
    CaseTag,
    IngestRun,
    RawDocument,
    SourceRegistry,
    Subscription,
    User,
    UserReport,
    UserRole,
    VictimCase,
    VictimCaseEvidence,
)


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

    def test_user_create(self):
        with self.Session() as db:
            user = User(email="test@aegisnexus.dev", role=UserRole.free)
            db.add(user)
            db.commit()
            self.assertIsNotNone(user.id)
            self.assertEqual(user.email, "test@aegisnexus.dev")
            self.assertEqual(user.role, UserRole.free)
            self.assertTrue(user.is_active)

    def test_user_unique_email(self):
        with self.Session() as db:
            u1 = User(email="unique@aegisnexus.dev", role=UserRole.free)
            db.add(u1)
            db.commit()
            u2 = User(email="unique@aegisnexus.dev", role=UserRole.premium)
            db.add(u2)
            with self.assertRaises(Exception):
                db.commit()

    def test_api_key_create(self):
        with self.Session() as db:
            user = User(email="keytest@aegisnexus.dev", role=UserRole.premium)
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

    def test_source_registry_create(self):
        with self.Session() as db:
            src = SourceRegistry(
                name="Test Source",
                base_url="https://example.com/feed",
                trust_tier="tier1",
            )
            db.add(src)
            db.commit()
            self.assertIsNotNone(src.id)
            self.assertTrue(src.enabled)

    def test_victim_case_create(self):
        with self.Session() as db:
            case = VictimCase(
                case_slug="test-smishing-001",
                case_title="Test Smishing Vakası",
                attack_method="smishing",
                loss_type="bank_account",
                target_platform="mobile",
                critical_warning="SMS ile banka bilgilerinizi vermeyin",
                narrative_summary="Kullanıcıya sahte SMS gönderildi",
                defense_steps_json=["Adım 1", "Adım 2"],
                confidence_score=85,
                severity_score=70,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(case)
            db.commit()
            self.assertIsNotNone(case.id)
            self.assertEqual(case.attack_method, "smishing")
            self.assertTrue(case.is_hot)
            self.assertTrue(case.is_published)

    def test_victim_case_slug_unique(self):
        with self.Session() as db:
            c1 = VictimCase(
                case_slug="unique-slug",
                case_title="Vaka 1",
                attack_method="phishing",
                loss_type="identity",
                target_platform="web",
                critical_warning="Uyarı",
                narrative_summary="Özet",
                defense_steps_json=[],
                confidence_score=60,
                severity_score=50,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(c1)
            db.commit()
            c2 = VictimCase(
                case_slug="unique-slug",
                case_title="Vaka 2",
                attack_method="phishing",
                loss_type="identity",
                target_platform="web",
                critical_warning="Uyarı 2",
                narrative_summary="Özet 2",
                defense_steps_json=[],
                confidence_score=70,
                severity_score=60,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(c2)
            with self.assertRaises(Exception):
                db.commit()

    def test_case_tag_create(self):
        with self.Session() as db:
            case = VictimCase(
                case_slug="tagged-case",
                case_title="Etiketli Vaka",
                attack_method="phishing",
                loss_type="credit_card",
                target_platform="web",
                critical_warning="Uyarı",
                narrative_summary="Özet",
                defense_steps_json=[],
                confidence_score=75,
                severity_score=65,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(case)
            db.commit()
            tag = CaseTag(case_id=case.id, tag="kredi_karti")
            db.add(tag)
            db.commit()
            self.assertIsNotNone(tag.id)

    def test_user_report_create(self):
        with self.Session() as db:
            user = User(email="report@aegisnexus.dev", role=UserRole.free)
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

    def test_subscription_create(self):
        with self.Session() as db:
            user = User(email="sub@aegisnexus.dev", role=UserRole.free)
            db.add(user)
            db.commit()
            sub = Subscription(
                user_id=user.id,
                plan=UserRole.premium,
                is_active=True,
            )
            db.add(sub)
            db.commit()
            self.assertIsNotNone(sub.id)
            self.assertEqual(sub.plan, UserRole.premium)

    def test_alert_subscription_create(self):
        with self.Session() as db:
            user = User(email="alert@aegisnexus.dev", role=UserRole.free)
            db.add(user)
            db.commit()
            alert = AlertSubscription(
                user_id=user.id,
                region="İstanbul",
                attack_method="phishing",
            )
            db.add(alert)
            db.commit()
            self.assertIsNotNone(alert.id)
            self.assertEqual(alert.region, "İstanbul")

    def test_ingest_run_create(self):
        with self.Session() as db:
            run = IngestRun(
                started_at=datetime.now(timezone.utc),
                status="running",
            )
            db.add(run)
            db.commit()
            self.assertIsNotNone(run.id)
            self.assertEqual(run.status, "running")
            self.assertEqual(run.documents_fetched, 0)

    def test_evidence_create(self):
        with self.Session() as db:
            src = SourceRegistry(name="EvSrc", base_url="https://x.com", trust_tier="tier1")
            db.add(src)
            db.commit()
            doc = RawDocument(
                source_id=src.id,
                external_id="ext-1",
                url="https://x.com/article",
                title="Test Article",
                raw_text="Some text",
                hash="abc123",
            )
            db.add(doc)
            db.commit()
            case = VictimCase(
                case_slug="evidence-case",
                case_title="Delilli Vaka",
                attack_method="phishing",
                loss_type="identity",
                target_platform="web",
                critical_warning="Uyarı",
                narrative_summary="Özet",
                defense_steps_json=[],
                confidence_score=80,
                severity_score=70,
                first_seen=datetime.now(timezone.utc),
                last_seen=datetime.now(timezone.utc),
            )
            db.add(case)
            db.commit()
            ev = VictimCaseEvidence(
                case_id=case.id,
                raw_document_id=doc.id,
                evidence_snippet="Dolandırıcılık kanıtı",
                evidence_weight=0.9,
            )
            db.add(ev)
            db.commit()
            self.assertIsNotNone(ev.id)
            self.assertAlmostEqual(ev.evidence_weight, 0.9)


class TestParseDt(unittest.TestCase):
    """_parse_dt helper fonksiyonu testleri."""

    def _import_parse_dt(self):
        from modules.victim_atlas.database import _parse_dt
        return _parse_dt

    def test_parse_valid_iso(self):
        parse_dt = self._import_parse_dt()
        result = parse_dt("2026-04-30T12:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)
        self.assertEqual(result.month, 4)

    def test_parse_none(self):
        parse_dt = self._import_parse_dt()
        self.assertIsNone(parse_dt(None))

    def test_parse_empty(self):
        parse_dt = self._import_parse_dt()
        self.assertIsNone(parse_dt(""))

    def test_parse_invalid(self):
        parse_dt = self._import_parse_dt()
        self.assertIsNone(parse_dt("not-a-date"))


if __name__ == "__main__":
    unittest.main()
