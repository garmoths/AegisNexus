"""Celery task testleri — mock ile, gerçek broker gerektirmez."""
import unittest
from unittest.mock import patch, MagicMock


class TestCeleryTaskDefinitions(unittest.TestCase):
    """Task tanımlarının doğru yapıldığını doğrula."""

    def test_app_created(self):
        from modules.victim_atlas.celery_tasks import app
        self.assertEqual(app.main, "aegis_victim_atlas")

    def test_beat_schedule_has_required_tasks(self):
        from modules.victim_atlas.celery_tasks import app
        schedule = app.conf.beat_schedule
        self.assertIn("victim-atlas-ingest-6h", schedule)
        self.assertIn("victim-atlas-classify-hourly", schedule)
        self.assertIn("victim-atlas-prune-nightly", schedule)
        self.assertIn("victim-atlas-weekly-digest", schedule)

    def test_task_names_registered(self):
        from modules.victim_atlas.celery_tasks import (
            ingest_6h,
            classify_pending,
            prune_hotset,
            alert_critical,
            weekly_digest,
            generate_report_pdf,
            enrich_cases,
        )
        self.assertIn("modules.victim_atlas.celery_tasks.ingest_6h", ingest_6h.name)
        self.assertIn("modules.victim_atlas.celery_tasks.classify_pending", classify_pending.name)
        self.assertIn("modules.victim_atlas.celery_tasks.prune_hotset", prune_hotset.name)
        self.assertIn("modules.victim_atlas.celery_tasks.alert_critical", alert_critical.name)
        self.assertIn("modules.victim_atlas.celery_tasks.weekly_digest", weekly_digest.name)
        self.assertIn("modules.victim_atlas.celery_tasks.generate_report_pdf", generate_report_pdf.name)
        self.assertIn("modules.victim_atlas.celery_tasks.enrich_cases", enrich_cases.name)


class TestIngest6h(unittest.TestCase):
    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    @patch("modules.victim_atlas.ingest.run_daily_pipeline")
    def test_ingest_success(self, mock_pipeline, mock_session):
        mock_pipeline.return_value = {"documents_fetched": 10, "cases_created": 3}
        from modules.victim_atlas.celery_tasks import ingest_6h
        result = ingest_6h.run()
        self.assertEqual(result["cases_created"], 3)


class TestClassifyPending(unittest.TestCase):
    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    @patch("modules.victim_atlas.gemini_service.classify_case")
    def test_classify_with_pending(self, mock_classify, mock_session_cls):
        # Mock DB session
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        # Mock pending cases
        mock_case = MagicMock()
        mock_case.id = 1
        mock_case.narrative_summary = "Sahte SMS ile dolandırıcılık"
        mock_case.is_published = False
        mock_case.severity_score = 50
        mock_db.query.return_value.filter_by.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_case]
        mock_db.query.return_value.filter_by.return_value.first.return_value = None

        # Mock Gemini
        mock_classify.return_value = {
            "attack_method": "smishing",
            "loss_type": "bank_account",
            "severity": 80,
            "confidence": 75,
            "tags": ["sms", "banka"],
            "region": "İstanbul",
            "critical_warning": "SMS linklerine dikkat",
        }

        from modules.victim_atlas.celery_tasks import classify_pending
        result = classify_pending.run()
        self.assertEqual(result["classified"], 1)

    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    def test_classify_no_pending(self, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        mock_db.query.return_value.filter_by.return_value.order_by.return_value.limit.return_value.all.return_value = []

        from modules.victim_atlas.celery_tasks import classify_pending
        result = classify_pending.run()
        self.assertEqual(result["classified"], 0)


class TestAlertCritical(unittest.TestCase):
    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    def test_alert_no_subscribers(self, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        mock_case = MagicMock()
        mock_case.id = 1
        mock_case.attack_method = "smishing"
        mock_case.region = "İstanbul"

        # İlk .get() → case, ikinci .filter_by().all() → boş liste
        mock_db.query.return_value.get.return_value = mock_case
        mock_db.query.return_value.filter_by.return_value.all.return_value = []

        from modules.victim_atlas.celery_tasks import alert_critical
        result = alert_critical.run(case_id=1)
        # No subscribers → early return with status no_subscribers
        self.assertEqual(result["status"], "no_subscribers")

    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    def test_alert_case_not_found(self, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        mock_db.query.return_value.get.return_value = None

        from modules.victim_atlas.celery_tasks import alert_critical
        result = alert_critical.run(case_id=999)
        self.assertEqual(result["status"], "not_found")


class TestWeeklyDigest(unittest.TestCase):
    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    @patch("modules.victim_atlas.gemini_service.generate_weekly_digest")
    def test_digest_success(self, mock_gen, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db

        mock_case = MagicMock()
        mock_case.case_title = "Test vaka"
        mock_case.attack_method = "phishing"
        mock_case.severity_score = 80
        mock_case.last_seen = MagicMock()
        mock_case.is_published = True
        mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [mock_case]

        mock_gen.return_value = "Haftalık bülten metni"

        from modules.victim_atlas.celery_tasks import weekly_digest
        result = weekly_digest.run()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["total_cases"], 1)


class TestGenerateReportPdf(unittest.TestCase):
    @patch("modules.victim_atlas.celery_tasks.SessionLocal")
    def test_pdf_not_found(self, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        mock_db.query.return_value.get.return_value = None

        from modules.victim_atlas.celery_tasks import generate_report_pdf
        result = generate_report_pdf.run(report_id=999)
        self.assertEqual(result["status"], "not_found")


if __name__ == "__main__":
    unittest.main()
