"""Celery task testleri — mock ile, gerçek broker gerektirmez."""
import unittest
from unittest.mock import MagicMock, patch


class TestCeleryTaskDefinitions(unittest.TestCase):
    """Task tanımlarının doğru yapıldığını doğrula."""

    def test_app_created(self):
        from app.celery_app import celery_app
        from app.workflow_tasks import generate_report_pdf
        self.assertIs(generate_report_pdf.app, celery_app)












class TestGenerateReportPdf(unittest.TestCase):
    @patch("app.workflow_tasks.SessionLocal")
    def test_pdf_not_found(self, mock_session_cls):
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        mock_db.get.return_value = None
        mock_db.__enter__.return_value = mock_db

        from app.workflow_tasks import generate_report_pdf
        result = generate_report_pdf.run(report_id=999)
        self.assertEqual(result["status"], "not_found")


if __name__ == "__main__":
    unittest.main()
