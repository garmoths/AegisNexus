"""Rapor PDF üretim görevi (olay bildirimi analizinin çıktısı)."""
from app.celery_app import celery_app as app
from app.database import SessionLocal
from app.models import UserReport


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.generate_report_pdf")
def generate_report_pdf(self, report_id: int):
    from app.pdf_reports import generate_pdf
    with SessionLocal() as db:
        report = db.get(UserReport, report_id)
        if report is None:
            return {'status': 'not_found', 'report_id': report_id}
        try:
            report.pdf_path = generate_pdf(report)
            report.pdf_status = 'ready'
            db.commit()
            return {'status': 'success', 'report_id': report_id, 'pdf_path': report.pdf_path}
        except Exception:
            report.pdf_status = 'failed'
            db.commit()
            raise
