"""Victim Atlas Celery görevleri — Gemini sınıflandırma, uyarı, bülten, PDF üretimi.

Mevcut honeypot/celery_tasks.py'deki victim atlas task'lerine ek olarak:
- classify_pending: Her saat başı Gemini ile sınıflandır
- alert_critical: Kritik vaka webhook bildirimi
- weekly_digest: Pazartesi günü bülten üret
- generate_report_pdf: Rapor PDF üretimi (free: ayda 3)
- ingest_6h: 6 saatte bir ingest (ek schedule)
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from app.celery_app import celery_app as app
from app.database import SessionLocal
from app.models import (
    AlertSubscription,
    CaseTag,
    Subscription,
    User,
    UserReport,
    UserRole,
    VictimCase,
)

logger = logging.getLogger(__name__)


# ── Yardımcı ──────────────────────────────────────────────

def _get_gemini_service():
    from .gemini_service import classify_case, analyze_user_report, generate_weekly_digest, generate_protection_card
    return classify_case, analyze_user_report, generate_weekly_digest, generate_protection_card


# ── Görevler ──────────────────────────────────────────────

@app.task(bind=True, max_retries=3, name="modules.victim_atlas.celery_tasks.ingest_6h")
def ingest_6h(self):
    """6 saatte bir RSS kaynaklarından yeni belge ve vaka çek."""
    try:
        from .ingest import run_daily_pipeline
        max_items = int(os.getenv("VICTIM_ATLAS_SOURCE_ITEM_LIMIT", "120"))
        result = run_daily_pipeline(max_items_per_source=max_items)
        logger.info("ingest_6h tamamlandı: %s", result)
        return result
    except Exception as exc:
        logger.error("ingest_6h hatası: %s", exc)
        raise self.retry(exc=exc, countdown=180)


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.classify_pending")
def classify_pending(self):
    """Her saat başı yayınlanmamış vakaları Gemini ile sınıflandır."""
    db = SessionLocal()
    try:
        pending = (
            db.query(VictimCase)
            .filter_by(is_published=False)
            .order_by(VictimCase.id.desc())
            .limit(50)
            .all()
        )
        if not pending:
            return {"status": "no_pending", "classified": 0}

        classify_case, *_ = _get_gemini_service()
        classified = 0
        errors = 0

        for case in pending:
            try:
                result = classify_case(case.narrative_summary or "")
                if result.get("attack_method"):
                    case.attack_method = result["attack_method"]
                if result.get("loss_type"):
                    case.loss_type = result["loss_type"]
                if result.get("severity"):
                    case.severity_score = min(100, max(0, int(result["severity"])))
                if result.get("confidence"):
                    case.confidence_score = min(100, max(0, int(result["confidence"])))
                if result.get("region"):
                    case.region = result["region"]
                if result.get("tags"):
                    for tag in result["tags"][:5]:
                        existing = db.query(CaseTag).filter_by(case_id=case.id, tag=tag).first()
                        if not existing:
                            db.add(CaseTag(case_id=case.id, tag=tag))
                if result.get("critical_warning"):
                    case.critical_warning = result["critical_warning"]
                case.is_published = True
                case.updated_at = datetime.now(timezone.utc)
                classified += 1
            except Exception as e:
                logger.warning("classify case %d hatası: %s", case.id, e)
                errors += 1

        db.commit()
        logger.info("classify_pending: %d sınıflandırıldı, %d hata", classified, errors)

        # Kritik vakalar için alert task tetikle (hata durumunda sessiz devam)
        try:
            critical = [c for c in pending if c.severity_score >= 80 and c.is_published]
            if critical:
                for c in critical[:10]:
                    alert_critical.delay(c.id)
        except Exception:
            pass  # Broker yoksa sessizce geç

        return {"status": "success", "classified": classified, "errors": errors}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=120)
    finally:
        db.close()


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.prune_hotset")
def prune_hotset(self):
    """Gece hot-set pruning — soğuyan vakaları çıkar."""
    try:
        from .ingest import run_hotset_maintenance
        result = run_hotset_maintenance()
        logger.info("prune_hotset tamamlandı: %s", result)
        return result
    except Exception as exc:
        logger.error("prune_hotset hatası: %s", exc)
        raise self.retry(exc=exc, countdown=120)


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.alert_critical")
def alert_critical(self, case_id: int):
    """Kritik vaka için abone kullanıcılara webhook bildirimi gönder."""
    db = SessionLocal()
    try:
        case = db.query(VictimCase).get(case_id)
        if not case:
            return {"status": "not_found", "case_id": case_id}

        # Abone kullanıcıları bul
        subs = db.query(AlertSubscription).filter_by(is_active=True).all()
        if not subs:
            return {"status": "no_subscribers", "case_id": case_id}

        notified = 0
        for sub in subs:
            # Attack method filtresi
            if sub.attack_method and sub.attack_method != case.attack_method:
                continue
            # Region filtresi
            if sub.region and sub.region != case.region:
                continue

            # Webhook URL yoksa sadece DB kaydı
            # TODO: Gerçek webhook HTTP POST eklenecek
            notified += 1

        logger.info("alert_critical: case %d → %d kullanıcıya bildirildi", case_id, notified)
        return {"status": "success", "case_id": case_id, "notified": notified}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.weekly_digest")
def weekly_digest(self):
    """Pazartesi günü haftalık bülten üret — Gemini ile."""
    db = SessionLocal()
    try:
        from datetime import timedelta
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_cases = (
            db.query(VictimCase)
            .filter(VictimCase.last_seen >= week_ago, VictimCase.is_published == True)
            .order_by(VictimCase.severity_score.desc())
            .limit(20)
            .all()
        )

        cases_data = [
            {"title": c.case_title, "method": c.attack_method, "severity": c.severity_score}
            for c in recent_cases
        ]

        _, _, generate_digest, _ = _get_gemini_service()
        digest_text = generate_digest(cases_data)

        logger.info("weekly_digest üretildi (%d vaka)", len(cases_data))
        return {
            "status": "success",
            "total_cases": len(cases_data),
            "digest_preview": digest_text[:200] if digest_text else None,
        }
    except Exception as exc:
        logger.error("weekly_digest hatası: %s", exc)
        raise self.retry(exc=exc, countdown=300)
    finally:
        db.close()


@app.task(bind=True, max_retries=2, name="modules.victim_atlas.celery_tasks.generate_report_pdf")
def generate_report_pdf(self, report_id: int):
    """Kullanıcı raporu için PDF üret."""
    db = SessionLocal()
    try:
        report = db.query(UserReport).get(report_id)
        if not report:
            return {"status": "not_found", "report_id": report_id}

        # PDF çıktı dizini
        pdf_dir = Path(os.getenv("PDF_OUTPUT_DIR", "/tmp/aegis_reports"))
        pdf_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = pdf_dir / f"rapor_{report_id}.pdf"

        # TODO: Gerçek PDF üretimi (jspdf/weasyprint) — şimdilik stub
        # Basit text dosyası oluştur
        content = f"""AegisNexus Siber Güvenlik Raporu
================================

Tarih: {report.created_at or datetime.now(timezone.utc)}
Rapor ID: {report.id}

KULLANICI ANLATIMI:
{report.user_description}

KORUNMA PLANI:
{report.protection_plan or 'Henüz üretilmedi.'}

AI ANALİZİ:
{json.dumps(report.ai_analysis or {}, ensure_ascii=False, indent=2)}
"""
        pdf_path.write_text(content, encoding="utf-8")

        # DB'de yol güncelle
        report.pdf_path = str(pdf_path)
        db.commit()

        logger.info("PDF üretildi: %s", pdf_path)
        return {"status": "success", "report_id": report_id, "pdf_path": str(pdf_path)}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


@app.task(bind=True, max_retries=1, name="modules.victim_atlas.celery_tasks.enrich_cases")
def enrich_cases(self, limit: int = 500):
    """Mevcut vakaları zenginleştir (Gemini ile tekrar sınıflandır)."""
    db = SessionLocal()
    try:
        cases = (
            db.query(VictimCase)
            .filter_by(is_published=True)
            .order_by(VictimCase.updated_at.asc())
            .limit(limit)
            .all()
        )

        classify_case, *_ = _get_gemini_service()
        enriched = 0

        for case in cases:
            try:
                result = classify_case(case.narrative_summary or "")
                if result.get("tags"):
                    for tag in result["tags"][:5]:
                        existing = db.query(CaseTag).filter_by(case_id=case.id, tag=tag).first()
                        if not existing:
                            db.add(CaseTag(case_id=case.id, tag=tag))
                if result.get("region") and not case.region:
                    case.region = result["region"]
                case.updated_at = datetime.now(timezone.utc)
                enriched += 1
            except Exception:
                continue

        db.commit()
        return {"status": "success", "enriched": enriched}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=120)
    finally:
        db.close()


@app.task(bind=True, name="modules.victim_atlas.celery_tasks.update_fraud_profile_stats")
def update_fraud_profile_stats(self):
    """Her fraud profili için Victim Atlas'tan case_count ve avg_loss_try güncelle."""
    from sqlalchemy import func as sqlfunc
    from app.models import FraudProfile, VictimCase
    from .fraud_profile_matcher import seed_profiles

    db = SessionLocal()
    try:
        profiles = db.query(FraudProfile).all()
        if not profiles:
            seed_profiles(db)
            profiles = db.query(FraudProfile).all()

        updated = 0
        for profile in profiles:
            if not profile.attack_method:
                continue
            row = (
                db.query(sqlfunc.count(VictimCase.id))
                .filter(VictimCase.attack_method == profile.attack_method)
                .scalar()
            )
            profile.case_count = row or 0
            updated += 1

        db.commit()
        logger.info("[FraudProfile] %d profil istatistik güncellendi", updated)
        return {"status": "ok", "updated": updated}
    except Exception as exc:
        db.rollback()
        logger.error("[FraudProfile] Stat güncelleme hatası: %s", exc)
        raise
    finally:
        db.close()
