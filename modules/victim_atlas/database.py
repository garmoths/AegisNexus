import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import (
    IngestRun,
    RawDocument,
    SourceRegistry,
    VictimCase,
    VictimCaseEvidence,
)

logger = logging.getLogger(__name__)

ATTACK_METHOD_TR = {
    "phishing": "Oltalama",
    "smishing": "SMS Oltalaması",
    "vishing": "Telefon Dolandırıcılığı",
    "social_engineering": "Sosyal Mühendislik",
    "malware_assisted": "Zararlı Yazılım Destekli Saldırı",
    "sahte_mobil_uygulama": "Sahte Mobil Uygulama Tuzağı",
    "banka_taklit": "Banka Taklidi Senaryosu",
}

LOSS_TYPE_TR = {
    "bank_account": "Banka Hesabı Mağduriyeti",
    "social_media": "Sosyal Medya Hesap Mağduriyeti",
    "ecommerce": "E-Ticaret Mağduriyeti",
    "corporate_account": "Kurumsal Hesap Mağduriyeti",
    "crypto_wallet": "Kripto Cüzdan Mağduriyeti",
    "device_compromise": "Cihaz Ele Geçirme Mağduriyeti",
}

PLATFORM_TR = {
    "banking": "Bankacılık",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "telegram": "Telegram",
    "microsoft365": "Microsoft 365",
    "ecommerce": "E-Ticaret",
    "crypto": "Kripto",
    "sikayet_platformu": "Şikayet Platformu",
    "general": "Genel",
}


def _attack_method_tr(value: Optional[str]) -> str:
    return ATTACK_METHOD_TR.get(value or "", value or "Bilinmiyor")


def _loss_type_tr(value: Optional[str]) -> str:
    return LOSS_TYPE_TR.get(value or "", value or "Bilinmiyor")


def _platform_tr(value: Optional[str]) -> str:
    return PLATFORM_TR.get(value or "", value or "Genel")


def _session() -> Session:
    return SessionLocal()


def ensure_initialized() -> None:
    """Tablolar Alembic ile yönetilir, burada no-op."""
    pass


def upsert_source(name: str, base_url: str, trust_tier: str, enabled: bool = True) -> int:
    ensure_initialized()
    with _session() as db:
        src = db.query(SourceRegistry).filter_by(name=name).first()
        if src:
            src.base_url = base_url
            src.trust_tier = trust_tier
            src.enabled = enabled
            src.updated_at = datetime.now(timezone.utc)
        else:
            src = SourceRegistry(name=name, base_url=base_url, trust_tier=trust_tier, enabled=enabled)
            db.add(src)
        db.commit()
        return src.id


def sync_source_registry(sources: List[Dict[str, Any]]) -> Dict[str, int]:
    ensure_initialized()
    with _session() as db:
        existing = {row.name: row for row in db.query(SourceRegistry).all()}
        configured_names = {str(item.get("name") or "") for item in sources if item.get("name")}

        upserted = 0
        disabled = 0

        for item in sources:
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            row = existing.get(name)
            if row:
                row.base_url = str(item.get("base_url") or row.base_url)
                row.trust_tier = str(item.get("trust_tier") or row.trust_tier)
                row.enabled = bool(item.get("enabled", True))
                row.updated_at = datetime.now(timezone.utc)
            else:
                row = SourceRegistry(
                    name=name,
                    base_url=str(item.get("base_url") or ""),
                    trust_tier=str(item.get("trust_tier") or "tier2"),
                    enabled=bool(item.get("enabled", True)),
                )
                db.add(row)
            upserted += 1

        for name, row in existing.items():
            if name not in configured_names and row.enabled:
                row.enabled = False
                row.updated_at = datetime.now(timezone.utc)
                disabled += 1

        db.commit()
        return {"upserted": upserted, "disabled": disabled}


def mark_source_success(source_id: int) -> None:
    with _session() as db:
        src = db.query(SourceRegistry).get(source_id)
        if src:
            src.last_success_at = datetime.now(timezone.utc)
            src.last_error = None
            src.updated_at = datetime.now(timezone.utc)
            db.commit()


def mark_source_error(source_id: int, message: str) -> None:
    with _session() as db:
        src = db.query(SourceRegistry).get(source_id)
        if src:
            src.last_error = message[:500]
            src.updated_at = datetime.now(timezone.utc)
            db.commit()


def start_ingest_run() -> int:
    ensure_initialized()
    with _session() as db:
        run = IngestRun(started_at=datetime.now(timezone.utc), status="running")
        db.add(run)
        db.commit()
        return run.id


def finish_ingest_run(
    run_id: int,
    status: str,
    documents_fetched: int,
    cases_created: int,
    cases_updated: int,
    errors: Dict[str, Any],
) -> None:
    with _session() as db:
        run = db.query(IngestRun).get(run_id)
        if run:
            run.finished_at = datetime.now(timezone.utc)
            run.status = status
            run.documents_fetched = int(documents_fetched)
            run.cases_created = int(cases_created)
            run.cases_updated = int(cases_updated)
            run.errors_json = errors
            db.commit()


def upsert_raw_document(
    source_id: int,
    external_id: str,
    url: str,
    title: str,
    published_at: Optional[str],
    raw_text: str,
    lang: str,
    doc_hash: str,
) -> Tuple[Optional[int], bool]:
    ensure_initialized()
    with _session() as db:
        existing = (
            db.query(RawDocument)
            .filter_by(source_id=source_id, external_id=external_id)
            .first()
        )
        if existing:
            return existing.id, False
        existing = db.query(RawDocument).filter_by(hash=doc_hash).first()
        if existing:
            return existing.id, False
        pub_dt = None
        if published_at:
            try:
                pub_dt = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                pass
        doc = RawDocument(
            source_id=source_id,
            external_id=external_id,
            url=url,
            title=title,
            published_at=pub_dt,
            raw_text=raw_text,
            lang=lang,
            hash=doc_hash,
        )
        db.add(doc)
        db.commit()
        return doc.id, True


def upsert_case(case: Dict[str, Any]) -> Tuple[int, bool]:
    ensure_initialized()
    with _session() as db:
        existing = db.query(VictimCase).filter_by(case_slug=case["case_slug"]).first()
        if existing:
            existing.case_title = case["case_title"]
            existing.incident_period_start = _parse_dt(case.get("incident_period_start"))
            existing.incident_period_end = _parse_dt(case.get("incident_period_end"))
            existing.attack_method = case["attack_method"]
            existing.loss_type = case["loss_type"]
            existing.target_platform = case["target_platform"]
            existing.critical_warning = case["critical_warning"]
            existing.narrative_summary = case["narrative_summary"]
            existing.defense_steps_json = case["defense_steps"]
            existing.confidence_score = int(case["confidence_score"])
            existing.severity_score = int(case["severity_score"])
            if case.get("region"):
                existing.region = case.get("region")
            existing.last_seen = _parse_dt(case["last_seen"]) or datetime.now(timezone.utc)
            existing.updated_at = datetime.now(timezone.utc)
            db.commit()
            return existing.id, False

        new_case = VictimCase(
            case_slug=case["case_slug"],
            case_title=case["case_title"],
            incident_period_start=_parse_dt(case.get("incident_period_start")),
            incident_period_end=_parse_dt(case.get("incident_period_end")),
            attack_method=case["attack_method"],
            loss_type=case["loss_type"],
            target_platform=case["target_platform"],
            critical_warning=case["critical_warning"],
            narrative_summary=case["narrative_summary"],
            defense_steps_json=case["defense_steps"],
            confidence_score=int(case["confidence_score"]),
            severity_score=int(case["severity_score"]),
            region=case.get("region"),
            first_seen=_parse_dt(case["first_seen"]) or datetime.now(timezone.utc),
            last_seen=_parse_dt(case["last_seen"]) or datetime.now(timezone.utc),
            is_hot=True,
        )
        db.add(new_case)
        db.commit()
        return new_case.id, True


def _case_tokens(value: str) -> set[str]:
    normalized = (value or "").lower()
    normalized = normalized.translate(str.maketrans("çğıöşü", "cgiosu"))
    tokens = set(re.findall(r"[a-z0-9]{4,}", normalized))
    return tokens - {"haber", "son", "dakika", "turkiye", "dolandiricilik", "dolandirici", "magduriyet"}


def find_similar_case_id(case: Dict[str, Any], threshold: float = 0.72) -> Optional[int]:
    tokens = _case_tokens(case.get("case_title", ""))
    if len(tokens) < 3:
        return None
    with _session() as db:
        rows = (
            db.query(VictimCase)
            .filter(
                VictimCase.attack_method == case.get("attack_method"),
                VictimCase.loss_type == case.get("loss_type"),
            )
            .order_by(VictimCase.last_seen.desc())
            .limit(300)
            .all()
        )
        for row in rows:
            other = _case_tokens(row.case_title)
            if len(other) < 3:
                continue
            union = tokens | other
            if not union:
                continue
            score = len(tokens & other) / len(union)
            if score >= threshold:
                row.last_seen = _parse_dt(case.get("last_seen")) or datetime.now(timezone.utc)
                row.updated_at = datetime.now(timezone.utc)
                row.confidence_score = max(int(row.confidence_score or 0), int(case.get("confidence_score") or 0))
                row.severity_score = max(int(row.severity_score or 0), int(case.get("severity_score") or 0))
                if case.get("region") and not row.region:
                    row.region = case.get("region")
                db.commit()
                return row.id
    return None


def add_case_evidence(case_id: int, raw_document_id: int, snippet: str, evidence_weight: float = 1.0) -> None:
    with _session() as db:
        existing = (
            db.query(VictimCaseEvidence)
            .filter_by(case_id=case_id, raw_document_id=raw_document_id)
            .first()
        )
        if existing:
            return
        ev = VictimCaseEvidence(
            case_id=case_id,
            raw_document_id=raw_document_id,
            evidence_snippet=snippet[:500],
            evidence_weight=float(evidence_weight),
        )
        db.add(ev)
        db.commit()


def prune_hot_set(limit: int = 1000) -> Dict[str, int]:
    ensure_initialized()
    safe_limit = max(1, int(limit))
    with _session() as db:
        db.query(VictimCase).update({VictimCase.is_hot: False})
        top_ids = (
            db.query(VictimCase.id)
            .order_by(VictimCase.confidence_score.desc(), VictimCase.severity_score.desc(), VictimCase.last_seen.desc())
            .limit(safe_limit)
            .subquery()
        )
        db.query(VictimCase).filter(VictimCase.id.in_(top_ids)).update({VictimCase.is_hot: True}, synchronize_session="fetch")
        db.commit()
        hot = db.query(func.count(VictimCase.id)).filter_by(is_hot=True).scalar()
        total = db.query(func.count(VictimCase.id)).scalar()
        return {"hot_count": int(hot), "total_cases": int(total)}


def get_cases(
    page: int = 1,
    limit: int = 20,
    attack_method: Optional[str] = None,
    loss_type: Optional[str] = None,
    severity_min: int = 0,
    confidence_min: int = 60,
    q: Optional[str] = None,
    hot_set_only: bool = True,
) -> Dict[str, Any]:
    ensure_initialized()
    page = max(1, int(page))
    limit = max(1, min(int(limit), 100))
    offset = (page - 1) * limit

    with _session() as db:
        query = db.query(VictimCase).filter(
            VictimCase.confidence_score >= int(confidence_min),
            VictimCase.severity_score >= int(severity_min),
        )
        if hot_set_only:
            query = query.filter_by(is_hot=True)
        if attack_method:
            query = query.filter_by(attack_method=attack_method)
        if loss_type:
            query = query.filter_by(loss_type=loss_type)
        if q:
            pattern = f"%{q.strip()}%"
            query = query.filter(
                or_(
                    VictimCase.case_title.ilike(pattern),
                    VictimCase.narrative_summary.ilike(pattern),
                    VictimCase.critical_warning.ilike(pattern),
                )
            )

        total = query.count()
        rows = (
            query.order_by(
                VictimCase.last_seen.desc(),
                VictimCase.confidence_score.desc(),
                VictimCase.severity_score.desc(),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

    data = []
    for row in rows:
        data.append({
            "id": row.id,
            "case_slug": row.case_slug,
            "case_title": row.case_title,
            "incident_period_start": row.incident_period_start.isoformat() if row.incident_period_start else None,
            "incident_period_end": row.incident_period_end.isoformat() if row.incident_period_end else None,
            "attack_method": row.attack_method,
            "attack_method_tr": _attack_method_tr(row.attack_method),
            "loss_type": row.loss_type,
            "loss_type_tr": _loss_type_tr(row.loss_type),
            "target_platform": row.target_platform,
            "target_platform_tr": _platform_tr(row.target_platform),
            "critical_warning": row.critical_warning,
            "confidence_score": row.confidence_score,
            "severity_score": row.severity_score,
            "region": row.region,
            "first_seen": row.first_seen.isoformat() if row.first_seen else None,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        })
    total_pages = (int(total) + limit - 1) // limit if total else 0
    return {
        "data": data,
        "page": page,
        "limit": limit,
        "total": int(total),
        "total_pages": total_pages,
    }


def get_case(case_id: int) -> Optional[Dict[str, Any]]:
    ensure_initialized()
    with _session() as db:
        case = db.query(VictimCase).get(int(case_id))
        if not case:
            return None

        evidence_rows = (
            db.query(VictimCaseEvidence, RawDocument)
            .join(RawDocument, RawDocument.id == VictimCaseEvidence.raw_document_id)
            .filter(VictimCaseEvidence.case_id == int(case_id))
            .order_by(VictimCaseEvidence.id.desc())
            .limit(10)
            .all()
        )

        payload = {
            "id": case.id,
            "case_slug": case.case_slug,
            "case_title": case.case_title,
            "incident_period_start": case.incident_period_start.isoformat() if case.incident_period_start else None,
            "incident_period_end": case.incident_period_end.isoformat() if case.incident_period_end else None,
            "attack_method": case.attack_method,
            "attack_method_tr": _attack_method_tr(case.attack_method),
            "loss_type": case.loss_type,
            "loss_type_tr": _loss_type_tr(case.loss_type),
            "target_platform": case.target_platform,
            "target_platform_tr": _platform_tr(case.target_platform),
            "critical_warning": case.critical_warning,
            "narrative_summary": case.narrative_summary,
            "defense_steps": case.defense_steps_json if isinstance(case.defense_steps_json, list) else json.loads(case.defense_steps_json or "[]"),
            "confidence_score": case.confidence_score,
            "severity_score": case.severity_score,
            "region": case.region,
            "first_seen": case.first_seen.isoformat() if case.first_seen else None,
            "last_seen": case.last_seen.isoformat() if case.last_seen else None,
        }
        payload["evidence"] = [
            {
                "url": doc.url,
                "title": doc.title,
                "published_at": doc.published_at.isoformat() if doc.published_at else None,
                "evidence_snippet": ev.evidence_snippet,
                "evidence_weight": ev.evidence_weight,
            }
            for ev, doc in evidence_rows
        ]
        return payload


def get_stats() -> Dict[str, Any]:
    ensure_initialized()
    with _session() as db:
        total_cases = db.query(func.count(VictimCase.id)).scalar()
        hot_cases = db.query(func.count(VictimCase.id)).filter_by(is_hot=True).scalar()
        high_conf = db.query(func.count(VictimCase.id)).filter(VictimCase.confidence_score >= 80).scalar()

        by_method = (
            db.query(VictimCase.attack_method, func.count(VictimCase.id).label("c"))
            .group_by(VictimCase.attack_method)
            .order_by(func.count(VictimCase.id).desc())
            .all()
        )
        by_loss = (
            db.query(VictimCase.loss_type, func.count(VictimCase.id).label("c"))
            .group_by(VictimCase.loss_type)
            .order_by(func.count(VictimCase.id).desc())
            .all()
        )

    return {
        "total_cases": int(total_cases),
        "hot_cases": int(hot_cases),
        "high_confidence_cases": int(high_conf),
        "attack_method_distribution": {r.attack_method: int(r.c) for r in by_method},
        "loss_type_distribution": {r.loss_type: int(r.c) for r in by_loss},
    }


def get_ingest_health() -> Dict[str, Any]:
    ensure_initialized()
    with _session() as db:
        last_run = db.query(IngestRun).order_by(IngestRun.id.desc()).first()
        sources = db.query(SourceRegistry).order_by(SourceRegistry.name.asc()).all()

    run_payload = None
    if last_run:
        raw_errors = dict(last_run.errors_json or {})
        filter_stats = raw_errors.pop("__filter_stats__", None)
        run_payload = {
            "id": last_run.id,
            "started_at": last_run.started_at.isoformat() if last_run.started_at else None,
            "finished_at": last_run.finished_at.isoformat() if last_run.finished_at else None,
            "status": last_run.status,
            "documents_fetched": last_run.documents_fetched,
            "cases_created": last_run.cases_created,
            "cases_updated": last_run.cases_updated,
            "errors": raw_errors,
            "filter_stats": filter_stats or {},
        }
    return {
        "last_run": run_payload,
        "sources": [
            {
                "name": s.name,
                "trust_tier": s.trust_tier,
                "enabled": s.enabled,
                "last_success_at": s.last_success_at.isoformat() if s.last_success_at else None,
                "last_error": s.last_error,
            }
            for s in sources
        ],
    }


# =========================================================
# HELPER
# =========================================================


def _parse_dt(value: Optional[str]) -> Optional[datetime]:
    """ISO format string → datetime. None/bad values → None."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None
