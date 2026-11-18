"""AI analyzer use cases: hybrid message analysis, URL checks and per-user history.

``analyze()`` runs the advanced hybrid detector (primary score) and the legacy
engine (context, recommendations), then reconciles the legacy report so every
field reflects the primary verdict.
"""
from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.errors import NotFound
from app.models import APIKey, URLAnalizHistory

from .advanced_phishing_detector import detect_phishing
from .email_parser import parse_email
from .engine import AIAnalyzerEngine

logger = logging.getLogger(__name__)

MODULE = '07_ai_analyzer'
_URL = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

# verdict → (risk_level, safety_status, action_required, threat_level)
VERDICTS: dict[str, tuple[str, str, str, str]] = {
    'PHİSHİNG': ('critical', 'TEHLİKELİ', 'ACİL', 'critical'),
    'ŞÜPHELİ': ('high', 'ŞÜPHELİ', 'DİKKAT', 'high'),
    'DÜŞÜK RİSK': ('medium', 'ŞÜPHELİ', 'DİKKAT', 'medium'),
    'TEMİZ': ('low', 'GÜVENLİ', 'YOK', 'low'),
}


def _email_payload(parsed) -> dict[str, Any]:
    return {
        'from_address': parsed.from_address, 'from_domain': parsed.from_domain, 'display_name': parsed.display_name,
        'to': parsed.to, 'reply_to': parsed.reply_to, 'cc': parsed.cc, 'subject': parsed.subject, 'date': parsed.date,
        'urls': parsed.urls, 'attachments': parsed.attachments,
        'email_signals': parsed.email_signals, 'email_evidence': parsed.email_evidence,
    }


def _risk_level(score: int) -> str:
    if score >= 70:
        return 'high'
    if score >= 40:
        return 'medium'
    return 'low' if score > 0 else 'safe'


def record_url_analysis(db: Session, api_key: APIKey | None, result: dict[str, Any]) -> None:
    """Store a URL check in the caller's private history (anonymous calls are not stored)."""
    if not isinstance(api_key, APIKey) or not result.get('url'):
        return
    url = str(result['url'])[:2000]
    score = int(result.get('risk_score', 0))
    db.add(URLAnalizHistory(
        user_id=api_key.user_id, url=url, domain=(urlparse(url).hostname or '').lower().rstrip('.')[:512],
        risk_level=_risk_level(score), is_phishing=not result.get('is_safe', True), confidence=score / 100.0,
        analysis_result=result, url_checks=result.get('checks', []),
    ))
    db.commit()


def analyze(engine: AIAnalyzerEngine, *, message: str, message_type: str, context: str | None,
            sender: str | None, subject: str | None) -> dict[str, Any]:
    parsed = parse_email(message) if message_type == 'email' else None
    text = (parsed.body_text or message) if parsed else message
    urls = _URL.findall(text)
    url = urls[0] if urls else None

    advanced = detect_phishing(text, url, email_signals=parsed.email_signals if parsed else None)
    report = engine.analyze_message(
        message=text,
        context=context or message_type,
        sender=(parsed.display_name or parsed.from_address) if parsed else sender,
        subject=parsed.subject if parsed else subject,
    )

    verdict = advanced['verdict']
    score = advanced['score'] * 100
    confidence = advanced['confidence']
    risk_level, safety_status, action_required, threat_level = VERDICTS.get(verdict, VERDICTS['DÜŞÜK RİSK'])
    is_phishing = verdict == 'PHİSHİNG'

    report['security_assessment'].update(
        risk_level=risk_level, score=round(score, 2), is_phishing=is_phishing, is_scam=is_phishing,
        confidence=round(confidence, 2), safety_status=safety_status, action_required=action_required,
        threat_level=threat_level,
    )
    detailed = report['detailed_analysis']
    detailed.update(
        advanced_breakdown=advanced['breakdown'], hard_override=advanced['hard_override'],
        matched_categories=advanced.get('matched_categories', []), signal_evidence=advanced.get('evidence', []),
    )
    detailed['ai_analysis'].update(
        is_phishing=is_phishing, is_scam=is_phishing, threat_level=threat_level,
        confidence_score=int(round(confidence * 100)), analysis_method='groq_hybrid',
    )

    evidence = list(advanced.get('evidence', []))
    if parsed:
        payload = _email_payload(parsed)
        report['parsed_email'] = detailed['parsed_email'] = payload
        report['email_signals'] = detailed['email_signals'] = parsed.email_signals
        evidence.extend(parsed.email_evidence)
    report['evidence'] = evidence
    report['matched_categories'] = advanced.get('matched_categories', [])
    report['analysis_mode'] = message_type
    report['summary'] = (f"[{verdict}] {advanced['reason']} "
                         f"(Skor: {advanced['score']:.2f}, Güven: {advanced['confidence']:.2f})")

    if is_phishing and url:
        try:
            from modules.shared.events import publish
            publish('url.phishing_confirmed', {'url': url, 'score': round(score, 2), 'source': 'ai_analyzer',
                                               'created_at': datetime.now(UTC).isoformat()}, durable=True)
        except Exception:
            logger.warning('Publishing url.phishing_confirmed failed (non-critical)', exc_info=True)
    logger.info('Advanced analysis completed: %s (score %.1f)', verdict, score)
    return report


def analyze_with_fallback(engine: AIAnalyzerEngine, **kwargs: Any) -> dict[str, Any]:
    """The legacy engine alone still gives a useful answer if the hybrid path fails."""
    try:
        return analyze(engine, **kwargs)
    except Exception:
        logger.exception('Hybrid analysis failed; falling back to the legacy engine')
        return engine.analyze_message(message=kwargs['message'], context=kwargs.get('context') or 'email',
                                      sender=kwargs.get('sender'), subject=kwargs.get('subject'))


def history(db: Session, api_key: APIKey, limit: int) -> dict[str, Any]:
    rows = (db.query(URLAnalizHistory).filter(URLAnalizHistory.user_id == api_key.user_id)
            .order_by(URLAnalizHistory.created_at.desc()).limit(limit).all())
    return {'data': [{
        'id': h.id, 'url': h.url, 'domain': h.domain, 'risk_level': h.risk_level, 'is_phishing': h.is_phishing,
        'confidence': h.confidence, 'created_at': h.created_at.isoformat() if h.created_at else None,
    } for h in rows], 'total': len(rows), 'module': MODULE}


def history_detail(db: Session, api_key: APIKey, history_id: int) -> dict[str, Any]:
    h = db.query(URLAnalizHistory).filter(URLAnalizHistory.id == history_id,
                                          URLAnalizHistory.user_id == api_key.user_id).first()
    if h is None:
        raise NotFound('Analiz bulunamadı')
    return {'id': h.id, 'url': h.url, 'domain': h.domain, 'risk_level': h.risk_level, 'is_phishing': h.is_phishing,
            'confidence': h.confidence, 'analysis_result': h.analysis_result, 'llm_analysis': h.llm_analysis,
            'url_checks': h.url_checks, 'created_at': h.created_at.isoformat() if h.created_at else None,
            'module': MODULE}
