"""Durable candidate lifecycle. A scanner result cannot publish itself as a threat."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid

from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from app.models import CrawlCandidate, CrawlObservation, CrawlReview, CrawlSettings, PhishingURL
from app.discovery.analysis import canonical_url, display_url, extract, assess


def now():
    # Existing SQLite/DateTime columns are UTC-naive; keep the persisted contract.
    return datetime.now(timezone.utc).replace(tzinfo=None)


def settings(db):
    row = db.get(CrawlSettings, 1)
    if row is None:
        row = CrawlSettings(id=1)
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
        row = db.get(CrawlSettings, 1)
    return row


def excluded(host, config):
    return any(host == domain or host.endswith('.' + domain) for domain in config.excluded_hosts)


def enqueue(db, url, *, source='manual', reason='Kullanıcı tarafından eklendi', depth=0, root_id=None, suggested=False):
    url, host, digest = canonical_url(url)
    if excluded(host, settings(db)):
        raise ValueError('Alan adı hariç tutma listesinde.')
    existing = db.query(CrawlCandidate).filter_by(url_hash=digest).first()
    if existing:
        return existing, False
    if db.query(CrawlCandidate).filter(CrawlCandidate.state.in_(['pending', 'retry', 'running', 'suggested'])).count() >= 10000:
        raise ValueError('Aday kuyruğu sınırına ulaşıldı.')
    row = CrawlCandidate(url=url, url_hash=digest, host=host, source=source[:120], reason=reason[:500],
                         depth=depth, root_id=root_id, state='suggested' if suggested else 'pending')
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = db.query(CrawlCandidate).filter_by(url_hash=digest).one()
        return row, False
    return row, True


def claim(db):
    moment = now()
    eligible = or_(CrawlCandidate.state.in_(['pending', 'retry']),
                   (CrawlCandidate.state == 'running') & (CrawlCandidate.lease_until < moment))
    # A killed last attempt must become visible as failed, never remain running forever.
    db.query(CrawlCandidate).filter(CrawlCandidate.state == 'running', CrawlCandidate.lease_until < moment,
                                    CrawlCandidate.attempts >= 3).update({'state': 'failed', 'last_error': 'worker_timeout'})
    db.commit()
    ids = [row.id for row in db.query(CrawlCandidate).filter(eligible, CrawlCandidate.attempts < 3,
            or_(CrawlCandidate.next_attempt_at.is_(None), CrawlCandidate.next_attempt_at <= moment)).order_by(CrawlCandidate.id).limit(30)]
    for candidate_id in ids:
        token = uuid.uuid4().hex
        updated = db.query(CrawlCandidate).filter(CrawlCandidate.id == candidate_id, eligible,
                CrawlCandidate.attempts < 3).update({'state': 'running', 'lease_token': token,
                    'lease_until': moment + timedelta(minutes=10), 'attempts': CrawlCandidate.attempts + 1,
                    'updated_at': moment}, synchronize_session=False)
        db.commit()
        if updated:
            db.expire_all()
            return db.get(CrawlCandidate, candidate_id), token
    return None, None


def artifacts():
    root = Path(os.getenv('CRAWLER_DATA_DIR', str(Path(__file__).resolve().parents[2] / 'data/crawler')))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def save_html(html):
    digest = hashlib.sha256(html.encode()).hexdigest()
    name = digest + '.html'
    path = artifacts() / name
    if not path.exists():
        path.write_text(html, encoding='utf-8')
        path.chmod(0o600)
    return name


def finish(db, candidate_id, token, *, url, html, status, live=True, truncated=False, rendered=False, screenshot=None, extra=None):
    features = extract(html, url)
    if extra:
        features.update(extra)
    assessment = assess(features, http_status=status, truncated=truncated, rendered=rendered, live=live)
    # All observations remain evidence even when low-scoring; they are not threat rows.
    observation = CrawlObservation(candidate_id=candidate_id, attempt_token=token, final_url=url, http_status=status,
            live=live, truncated=truncated, content_hash=features['content_hash'], html_path=save_html(html),
            screenshot_path=screenshot, features=features, assessment=assessment)
    changed = db.query(CrawlCandidate).filter_by(id=candidate_id, lease_token=token, state='running').update({
        'state': 'review', 'risk': assessment['risk'], 'coverage': assessment['coverage'], 'last_error': None,
        'lease_token': None, 'lease_until': None, 'updated_at': now()}, synchronize_session=False)
    if not changed:
        db.rollback()
        return None
    db.add(observation)
    db.commit()
    return observation


def failure(db, candidate_id, token, error, *, retry=True, defer=False):
    row = db.get(CrawlCandidate, candidate_id)
    if not row or row.lease_token != token or row.state != 'running':
        return
    can_retry = retry and (row.attempts < 3 or defer)
    changes = {
        'state': 'retry' if can_retry else 'blocked' if not retry else 'failed',
        'last_error': error,
        'next_attempt_at': now() + timedelta(seconds=60 * 2 ** min(row.attempts, 5)) if can_retry else None,
        'lease_token': None, 'lease_until': None, 'updated_at': now(),
    }
    if defer:
        changes['attempts'] = max(0, row.attempts - 1)
    db.query(CrawlCandidate).filter_by(id=candidate_id, lease_token=token, state='running').update(
        changes, synchronize_session=False)
    db.commit()



def invalidate_verdict(url):
    from app import runtime_store
    from modules.phishing_detector.url_normalize import normalize_url_record
    normalized = normalize_url_record(url)
    runtime_store.delete('scan:' + normalized['url_hash'])
    # Invalidate reusable verdicts, retaining the scan event audit history.
    from modules.phishing_detector.cache_db import get_db_connection, init_database
    init_database()
    with get_db_connection() as connection:
        connection.execute('DELETE FROM scan_results WHERE url IN (?, ?)', (url, normalized['canonical_url']))
        connection.commit()


def withdraw_publication(db, candidate_id):
    owned = db.query(PhishingURL).filter_by(phish_id='CRAWL-' + str(candidate_id)).first()
    if owned is not None:
        db.delete(owned)


def requeue(db, row, actor):
    if row.state == 'running':
        raise ValueError('Devam eden tarama yeniden kuyruğa alınamaz.')
    if excluded(row.host, settings(db)):
        raise ValueError('Alan adı hariç tutma listesinde.')
    withdraw_publication(db, row.id)
    row.state, row.attempts, row.next_attempt_at, row.last_error = 'pending', 0, None, None
    row.lease_token = row.lease_until = None
    row.risk, row.coverage = None, 'unknown'
    row.updated_at = now()
    db.add(CrawlReview(candidate_id=row.id, decision='requeue', note='Yeniden tarama istendi', actor=actor))
    db.commit()
    invalidate_verdict(row.url)


def review(db, row, decision, note, actor, observation_id):
    latest = db.query(CrawlObservation).filter_by(candidate_id=row.id).order_by(CrawlObservation.id.desc()).first()
    if row.state not in ('review', 'confirmed', 'dismissed') or latest is None or latest.id != observation_id:
        raise ValueError('Son gözlemi yenileyin; bu kayıt şu anda incelemeye uygun değil.')
    if decision == 'confirmed' and (not latest.live or latest.truncated or latest.http_status < 200 or latest.http_status >= 300
                                  or latest.assessment['coverage'] == 'unknown' or latest.fetched_at < now() - timedelta(hours=48)):
        raise ValueError('Onay için son 48 saatte alınmış, tam ve başarılı canlı gözlem gerekli.')
    expected = row.state
    # A fresh worker or concurrent decision must not be overwritten by a stale UI.
    changed = db.query(CrawlCandidate).filter_by(id=row.id, state=expected, updated_at=row.updated_at).update({
        'state': decision, 'updated_at': now()}, synchronize_session=False)
    if not changed:
        db.rollback()
        raise ValueError('Kayıt değişti; yeniden yükleyin.')
    phish_id = 'CRAWL-' + str(row.id)
    owned = db.query(PhishingURL).filter_by(phish_id=phish_id).first()
    if decision == 'confirmed':
        # Use the legacy canonical identity so quick checks see exactly this URL.
        from modules.phishing_detector.url_normalize import normalize_url_record
        normalized = normalize_url_record(row.url)
        existing = db.query(PhishingURL).filter_by(url_hash=normalized['url_hash']).first()
        if owned is None and existing is None:
            db.add(PhishingURL(phish_id=phish_id, url=normalized['canonical_url'], url_hash=normalized['url_hash'],
                    domain_norm=normalized['domain_norm'], status='verified', online=True,
                    target=', '.join(latest.features.get('brands', [])) or 'Unknown'))
    elif owned is not None:
        # Withdraw only our publication; never delete independently imported evidence.
        db.delete(owned)
    db.add(CrawlReview(candidate_id=row.id, observation_id=latest.id, decision=decision, note=note, actor=actor))
    db.commit()
    # Legacy scanners cache a final verdict; invalidate it after approval/withdrawal.
    invalidate_verdict(row.url)


def serialize(row):
    return {'id': row.id, 'url': display_url(row.url), 'host': row.host, 'source': row.source, 'reason': row.reason,
            'state': row.state, 'risk': row.risk, 'coverage': row.coverage, 'attempts': row.attempts,
            'depth': row.depth, 'last_error': row.last_error, 'created_at': row.created_at,
            'updated_at': row.updated_at, 'next_attempt_at': row.next_attempt_at}


def public_features(features):
    return {**features, 'redirects': [display_url(url) for url in features.get('redirects', [])],
            'links': [display_url(url) for url in features.get('links', [])],
            'favicon_url': display_url(features['favicon_url']) if features.get('favicon_url') else None}
