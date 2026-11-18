"""Operator-only discovery API. Raw captured HTML is never served as active content."""
from typing import Literal
from pathlib import Path
from datetime import timedelta
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.auth import require_admin
from app.database import get_db
from app.models import CrawlCandidate, CrawlObservation, CrawlReview, CrawlSource
from app.discovery import service
from app.discovery.analysis import canonical_url, display_url


def operator(key=Depends(require_admin)):
    return f'user:{key.user_id}'


router = APIRouter(prefix='/api/v2/crawler', tags=['crawler'], dependencies=[Depends(operator)])


class Seeds(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=100)


class ConfigPatch(BaseModel):
    enabled: bool
    browser_enabled: bool = False
    daily_limit: int = Field(default=1000, ge=1, le=10000)
    browser_limit: int = Field(default=100, ge=0, le=500)
    excluded_hosts: list[str] = Field(default_factory=list, max_length=100)


class ReviewBody(BaseModel):
    decision: Literal['confirmed', 'dismissed']
    observation_id: int
    note: str = Field(min_length=5, max_length=2000)


class SourceBody(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    url: str = Field(default='', max_length=4096)
    kind: Literal['url_list', 'ct_json', 'certstream'] = 'url_list'


class Snapshot(BaseModel):
    url: str = Field(max_length=4096)
    html: str = Field(min_length=1, max_length=1_000_000)


def require_candidate(db, candidate_id):
    row = db.get(CrawlCandidate, candidate_id)
    if row is None:
        raise HTTPException(404, 'Aday bulunamadı.')
    return row


def config_json(row):
    return {key: getattr(row, key) for key in ('enabled', 'browser_enabled', 'daily_limit', 'browser_limit', 'excluded_hosts')}


@router.get('/overview')
def overview(response: Response, db: Session = Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    from app import runtime_store as store
    day = service.now().strftime('%Y-%m-%d')
    return {'settings': config_json(service.settings(db)),
            'counts': dict(db.query(CrawlCandidate.state, func.count(CrawlCandidate.id)).group_by(CrawlCandidate.state).all()),
            'today_crawled': store.get('crawler:daily:' + day, 0),
            'today_browser': store.get('crawler:browser:' + day, 0),
            'worker': store.get('crawler:heartbeat'),
            'certstream': store.get('crawler:certstream:state'), 'mode': 'operator'}


@router.patch('/settings')
def update_settings(body: ConfigPatch, db: Session = Depends(get_db)):
    exclusions = []
    for host in body.excluded_hosts:
        if not host.strip():
            continue
        try:
            url, normalized_host, _ = canonical_url(host.strip())
            from urllib.parse import urlsplit
            if urlsplit(url).path != '/' or urlsplit(url).query:
                raise ValueError()
            exclusions.append(normalized_host)
        except ValueError:
            raise HTTPException(422, 'Hariç tutulacak alan adı geçersiz.')
    row = service.settings(db)
    for key, value in body.model_dump(exclude={'excluded_hosts'}).items():
        setattr(row, key, value)
    row.excluded_hosts = list(dict.fromkeys(exclusions))
    db.commit()
    return config_json(row)


@router.post('/candidates')
def add_candidates(body: Seeds, db: Session = Depends(get_db)):
    added, existing, rejected = 0, 0, []
    for index, url in enumerate(body.urls):
        try:
            _, created = service.enqueue(db, url)
            added += int(created)
            existing += int(not created)
        except ValueError as exc:
            rejected.append({'index': index, 'reason': str(exc)})
    return {'added': added, 'existing': existing, 'rejected': rejected}


@router.get('/candidates')
def candidates(state: str | None = Query(None, max_length=24), page: int = Query(1, ge=1), db: Session = Depends(get_db)):
    query = db.query(CrawlCandidate)
    if state:
        query = query.filter_by(state=state)
    return {'data': [service.serialize(row) for row in query.order_by(CrawlCandidate.updated_at.desc(), CrawlCandidate.id.desc()).offset((page-1)*30).limit(30)],
            'total': query.count(), 'page': page}


@router.get('/candidates/{candidate_id}')
def detail(candidate_id: int, db: Session = Depends(get_db)):
    row = require_candidate(db, candidate_id)
    observations = db.query(CrawlObservation).filter_by(candidate_id=candidate_id).order_by(CrawlObservation.id.desc()).limit(10).all()
    reviews = db.query(CrawlReview).filter_by(candidate_id=candidate_id).order_by(CrawlReview.id.desc()).limit(20).all()
    return {**service.serialize(row), 'observations': [{'id': item.id, 'final_url': display_url(item.final_url),
                'http_status': item.http_status, 'live': item.live, 'truncated': item.truncated, 'fetched_at': item.fetched_at,
                'features': service.public_features(item.features), 'assessment': item.assessment,
                'has_screenshot': bool(item.screenshot_path)} for item in observations],
            'reviews': [{'decision': item.decision, 'note': item.note, 'actor': item.actor, 'created_at': item.created_at} for item in reviews]}


@router.post('/candidates/{candidate_id}/retry')
def retry(candidate_id: int, actor=Depends(operator), db: Session = Depends(get_db)):
    try:
        service.requeue(db, require_candidate(db, candidate_id), actor)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {'state': 'pending'}


@router.post('/candidates/{candidate_id}/review')
def review(candidate_id: int, body: ReviewBody, actor=Depends(operator), db: Session = Depends(get_db)):
    try:
        service.review(db, require_candidate(db, candidate_id), body.decision, body.note, actor, body.observation_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return {'state': body.decision}


@router.get('/observations/{observation_id}/screenshot')
def screenshot(observation_id: int, db: Session = Depends(get_db)):
    row = db.get(CrawlObservation, observation_id)
    if row is None or not row.screenshot_path:
        raise HTTPException(404, 'Ekran görüntüsü yok.')
    root = service.artifacts().resolve()
    path = (root / row.screenshot_path).resolve()
    if path.parent != root or not path.is_file() or path.suffix != '.png':
        raise HTTPException(404, 'Ekran görüntüsü yok.')
    return FileResponse(path, media_type='image/png', headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


@router.get('/candidates/{candidate_id}/related')
def related(candidate_id: int, db: Session = Depends(get_db)):
    require_candidate(db, candidate_id)
    latest = db.query(CrawlObservation).filter_by(candidate_id=candidate_id).order_by(CrawlObservation.id.desc()).first()
    if not latest:
        return {'data': [], 'scope': 'latest_500_observations'}
    data = []
    seen = set()
    for other in db.query(CrawlObservation).filter(CrawlObservation.candidate_id != candidate_id).order_by(CrawlObservation.id.desc()).limit(500):
        if other.candidate_id in seen:
            continue
        seen.add(other.candidate_id)
        reasons = []
        if other.content_hash == latest.content_hash:
            reasons.append('Aynı HTML')
        for key, label in [('script_hashes', 'Ortak satır içi script'), ('trackers', 'Ortak tracker kimliği')]:
            if set(latest.features.get(key, [])) & set(other.features.get(key, [])):
                reasons.append(label)
        if latest.features.get('favicon_sha256') and latest.features['favicon_sha256'] == other.features.get('favicon_sha256'):
            reasons.append('Aynı favicon')
        if reasons:
            data.append({'candidate_id': other.candidate_id, 'url': display_url(other.final_url), 'reasons': reasons})
    return {'data': data[:30], 'scope': 'latest_500_observations', 'note': 'Benzerlik phishing veya aynı operatör kanıtı değildir.'}


@router.post('/snapshots')
def import_snapshot(body: Snapshot, db: Session = Depends(get_db)):
    try:
        if len(body.html.encode('utf-8')) > 1_000_000:
            raise ValueError('HTML en fazla 1 MB olabilir.')
        row, created = service.enqueue(db, body.url, source='snapshot', reason='İçe aktarılan kaynak kod; canlı doğrulama yapılmadı')
        if not created:
            raise HTTPException(409, 'Bu adres zaten var; mevcut gözlem geçmişi korunuyor.')
        token = uuid.uuid4().hex
        row.state, row.lease_token, row.lease_until = 'running', token, service.now() + timedelta(minutes=1)
        db.commit()
        observation = service.finish(db, row.id, token, url=row.url, html=body.html, status=200, live=False)
        return {'id': row.id, 'observation_id': observation.id}
    except ValueError as exc:
        raise HTTPException(422, str(exc))


@router.get('/sources')
def sources(db: Session = Depends(get_db)):
    return {'data': [{'id': row.id, 'name': row.name, 'url': display_url(row.url), 'kind': row.kind, 'enabled': row.enabled,
        'last_checked_at': row.last_checked_at, 'last_error': row.last_error, 'added_count': row.added_count} for row in db.query(CrawlSource).order_by(CrawlSource.id).all()]}


@router.post('/sources')
def add_source(body: SourceBody, db: Session = Depends(get_db)):
    if db.query(CrawlSource).count() >= 20:
        raise HTTPException(409, 'En fazla 20 kaynak eklenebilir.')
    if body.kind == 'certstream':
        # CertStream uç noktası sabittir; operatör WebSocket adresi girmez.
        if db.query(CrawlSource).filter_by(kind='certstream').count() >= 1:
            raise HTTPException(409, 'Zaten bir CertStream kaynağı var.')
        from app.discovery.certstream import DEFAULT_URL
        row = CrawlSource(name=body.name, url=DEFAULT_URL, kind='certstream')
        db.add(row)
        db.commit()
        return {'id': row.id}
    try:
        url, host, _ = canonical_url(body.url)
        if service.excluded(host, service.settings(db)):
            raise ValueError('Alan adı hariç tutuldu.')
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    row = CrawlSource(name=body.name, url=url, kind=body.kind)
    db.add(row)
    db.commit()
    return {'id': row.id}


@router.delete('/sources/{source_id}')
def remove_source(source_id: int, db: Session = Depends(get_db)):
    row = db.get(CrawlSource, source_id)
    if row is None:
        raise HTTPException(404, 'Kaynak bulunamadı.')
    db.delete(row)
    db.commit()
    return {'deleted': True}
