"""CertStream keşif katmanı: süzgeç kalibrasyonu, hacim freni, güvenli entegrasyon.

Testler ağa çıkmaz; gerçek WebSocket açılmaz. Dinleyici mesaj işleme yolu örnek
CT JSON sözlükleriyle sınanır.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.discovery import certstream, matcher, service, worker
from app.discovery.router import operator, router
from app.models import CrawlCandidate, CrawlSource


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    monkeypatch.setenv('CRAWLER_DATA_DIR', str(tmp_path / 'artifacts'))
    engine = create_engine('sqlite:///' + str(tmp_path / 'discovery.db'),
                           connect_args={'check_same_thread': False, 'timeout': 20})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    with sessions() as db:
        service.settings(db)
    yield sessions
    engine.dispose()


@pytest.fixture
def client(discovery):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[operator] = lambda: 'test-operator'
    def database():
        with discovery() as db:
            yield db
    app.dependency_overrides[get_db] = database
    with TestClient(app) as http:
        yield http


def enable(db, *, certstream_source=True):
    config = service.settings(db)
    config.enabled = True
    if certstream_source:
        db.add(CrawlSource(name='CT', url=certstream.DEFAULT_URL, kind='certstream'))
    db.commit()


# ---------------------------------------------------------------- matcher

@pytest.mark.parametrize('domain', [
    'paypal-login.xyz',          # marka adı + anahtar sözcük + riskli TLD
    'secure-apple.verify.top',   # marka adı + anahtar sözcükler
    'paypa1.com',                # typosquat (l→1)
    'netfl1x-account.com',       # typosquat + anahtar sözcük
    'micr0soft-update.tk',       # typosquat + anahtar sözcük + TLD
    'garantibbva-giris.xyz',     # TR banka markası + anahtar sözcük
])
def test_suspicious_domains_flagged(domain):
    matched, score, reason = matcher.classify(domain)
    assert matched, (domain, score, reason)
    assert reason


@pytest.mark.parametrize('domain', [
    'paypal.com',                # resmi alan
    'accounts.google.com',       # resmi alanın alt alanı
    'www.microsoft.com',         # resmi alanın alt alanı
    'snapple.com',               # 'apple' içerir ama sözcük sınırı yok, uzunluk farkı >1
    'example.com',               # alakasız
    'pineapple-recipes.com',     # 'apple' gömülü; sınır yok
    'documentation.dev',         # anahtar sözcük yok
])
def test_benign_domains_not_flagged(domain):
    matched, score, reason = matcher.classify(domain)
    assert not matched, (domain, score, reason)


def test_official_short_circuits_before_scoring():
    assert matcher.classify('paypal.com') == (False, 0, 'official')


def test_wildcard_and_dot_normalized():
    assert matcher.normalize_domain('*.Paypal-Login.XYZ.') == 'paypal-login.xyz'


# ---------------------------------------------------------------- handle_domains

def test_only_matching_domains_enqueued(discovery):
    with discovery() as db:
        enable(db)
        source = db.query(CrawlSource).filter_by(kind='certstream').one()
        added = certstream.handle_domains(
            db, ['paypal-login.xyz', 'example.com', 'netfl1x-account.com'], source)
        assert added == 2
        hosts = {row.host for row in db.query(CrawlCandidate).all()}
        assert hosts == {'paypal-login.xyz', 'netfl1x-account.com'}
        assert db.query(CrawlCandidate).filter_by(source='certstream').count() == 2
        db.refresh(source)
        assert source.added_count == 2


def test_duplicate_domain_not_recounted(discovery):
    with discovery() as db:
        enable(db)
        source = db.query(CrawlSource).filter_by(kind='certstream').one()
        assert certstream.handle_domains(db, ['paypal-login.xyz'], source) == 1
        assert certstream.handle_domains(db, ['paypal-login.xyz'], source) == 0
        assert db.query(CrawlCandidate).count() == 1


def test_excluded_host_skipped(discovery):
    with discovery() as db:
        enable(db)
        config = service.settings(db)
        config.excluded_hosts = ['paypal-login.xyz']
        db.commit()
        source = db.query(CrawlSource).filter_by(kind='certstream').one()
        added = certstream.handle_domains(db, ['paypal-login.xyz', 'netfl1x-account.com'], source)
        assert added == 1
        assert db.query(CrawlCandidate).count() == 1


def test_per_minute_rate_cap(discovery, monkeypatch):
    monkeypatch.setattr(certstream, 'RATE_PER_MIN', 2)
    with discovery() as db:
        enable(db)
        source = db.query(CrawlSource).filter_by(kind='certstream').one()
        batch = ['paypal-login.xyz', 'netfl1x-account.com', 'micr0soft-update.tk', 'garantibbva-giris.xyz']
        added = certstream.handle_domains(db, batch, source)
        assert added == 2
        assert db.query(CrawlCandidate).count() == 2


def test_cert_domain_count_bounded(discovery, monkeypatch):
    monkeypatch.setattr(certstream, 'MAX_DOMAINS_PER_CERT', 1)
    monkeypatch.setattr(certstream, 'RATE_PER_MIN', 100)
    with discovery() as db:
        enable(db)
        source = db.query(CrawlSource).filter_by(kind='certstream').one()
        added = certstream.handle_domains(db, ['paypal-login.xyz', 'netfl1x-account.com'], source)
        assert added == 1


# ---------------------------------------------------------------- active_source gate

def test_listener_idle_when_discovery_paused(discovery):
    with discovery() as db:
        db.add(CrawlSource(name='CT', url=certstream.DEFAULT_URL, kind='certstream'))
        db.commit()  # kaynak var ama keşif kapalı
        assert certstream.active_source(db) is None


def test_listener_idle_without_source(discovery):
    with discovery() as db:
        config = service.settings(db)
        config.enabled = True
        db.commit()
        assert certstream.active_source(db) is None


def test_listener_active_when_enabled(discovery):
    with discovery() as db:
        enable(db)
        assert certstream.active_source(db) is not None


# ---------------------------------------------------------------- integration guards

def test_poll_sources_ignores_certstream(discovery):
    # poll_sources certstream kaynağını GET ile çekmeye kalkmamalı (ağa çıkmaz).
    with discovery() as db:
        enable(db)
    assert worker.poll_sources(sessions=discovery) == 0
    with discovery() as db:
        assert db.query(CrawlCandidate).count() == 0


def test_router_adds_single_fixed_certstream_source(client):
    created = client.post('/api/v2/crawler/sources', json={'name': 'CT', 'kind': 'certstream'})
    assert created.status_code == 200
    second = client.post('/api/v2/crawler/sources', json={'name': 'CT2', 'kind': 'certstream'})
    assert second.status_code == 409
    rows = client.get('/api/v2/crawler/sources').json()['data']
    row = next(r for r in rows if r['kind'] == 'certstream')
    assert row['url'].startswith('wss://')
