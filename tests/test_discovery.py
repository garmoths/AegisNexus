"""Discovery stays bounded, isolated from verified threats and operable offline."""
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.discovery import service, worker
from app.discovery.analysis import assess, canonical_url, display_url, extract
from app.discovery.router import operator, router
from app.models import CrawlCandidate, CrawlObservation, CrawlReview, PhishingURL

HTML = '<html><title>Google hesabı</title><body>Google giriş<form action="https://collector.example/save" method="post"><input type="password"><input name="otp"></form><a href="/login">Giriş</a></body></html>'


@pytest.fixture
def discovery(tmp_path, monkeypatch):
    monkeypatch.setenv('CRAWLER_DATA_DIR', str(tmp_path / 'artifacts'))
    engine = create_engine('sqlite:///' + str(tmp_path / 'discovery.db'), connect_args={'check_same_thread': False, 'timeout': 20})
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
    with TestClient(app) as client:
        yield client


def observe(sessions, url='https://suspicious.example/login', live=True, status=200):
    with sessions() as db:
        row, _ = service.enqueue(db, url)
        candidate_id = row.id
        row, token = service.claim(db)
        assert row.id == candidate_id
        result = service.finish(db, candidate_id, token, url=url, html=HTML, status=status, live=live)
        return candidate_id, result.id


@pytest.mark.parametrize('url', ['https://127.0.0.1', 'http://[::1]', 'https://169.254.169.254', 'file:///etc/passwd', 'https://user:pass@public.example', 'http://localhost', 'https://public.example:9000'])
def test_private_and_unsafe_seeds_rejected(url):
    with pytest.raises(ValueError):
        canonical_url(url)


def test_paths_and_queries_preserved_without_fragment():
    a = canonical_url('https://EXAMPLE.com/a?token=secret#fragment')
    b = canonical_url('https://example.com/b?token=secret')
    assert a[0] == 'https://example.com/a?token=secret'
    assert a[2] != b[2]
    assert 'secret' not in display_url(a[0])


def test_html_analysis_is_explainable_and_never_confirms():
    features = extract(HTML, 'https://suspicious.example/login')
    result = assess(features)
    assert features['forms'][0]['external'] is True
    assert set(features['forms'][0]['fields']) == {'password', 'otp'}
    assert result['risk'] >= 55
    assert result['confirmed'] is False
    assert result['coverage'] == 'static'
    assert result['evidence']


def test_official_login_not_treated_as_brand_impersonation():
    html = '<title>Google</title><form action="/login" method="post"><input type="password"></form>'
    features = extract(html, 'https://accounts.google.com/login')
    assert features['brand_mismatches'] == []
    assert assess(features)['risk'] < 55


def test_unavailable_and_archival_pages_do_not_claim_safety():
    features = extract(HTML, 'https://suspicious.example')
    assert assess(features, http_status=404)['risk'] is None
    assert assess(features, live=False)['coverage'] == 'partial'
    assert assess(extract('<html></html>', 'https://example.com'))['coverage'] == 'unknown'


def test_candidate_ingestion_does_not_create_threat_rows(discovery):
    with discovery() as db:
        row, added = service.enqueue(db, 'https://new.example/login')
        assert added
        other, added = service.enqueue(db, 'https://new.example/login')
        assert other.id == row.id and not added
        assert db.query(PhishingURL).count() == 0


def test_existing_feed_candidates_go_to_discovery(discovery):
    from modules.phishing_detector.fetch_all_sources import convert_to_phishtank_format, import_to_database
    with discovery() as db:
        entries = convert_to_phishtank_format(['https://new.example/'], 'certstream')
        assert entries[0]['status'] == 'candidate'
        result = import_to_database(db, entries)
        assert result['added'] == 1
        assert db.query(CrawlCandidate).count() == 1
        assert db.query(PhishingURL).count() == 0


def test_only_one_worker_can_claim_a_candidate(discovery):
    with discovery() as db:
        service.enqueue(db, 'https://new.example/')
    def claim_once(_):
        with discovery() as db:
            row, token = service.claim(db)
            return token
    with ThreadPoolExecutor(max_workers=4) as pool:
        tokens = list(pool.map(claim_once, range(4)))
    assert sum(token is not None for token in tokens) == 1


def test_expired_worker_cannot_overwrite_new_observation(discovery):
    with discovery() as db:
        service.enqueue(db, 'https://new.example/')
        row, old = service.claim(db)
        candidate_id = row.id
        row.lease_until = service.now() - timedelta(seconds=1)
        db.commit()
        row, new = service.claim(db)
        assert new != old
        assert service.finish(db, candidate_id, old, url=row.url, html=HTML, status=200) is None
        assert service.finish(db, candidate_id, new, url=row.url, html=HTML, status=200)
        assert db.query(CrawlObservation).count() == 1


def test_repeated_timeouts_become_visible_failures(discovery):
    with discovery() as db:
        service.enqueue(db, 'https://new.example/')
        row, token = service.claim(db)
        row.attempts = 3
        row.lease_until = service.now() - timedelta(seconds=1)
        db.commit()
        assert service.claim(db) == (None, None)
        db.refresh(row)
        assert row.state == 'failed'


def test_review_publishes_only_after_human_approval_and_can_withdraw(discovery):
    candidate_id, observation_id = observe(discovery)
    with discovery() as db:
        assert db.query(PhishingURL).count() == 0
        row = db.get(CrawlCandidate, candidate_id)
        service.review(db, row, 'confirmed', 'Marka taklidi ve harici parola formu doğrulandı.', 'operator', observation_id)
        assert db.query(PhishingURL).count() == 1
        db.refresh(row)
        service.review(db, row, 'dismissed', 'Meşru test sayfası olarak doğrulandı.', 'operator', observation_id)
        assert db.query(PhishingURL).count() == 0
        assert db.query(CrawlReview).count() == 2


@pytest.mark.parametrize('live,status', [(False,200), (True,404)])
def test_incomplete_observations_cannot_be_approved(discovery, live, status):
    candidate_id, observation_id = observe(discovery, live=live, status=status)
    with discovery() as db:
        with pytest.raises(ValueError):
            service.review(db, db.get(CrawlCandidate,candidate_id), 'confirmed', 'Test reason', 'operator', observation_id)
        assert db.query(PhishingURL).count() == 0


def test_stale_review_is_rejected(discovery):
    candidate_id, observation_id = observe(discovery)
    with discovery() as db:
        row = db.get(CrawlCandidate, candidate_id)
        service.requeue(db, row, 'operator')
        with pytest.raises(ValueError):
            service.review(db, row, 'confirmed', 'Test reason', 'operator', observation_id)


def test_crawl_follows_bounded_same_host_links(discovery, monkeypatch):
    html = HTML + ''.join(f'<a href="/page/{n}">Link</a>' for n in range(20)) + '<a href="https://other.example/x">External</a>'
    monkeypatch.setattr(worker, 'fetch_page', lambda url, **kwargs: {'url':url,'html':html,'status':200,'redirects':[]})
    with discovery() as db:
        service.settings(db).enabled = True
        db.commit()
        service.enqueue(db, 'https://suspicious.example/')
    assert worker.run_one(discovery)['state'] == 'review'
    with discovery() as db:
        assert db.query(CrawlCandidate).count() == 5
        assert all(row.host == 'suspicious.example' for row in db.query(CrawlCandidate))
        assert db.query(PhishingURL).count() == 0


def test_paused_worker_makes_no_network_requests(discovery, monkeypatch):
    monkeypatch.setattr(worker, 'fetch_page', lambda *a, **k: pytest.fail('Unexpected network'))
    with discovery() as db:
        service.enqueue(db, 'https://suspicious.example/')
    assert worker.run_one(discovery)['state'] == 'paused'


def test_exclusion_blocks_subdomains(discovery):
    with discovery() as db:
        service.settings(db).excluded_hosts = ['example.com']
        db.commit()
        with pytest.raises(ValueError):
            service.enqueue(db, 'https://sub.example.com/login')


def test_source_parsing_never_marks_ct_as_threat():
    urls = worker.source_urls('[{"name_value":"*.example.com\\nlogin.example.com"}]', 'ct_json')
    assert urls == ['https://login.example.com']


def test_local_console_defends_against_cross_origin_and_rebinding():
    from fastapi import HTTPException
    from starlette.requests import Request

    from app.discovery.server import local_operator
    def request(host='127.0.0.1:8010', origin='http://127.0.0.1:8010', client='127.0.0.1', header=True):
        headers=[(b'host',host.encode()),(b'origin',origin.encode())]
        if header:
            headers.append((b'x-aegis-local',b'1'))
        return Request({'type':'http','method':'POST','scheme':'http','path':'/','query_string':b'', 'headers':headers, 'client':(client,1234), 'server':('127.0.0.1',8010)})
    assert local_operator(request()) == 'local-operator'
    for bad in [request(origin='https://evil.example'),request(host='evil.example'),request(client='10.0.0.1'),request(header=False)]:
        with pytest.raises(HTTPException):
            local_operator(bad)


def test_import_is_offline_and_read_api_never_serves_raw_html(client, discovery):
    response = client.post('/api/v2/crawler/snapshots', json={'url':'https://snapshot.example/login?token=secret','html':HTML})
    assert response.status_code == 200
    detail = client.get('/api/v2/crawler/candidates/' + str(response.json()['id'])).json()
    assert detail['observations'][0]['live'] is False
    assert 'secret' not in str(detail)
    assert '<form' not in str(detail)
    assert client.post('/api/v2/crawler/candidates/'+str(detail['id'])+'/review', json={
        'decision':'confirmed','observation_id':detail['observations'][0]['id'],'note':'Would be a mistake'}).status_code == 409


def test_api_input_bounds_and_partial_rejections(client):
    response = client.post('/api/v2/crawler/candidates', json={'urls':['https://127.0.0.1','https://public.example/login']})
    assert response.json()['added'] == 1
    assert len(response.json()['rejected']) == 1
    assert client.post('/api/v2/crawler/candidates', json={'urls':['https://x.example']*101}).status_code == 422
    assert client.patch('/api/v2/crawler/settings',json={'enabled':True,'daily_limit':999999}).status_code == 422


def test_robots_disallow_prevents_page_request(monkeypatch):
    from app.discovery import transport
    monkeypatch.setattr(transport, 'validate_url', lambda url: (url,'public.example',443,'93.184.216.34'))
    calls=[]
    def getter(url,**kwargs):
        calls.append(url)
        response=requests.Response();response.status_code=200;response._content=b'User-agent: *\nDisallow: /private';response.url=url
        return response
    with pytest.raises(transport.CrawlBlocked):
        transport.fetch_page('https://public.example/private', getter=getter)
    assert calls == ['https://public.example/robots.txt']


def test_redirect_to_private_network_never_reaches_transport(monkeypatch):
    import socket

    from app.discovery import transport
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('93.184.216.34',443))])
    calls=[]
    def getter(url,**kwargs):
        calls.append(url)
        response=requests.Response();response.url=url;response._content=b''
        response.status_code=404 if url.endswith('robots.txt') else 302
        response.headers['Location']='https://127.0.0.1/'
        return response
    with pytest.raises(ValueError):
        transport.fetch_page('https://public.example/', getter=getter)
    assert all('127.0.0.1' not in url for url in calls)


def test_multibyte_snapshot_limit_does_not_create_work(client, discovery):
    result = client.post('/api/v2/crawler/snapshots', json={'url': 'https://big.example/', 'html': '€' * 400000})
    assert result.status_code == 422
    with discovery() as db:
        assert db.query(CrawlCandidate).count() == 0


def test_scheduled_recheck_withdraws_only_owned_publication(discovery):
    candidate_id, observation_id = observe(discovery)
    with discovery() as db:
        row = db.get(CrawlCandidate, candidate_id)
        service.review(db, row, 'confirmed', 'Reviewed evidence', 'operator', observation_id)
        row.updated_at = service.now() - timedelta(hours=25)
        service.settings(db).enabled = True
        db.commit()
        assert db.query(PhishingURL).count() == 1
    assert worker.schedule_rechecks(discovery) == 1
    with discovery() as db:
        assert db.get(CrawlCandidate, candidate_id).state == 'pending'
        assert db.query(PhishingURL).count() == 0
        assert db.query(CrawlReview).filter_by(actor='scheduled_recheck').count() == 1


def test_daily_budget_defers_without_fetch(discovery, monkeypatch):
    from app import runtime_store as store
    with discovery() as db:
        config = service.settings(db)
        config.enabled, config.daily_limit = True, 1
        db.commit()
        service.enqueue(db, 'https://budget.example/')
    store.increment('crawler:daily:' + service.now().strftime('%Y-%m-%d'), ttl=172800, limit=1)
    monkeypatch.setattr(worker, 'fetch_page', lambda *a, **k: pytest.fail('Budget must prevent fetch'))
    assert worker.run_one(discovery)['state'] == 'budget'
    with discovery() as db:
        row = db.query(CrawlCandidate).one()
        assert row.state == 'retry' and row.attempts == 0


def test_source_redirect_respects_exclusions(discovery, monkeypatch):
    from app.models import CrawlSource
    with discovery() as db:
        config = service.settings(db)
        config.enabled, config.excluded_hosts = True, ['excluded.example']
        db.add(CrawlSource(name='Feed', url='https://feed.example/list', kind='url_list', enabled=True))
        db.commit()
    calls = []
    def getter(url, **kwargs):
        calls.append(url)
        response = requests.Response()
        response.status_code = 302
        response.headers['Location'] = 'https://excluded.example/list'
        return response
    monkeypatch.setattr(worker, 'safe_get', getter)
    assert worker.poll_sources(discovery) == 0
    assert calls == ['https://feed.example/list']
    with discovery() as db:
        assert db.query(CrawlSource).one().last_error == 'source_unavailable'


def test_lease_release_cannot_remove_new_owner():
    from app import runtime_store as store
    store.put('crawler:test-lease', 'new-owner', 60)
    worker.release('crawler:test-lease', 'old-owner')
    assert store.get('crawler:test-lease') == 'new-owner'
    worker.release('crawler:test-lease', 'new-owner')
    assert store.get('crawler:test-lease') is None


def test_stale_worker_failure_cannot_overwrite_new_lease(discovery):
    with discovery() as db:
        service.enqueue(db, 'https://lease.example/')
        row, old_token = service.claim(db)
        candidate_id = row.id
    with discovery() as stale:
        cached = stale.get(CrawlCandidate, candidate_id)
        assert cached.lease_token == old_token
        with discovery() as current:
            row = current.get(CrawlCandidate, candidate_id)
            row.lease_token = 'new-owner'
            current.commit()
        service.failure(stale, candidate_id, old_token, 'stale_error')
    with discovery() as db:
        row = db.get(CrawlCandidate, candidate_id)
        assert row.state == 'running' and row.lease_token == 'new-owner'
        assert row.last_error is None


def test_detail_reports_freshness_used_by_the_confirm_button(client, discovery):
    """Regression: the UI gated 'confirm' on detail.fresh, which the API never returned."""
    from datetime import timedelta
    candidate_id, observation_id = observe(discovery)
    assert client.get(f'/api/v2/crawler/candidates/{candidate_id}').json()['fresh'] is True
    with discovery() as db:
        obs = db.get(CrawlObservation, observation_id)
        obs.fetched_at = service.now() - timedelta(hours=49)
        db.commit()
    assert client.get(f'/api/v2/crawler/candidates/{candidate_id}').json()['fresh'] is False
    with discovery() as db, pytest.raises(ValueError):
        service.review(db, db.get(CrawlCandidate, candidate_id), 'confirmed', 'Stale evidence', 'operator', observation_id)
