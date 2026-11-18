"""Behavioral regressions for security boundaries and complete user workflows."""
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import json
import socket
import uuid
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.models import (User, UserRole, APIKey, IndicatorOfCompromise, URLAnalizHistory, UserReport,
                        EventOutbox, PrivateScan)
from app.auth import generate_api_key


@pytest.fixture
def environment(tmp_path, monkeypatch):
    engine = create_engine('sqlite:///' + str(tmp_path / 'main.db'), connect_args={'check_same_thread': False})
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    from app.main import app
    import app.middleware.rate_limit as limiter
    monkeypatch.setattr(limiter, 'SessionLocal', sessions)
    for module_name in ('app.database', 'shared.utils.db', 'app.workflow_tasks'):
        monkeypatch.setattr(importlib.import_module(module_name), 'SessionLocal', sessions)
    # Tarayıcının ham sqlite bağlantısı da aynı geçici veritabanını kullansın.
    monkeypatch.setattr(importlib.import_module('modules.phishing_detector.cache_db'), '_db_path', lambda: tmp_path / 'main.db')
    def db_override():
        with sessions() as db:
            yield db
    import shared.utils.db as shared_db
    app.dependency_overrides[get_db] = db_override
    app.dependency_overrides[shared_db.get_db] = db_override
    client = TestClient(app)
    def account(email='owner@example.com', role=UserRole.free):
        with sessions() as db:
            user = User(email=email, role=role)
            db.add(user)
            db.flush()
            raw, hashed, prefix = generate_api_key()
            key = APIKey(user_id=user.id, role=role, rate_limit_tier=role.value, key_hash=hashed, key_prefix=prefix)
            db.add(key)
            db.commit()
            return user.id, raw
    yield client, sessions, account
    app.dependency_overrides.clear()
    client.close()
    engine.dispose()




def test_sqlite_ioc_identity(environment):
    _, sessions, _ = environment
    with sessions() as db:
        db.add(IndicatorOfCompromise(ioc_type='url',ioc_value='https://bad.example/path',source='test',threat_type='phishing',risk_score=90,confidence=.9))
        db.commit()
        assert db.query(IndicatorOfCompromise).one().id > 0


def test_dangerous_zero_safety_persists_and_groups(environment):
    cache = importlib.import_module('modules.phishing_detector.cache_db')
    assert cache.persist_scan_result('https://bad.example', {'safety_score':0,'risk_level':'danger','sources':[]})
    with cache.get_db_connection() as db:
        row = db.execute('SELECT risk_score,is_safe FROM scan_results').fetchone()
        assert tuple(row) == (100, 0)
    assert cache.get_threat_type_distribution() == {'phishing':1}
    assert cache.get_cached_scan_result('https://bad.example')['safety_score'] == 0


def test_cache_counter_is_atomic_and_bounded():
    from app.runtime_store import increment
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: increment('counter',limit=15), range(40)))
    assert sum(accepted for _,accepted in values) == 15
    assert increment('counter',limit=15) == (15,False)


@pytest.mark.parametrize('url', ['http://127.0.0.1','http://[::1]','https://10.0.0.1','http://169.254.169.254','file:///etc/passwd','https://user:pass@example.com','https://localhost','https://example.com:8080'])
def test_outbound_rejects_private_and_unsafe_targets(url):
    from app.outbound import validate_url, UnsafeTarget
    with pytest.raises(UnsafeTarget):
        validate_url(url,resolve=False)


def test_outbound_rejects_mixed_dns_and_pins_public_address(monkeypatch):
    from app.outbound import validate_url, UnsafeTarget, safe_get
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('93.184.216.34',443)),(2,1,6,'',('10.0.0.2',443))])
    with pytest.raises(UnsafeTarget): validate_url('https://public.example')
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('93.184.216.34',443))])
    captured = {}
    class Response:
        status=200
        headers={'Content-Type':'text/plain'}
        def stream(self,*a,**k): yield b'ok'
        def close(self): pass
    class Pool:
        def __init__(self,address,**kwargs): captured.update(address=address,kwargs=kwargs)
        def urlopen(self,*a,**k): return Response()
        def close(self): pass
    monkeypatch.setattr('app.outbound.urllib3.HTTPSConnectionPool',Pool)
    assert safe_get('https://public.example/path').text == 'ok'
    assert captured['address'] == '93.184.216.34'
    assert captured['kwargs']['server_hostname'] == 'public.example'


def test_redirect_to_private_address_is_blocked(monkeypatch):
    from app.outbound import safe_get, UnsafeTarget
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:[(2,1,6,'',('93.184.216.34',443))])
    response=MagicMock(status=302,headers={'Location':'http://127.0.0.1/private'})
    response.stream.return_value=[]
    pool=MagicMock()
    pool.urlopen.return_value=response
    monkeypatch.setattr('app.outbound.urllib3.HTTPSConnectionPool',lambda *a,**k:pool)
    with pytest.raises(UnsafeTarget):safe_get('https://public.example')
    assert pool.urlopen.call_count == 1


def test_browser_never_directly_fetches_private_resource():
    from app.outbound import guard_browser_context
    context=MagicMock()
    guard_browser_context(context)
    handler=context.route.call_args.args[1]
    route=MagicMock()
    route.request.method='GET'
    route.request.resource_type='document'
    route.request.url='http://127.0.0.1/private'
    route.request.headers={}
    handler(route)
    route.abort.assert_called_once()
    route.fulfill.assert_not_called()


def test_whitelist_is_not_a_final_safety_verdict(monkeypatch):
    scanner=importlib.import_module('modules.phishing_detector.scanner')
    monkeypatch.setattr(scanner,'classify_url',lambda _: {'ml_penalty':0})
    monkeypatch.setattr(scanner,'PHISHTANK_DB',set())
    assert scanner.run_quick_checks('https://google.com/compromised')['definitive'] is False
    assert scanner.run_quick_checks('https://example.gov.tr/compromised')['definitive'] is False


def test_sessions_are_httponly_and_disabled_accounts_are_rejected(environment):
    client,sessions,account=environment
    user_id,raw=account()
    response=client.post('/api/v2/auth/login',json={'email':'owner@example.com','api_key':raw})
    assert response.status_code==200
    assert 'httponly' in response.headers['set-cookie'].lower()
    assert client.get('/api/v2/auth/me').status_code==200
    with sessions() as db:
        db.get(User,user_id).is_active=False
        db.commit()
    assert client.get('/api/v2/auth/me').status_code==401
    assert client.get('/api/v2/auth/me',headers={'X-API-Key':raw}).status_code==401


def test_private_history_and_reports_do_not_cross_accounts(environment):
    client,sessions,account=environment
    owner,raw=account()
    _,other=account('other@example.com')
    with sessions() as db:
        row=URLAnalizHistory(user_id=owner,url='https://secret.example/token',domain='secret.example',risk_level='high')
        report=UserReport(user_id=owner,user_description='Private incident',ai_analysis={})
        db.add_all([row,report]);db.commit();history_id,report_id=row.id,report.id
    assert client.get('/api/v2/ai-analyzer/history').status_code==401
    assert client.get(f'/api/v2/ai-analyzer/history/{history_id}',headers={'X-API-Key':other}).status_code==404
    assert client.get(f'/api/v2/reports/{report_id}',headers={'X-API-Key':other}).status_code==404
    assert client.get('/api/v2/ai-analyzer/history',headers={'X-API-Key':raw}).json()['total']==1


def test_job_lifecycle_and_final_history(environment,monkeypatch):
    client,sessions,account=environment
    owner,raw=account()
    rt=importlib.import_module('modules.phishing_detector.router')
    scanner=importlib.import_module('modules.phishing_detector.scanner')
    tasks=importlib.import_module('modules.phishing_detector.celery_tasks')
    monkeypatch.setattr(rt,'run_quick_checks',lambda *a:{'definitive':False,'score':50,'sources':[]})
    queued=client.post('/api/v2/phishing/check-url',json={'url':'https://unknown.example'},headers={'X-API-Key':raw})
    assert queued.status_code==200,queued.text
    job=queued.json()['job_id']
    assert client.get('/api/v2/phishing/result/'+job).json()['status']=='queued'
    # Same URL deduplicates into exactly the existing queued job.
    assert client.post('/api/v2/phishing/check-url',json={'url':'https://unknown.example'}).json()['job_id']==job
    monkeypatch.setattr(scanner,'calculate_safety_score',lambda *a:{'safety_score':0,'risk_level':'danger','sources':[]})
    tasks.run_heavy_analysis.run('https://unknown.example',job)
    assert client.get('/api/v2/phishing/result/'+job,headers={'X-API-Key':raw}).json()['risk_score']==100
    assert client.get('/api/v2/phishing/result/'+str(uuid.uuid4())).json()['status']=='expired'
    with sessions() as db:
        assert db.query(PrivateScan).filter_by(user_id=owner).count()==1


def test_pdf_export_is_real_private_and_monthly_quota_counts_distinct_reports(environment):
    client,sessions,account=environment
    owner,raw=account()
    _,other=account('other@example.com')
    with sessions() as db:
        rows=[UserReport(user_id=owner,user_description='Şüpheli SMS ve bağlantı',protection_plan='1. Bankayı doğrulayın\n2. Şifrenizi değiştirin') for _ in range(4)]
        db.add_all(rows);db.commit();ids=[r.id for r in rows]
    headers={'X-API-Key':raw}
    assert client.get(f'/api/v2/reports/{ids[0]}/pdf',headers={'X-API-Key':other}).status_code==404
    for report_id in ids[:3]:
        response=client.get(f'/api/v2/reports/{report_id}/pdf',headers=headers)
        assert response.status_code==200,response.text[:200]
        assert response.content.startswith(b'%PDF-')
    assert client.get(f'/api/v2/reports/{ids[0]}/pdf',headers=headers).status_code==200
    assert client.get(f'/api/v2/reports/{ids[3]}/pdf',headers=headers).status_code==429


def test_report_creation_and_pdf_event_are_atomic(environment,monkeypatch):
    client,sessions,account=environment
    owner,raw=account()
    monkeypatch.setattr('modules.ai_analyzer.incident_analysis.analyze_user_report',lambda _: {'attack_type':'smishing','risk_score':80,'protection_plan':'Doğrulayın','ai_analysis':{}})
    response=client.post('/api/v2/reports/analyze',json={'description':'Şüpheli bir banka mesajı aldım.'},headers={'X-API-Key':raw})
    assert response.status_code==200,response.text
    with sessions() as db:
        row=db.query(EventOutbox).one()
        assert row.payload['report_id']==response.json()['id']
    from app.workflow_tasks import deliver_outbox
    assert deliver_outbox.run()['processed']==1
    with sessions() as db:
        assert db.get(UserReport,response.json()['id']).pdf_status=='ready'






def test_api_missing_route_is_json_404_and_health_is_real(environment):
    client,_,_=environment
    response=client.get('/api/v2/missing')
    assert response.status_code==404
    assert response.headers['content-type'].startswith('application/json')
    assert client.get('/health').json()['status']=='ok'
    assert client.get('/ready').status_code==200


def test_watchlist_only_notifies_on_real_changes(environment):
    client,sessions,account=environment
    owner,raw=account()
    _,other=account('other@example.com')
    headers={'X-API-Key':raw}
    response=client.post('/api/v2/watchlist',headers=headers,json={'kind':'domain','value':'tracked.example'})
    watch=response.json()['id']
    assert client.delete('/api/v2/watchlist/'+str(watch),headers={'X-API-Key':other}).status_code==404
    with sessions() as db:
        ioc=IndicatorOfCompromise(ioc_type='domain',ioc_value='tracked.example',source='test',threat_type='phishing',risk_score=90,confidence=.9)
        db.add(ioc);db.commit();ioc_id=ioc.id
    from app.workflow_tasks import check_watchlist
    assert check_watchlist.run()['checked']==1
    assert len(client.get('/api/v2/notifications',headers=headers).json()['data'])==1
    check_watchlist.run()
    assert len(client.get('/api/v2/notifications',headers=headers).json()['data'])==1
    with sessions() as db:
        db.get(IndicatorOfCompromise,ioc_id).status='resolved';db.commit()
    check_watchlist.run()
    assert len(client.get('/api/v2/notifications',headers=headers).json()['data'])==2


def test_feedback_is_owned_and_only_admin_can_review(environment):
    client,sessions,account=environment
    owner,raw=account()
    _,other=account('other@example.com')
    _,admin=account('admin@example.com',UserRole.admin)
    with sessions() as db:
        report=UserReport(user_id=owner,user_description='Private incident')
        db.add(report);db.commit();report_id=report.id
    body={'report_id':report_id,'expected_verdict':'safe','reason':'Kaynak kurum tarafından doğrulandı.'}
    assert client.post('/api/v2/feedback',headers={'X-API-Key':other},json=body).status_code==404
    feedback_id=client.post('/api/v2/feedback',headers={'X-API-Key':raw},json=body).json()['id']
    review={'status':'resolved','note':'Kaynak kanıtı incelendi.'}
    assert client.patch('/api/v2/admin/feedback/'+str(feedback_id),headers={'X-API-Key':raw},json=review).status_code==403
    assert client.patch('/api/v2/admin/feedback/'+str(feedback_id),headers={'X-API-Key':admin},json=review).status_code==200
    assert client.get('/api/v2/feedback',headers={'X-API-Key':raw}).json()['data'][0]['review_note']==review['note']


def test_anonymous_expensive_endpoints_are_rate_limited(environment):
    client,_,_=environment
    responses=[client.post('/api/v2/sms/analyze',json={'text':'Merhaba toplantı yarın saat onda.'}) for _ in range(11)]
    assert all(response.status_code==200 for response in responses[:10])
    assert responses[-1].status_code==429
    assert responses[-1].headers['retry-after']=='60'


def test_recovery_token_is_single_use_and_revokes_old_keys(environment):
    from app.models import RecoveryToken
    client,sessions,account=environment
    owner,raw=account()
    token='recovery-test-'+'x'*40
    with sessions() as db:
        db.add(RecoveryToken(user_id=owner,token_hash=hashlib.sha256(token.encode()).hexdigest(),expires_at=datetime.now(timezone.utc)+timedelta(minutes=10)))
        db.commit()
    response=client.post('/api/v2/auth/recovery/complete',json={'token':token})
    assert response.status_code==200,response.text
    assert client.get('/api/v2/auth/me',headers={'X-API-Key':raw}).status_code==401
    assert client.get('/api/v2/auth/me',headers={'X-API-Key':response.json()['api_key']}).status_code==200
    assert client.post('/api/v2/auth/recovery/complete',json={'token':token}).status_code==400








def test_real_worker_consumes_queued_job_and_api_observes_completion(environment,monkeypatch):
    import time
    from celery.contrib.testing.worker import start_worker
    from app.celery_app import celery_app
    client,_,account=environment
    _,raw=account()
    rt=importlib.import_module('modules.phishing_detector.router')
    scanner=importlib.import_module('modules.phishing_detector.scanner')
    monkeypatch.setattr(rt,'run_quick_checks',lambda *a:{'definitive':False,'score':50,'sources':[]})
    monkeypatch.setattr(scanner,'calculate_safety_score',lambda *a:{'safety_score':20,'risk_level':'high','sources':[]})
    celery_app.loader.import_default_modules()
    with start_worker(celery_app,pool='solo',queues=['phishing'],perform_ping_check=False,shutdown_timeout=10):
        response=client.post('/api/v2/phishing/check-url',headers={'X-API-Key':raw},json={'url':'https://worker.example'})
        assert response.status_code==200,response.text
        job=response.json()['job_id']
        result={}
        for _ in range(100):
            result=client.get('/api/v2/phishing/result/'+job).json()
            if result['status']=='complete': break
            time.sleep(.05)
        assert result['status']=='complete'
        assert result['risk_score']==80


def test_baseline_migration_matches_models(tmp_path):
    import os
    import subprocess
    import sys
    env={**os.environ,'DATABASE_URL':'sqlite:///'+str(tmp_path/'fresh.db')}
    subprocess.run([sys.executable,'-m','alembic','upgrade','head'],env=env,check=True,capture_output=True)
    check=subprocess.run([sys.executable,'-m','alembic','check'],env=env,capture_output=True,text=True)
    assert check.returncode == 0, check.stdout + check.stderr
    engine=create_engine(env['DATABASE_URL'])
    with engine.begin() as connection:
        connection.execute(IndicatorOfCompromise.__table__.insert().values(ioc_type='url',ioc_value='https://new.example',source='test',threat_type='phishing',risk_score=80,confidence=.8))
        assert connection.exec_driver_sql('SELECT count(*) FROM indicators_of_compromise').scalar()==1
        assert connection.exec_driver_sql("SELECT count(*) FROM sqlite_master WHERE name IN ('scan_results','scan_events')").scalar()==2
    engine.dispose()


@pytest.mark.parametrize('text', [
    'Kargonuzu teslim almak için ödemenizi hemen yapın. Hesabınız kapanmadan 10 dakika içinde kart bilgilerinizi girin.',
    'HESABINIZ BLOKE OLACAK. Hemen sifrenizi ve dogrulama kodunu gonderin.',
])
def test_sms_sensitive_request_and_pressure_is_not_clean(environment, text):
    client, _, _ = environment
    response = client.post('/api/v2/sms/analyze', json={'text':text})
    assert response.status_code == 200
    assert response.json()['risk_score'] >= 75
    assert response.json()['action'] == 'BLOCK'
    assert response.json()['indicators']


def test_sms_normal_delivery_and_nonsharing_notice_not_blocked(environment):
    client, _, _ = environment
    for text in ('Kargonuz bugün teslim edilecektir.', 'Doğrulama kodunuz 123456. Kimseyle paylaşmayın.'):
        result = client.post('/api/v2/sms/analyze', json={'text':text}).json()
        assert result['action'] != 'BLOCK'
        assert 'garantisi değildir' in result['explanation']


