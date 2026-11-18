"""Async scanner checks: reputation, retries, expiry and persisted final results."""
import importlib
import uuid
from unittest.mock import MagicMock

import pytest
from billiard.exceptions import SoftTimeLimitExceeded
from celery.exceptions import Retry


def module(name):
    return importlib.import_module('modules.phishing_detector.'+name)


@pytest.mark.parametrize('url',['https://google.com','https://ziraatbank.com.tr','https://example.gov.tr'])
def test_known_reputation_still_requires_content_analysis(url,monkeypatch):
    scanner=module('scanner')
    monkeypatch.setattr(scanner,'PHISHTANK_DB',set())
    monkeypatch.setattr(scanner,'classify_url',lambda _: {'ml_penalty':0})
    assert scanner.run_quick_checks(url)['definitive'] is False


def test_known_malicious_domain_is_definitive(monkeypatch):
    scanner=module('scanner')
    monkeypatch.setattr(scanner,'PHISHTANK_DB',{'danger.example'})
    result=scanner.run_quick_checks('https://danger.example/login')
    assert result['definitive'] and result['safety_score']==0


def test_success_persists_full_final_result(monkeypatch):
    tasks=module('celery_tasks')
    monkeypatch.setattr(module('scanner'),'calculate_safety_score',lambda *a:{'safety_score':75,'risk_level':'medium','sources':[]})
    job=str(uuid.uuid4())
    result=tasks.run_heavy_analysis.run('https://test.example',job)
    stored=module('cache_db').get_celery_job('job:'+job)
    assert result['risk_score']==25
    assert stored['status']=='complete'
    assert stored['score_version']==2
    assert module('cache_db').get_cached_scan_result('https://test.example')['safety_score']==75


def test_transient_failure_records_retrying_not_terminal_error(monkeypatch):
    tasks=module('celery_tasks')
    monkeypatch.setattr(module('scanner'),'calculate_safety_score',lambda *a:(_ for _ in ()).throw(RuntimeError('test failure')))
    monkeypatch.setattr(tasks.run_heavy_analysis,'retry',MagicMock(side_effect=Retry()))
    job=str(uuid.uuid4())
    tasks.run_heavy_analysis.push_request(retries=0)
    try:
        with pytest.raises(Retry):tasks.run_heavy_analysis.run('https://test.example',job)
    finally:tasks.run_heavy_analysis.pop_request()
    assert module('cache_db').get_celery_job('job:'+job)['status']=='retrying'


def test_exhausted_retries_record_failure(monkeypatch):
    tasks=module('celery_tasks')
    monkeypatch.setattr(module('scanner'),'calculate_safety_score',lambda *a:(_ for _ in ()).throw(RuntimeError('test failure')))
    job=str(uuid.uuid4())
    tasks.run_heavy_analysis.push_request(retries=2)
    try:
        with pytest.raises(RuntimeError):tasks.run_heavy_analysis.run('https://test.example',job)
    finally:tasks.run_heavy_analysis.pop_request()
    assert module('cache_db').get_celery_job('job:'+job)['status']=='failed'


def test_timeout_records_terminal_state_without_retry(monkeypatch):
    tasks=module('celery_tasks')
    monkeypatch.setattr(module('scanner'),'calculate_safety_score',lambda *a:(_ for _ in ()).throw(SoftTimeLimitExceeded()))
    retry=MagicMock()
    monkeypatch.setattr(tasks.run_heavy_analysis,'retry',retry)
    job=str(uuid.uuid4())
    assert tasks.run_heavy_analysis.run('https://test.example',job)['status']=='timeout'
    assert module('cache_db').get_celery_job('job:'+job)['status']=='timeout'
    retry.assert_not_called()


def test_unknown_job_expires_instead_of_pending_forever():
    assert module('router').get_job_result(str(uuid.uuid4()),None,None)['status']=='expired'
