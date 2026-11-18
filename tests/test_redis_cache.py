"""The compatibility cache API uses shared SQLite, including TTL and bounded AI budgets."""
import importlib
import json
import os
import subprocess
import sys

import pytest
from app import runtime_store as store


def cache():
    return importlib.import_module('modules.phishing_detector.redis_cache')


def test_scan_roundtrip_preserves_result_and_invalidates():
    module = cache()
    result = {'safety_score': 0, 'url': 'https://bad.example', 'sources': []}
    assert module.redis_set_scan('url-hash', result)
    assert module.redis_get_scan('url-hash')['safety_score'] == 0
    assert '_cache_hit' not in result
    module.redis_invalidate_scan('url-hash')
    assert module.redis_get_scan('url-hash') is None


def test_cache_expires_and_cleanup_removes_old_entries(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(store.time, 'time', lambda: now[0])
    module = cache()
    module.redis_set_threat('test', {'listed': True}, ttl=5)
    assert module.redis_get_threat('test')['listed']
    now[0] += 6
    assert module.redis_get_threat('test') is None
    store.put('trigger-cleanup', {}, ttl=10)
    with store.connection() as db:
        assert db.execute('SELECT count(*) FROM kv WHERE key=?', ('ti:test',)).fetchone()[0] == 0


def test_ai_budget_is_bounded_and_daily_reset_is_shared(monkeypatch):
    module = cache()
    now = [1000.0]
    monkeypatch.setattr(store.time, 'time', lambda: now[0])
    monkeypatch.setattr(module, 'AI_DAILY_LIMIT', 2)
    assert module.redis_incr_ai_counter() == 1
    assert module.redis_incr_ai_counter() == 2
    assert module.ai_limit_reached()
    with pytest.raises(RuntimeError): module.redis_incr_ai_counter()
    now[0] += 86401
    assert module.redis_get_ai_count() == 0
    assert module.redis_incr_ai_counter() == 1


def test_worker_cache_and_counter_are_visible_in_separate_process():
    code = "from app import runtime_store as s; s.put('scan:worker',{'safety_score':80},60); s.increment('ai:daily')"
    subprocess.run([sys.executable, '-c', code], env=os.environ.copy(), check=True)
    assert cache().redis_get_scan('worker')['safety_score'] == 80
    assert cache().redis_get_ai_count() == 1


def test_health_identifies_real_storage_backend():
    value = cache().redis_health()
    assert value['available']
    assert value['backend'] == 'sqlite'
    assert value['ai_daily_count'] == 0
