"""Every API error shares {detail, error: {code, status, request_id}} and carries X-Request-ID."""
import json
import logging

from fastapi import APIRouter, HTTPException
from fastapi.testclient import TestClient

from app.main import create_app
from app.observability import JsonFormatter, RequestIdFilter, request_id_var


def build_client():
    app = create_app()
    router = APIRouter()

    @router.get('/api/v2/_test/boom')
    def boom():
        raise RuntimeError('secret internal detail')

    @router.get('/api/v2/_test/conflict')
    def conflict():
        raise HTTPException(409, 'already there')

    # Insert ahead of the SPA catch-all route.
    app.router.routes[:0] = router.routes
    return TestClient(app, raise_server_exceptions=False)


def assert_envelope(response, status, code):
    body = response.json()
    assert response.status_code == status
    assert body['error']['code'] == code and body['error']['status'] == status
    assert body['error']['request_id'] == response.headers['x-request-id']
    return body


def test_not_found_envelope():
    assert_envelope(build_client().get('/api/v2/does-not-exist'), 404, 'not_found')


def test_http_exception_envelope_keeps_detail():
    body = assert_envelope(build_client().get('/api/v2/_test/conflict'), 409, 'conflict')
    assert body['detail'] == 'already there'


def test_validation_error_envelope_keeps_field_list():
    body = assert_envelope(build_client().post('/api/v2/auth/login', json={'email': 'not-an-email'}), 422, 'validation_error')
    assert isinstance(body['detail'], list) and body['detail']


def test_unhandled_exception_is_500_without_leaking_internals(caplog):
    with caplog.at_level(logging.ERROR, logger='aegis.errors'):
        response = build_client().get('/api/v2/_test/boom')
    body = assert_envelope(response, 500, 'internal_error')
    assert 'secret internal detail' not in json.dumps(body)
    assert any('Unhandled error' in r.getMessage() for r in caplog.records)


def test_rate_limit_envelope(monkeypatch):
    import app.middleware.rate_limit as limiter
    monkeypatch.setattr(limiter, 'consume', lambda _request: False)
    response = build_client().post('/api/v2/sms/analyze', json={})
    assert_envelope(response, 429, 'rate_limited')
    assert response.headers['retry-after'] == '60'


def test_incoming_request_id_is_reused_and_invalid_one_replaced():
    client = build_client()
    assert client.get('/health', headers={'X-Request-ID': 'abc-123'}).headers['x-request-id'] == 'abc-123'
    replaced = client.get('/health', headers={'X-Request-ID': 'bad id with spaces'}).headers['x-request-id']
    assert replaced != 'bad id with spaces' and len(replaced) == 16


def test_access_log_has_no_query_string(caplog):
    with caplog.at_level(logging.INFO, logger='aegis.access'):
        build_client().get('/api/v2/does-not-exist?url=https://private.example/token')
    lines = [r.getMessage() for r in caplog.records if r.name == 'aegis.access']
    assert lines and all('private.example' not in line for line in lines)


def test_json_formatter_includes_request_id():
    token = request_id_var.set('req-1')
    try:
        record = logging.LogRecord('aegis', logging.INFO, __file__, 1, 'hello %s', ('world',), None)
        RequestIdFilter().filter(record)
        payload = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert payload['message'] == 'hello world' and payload['request_id'] == 'req-1' and payload['level'] == 'INFO'
