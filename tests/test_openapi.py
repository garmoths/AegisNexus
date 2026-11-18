"""The published API contract stays generable, tagged and versioned."""
from fastapi.testclient import TestClient

from app.main import API_VERSION, app


def test_openapi_schema_is_generated():
    schema = TestClient(app).get('/openapi.json').json()
    assert schema['info']['version'] == API_VERSION
    assert len(schema['paths']) > 50


def test_every_api_operation_has_a_tag():
    schema = app.openapi()
    untagged = [f'{method.upper()} {path}' for path, ops in schema['paths'].items() if path.startswith('/api/')
                for method, op in ops.items() if not op.get('tags')]
    assert untagged == []


def test_all_api_routes_are_versioned():
    paths = app.openapi()['paths']
    assert all(p.startswith('/api/v2/') for p in paths if p.startswith('/api/'))
