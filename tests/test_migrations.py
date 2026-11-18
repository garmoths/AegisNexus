"""Alembic is the only schema authority: migrations must match app.models exactly."""
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine

import app.models  # noqa: F401  (registers every table)
from app.database import Base

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def alembic_config(tmp_path, monkeypatch):
    url = 'sqlite:///' + str(tmp_path / 'migrated.db')
    monkeypatch.setenv('DATABASE_URL', url)
    config = Config(str(ROOT / 'alembic.ini'))
    config.set_main_option('script_location', str(ROOT / 'alembic'))
    config.set_main_option('sqlalchemy.url', url)
    config.attributes['configure_logging'] = False
    return config, url


def test_single_head():
    script = ScriptDirectory.from_config(Config(str(ROOT / 'alembic.ini')))
    assert len(script.get_heads()) == 1


def test_upgrade_head_matches_models(alembic_config):
    config, url = alembic_config
    command.upgrade(config, 'head')
    engine = create_engine(url)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={'compare_type': True, 'render_as_batch': True})
        diff = compare_metadata(context, Base.metadata)
    engine.dispose()
    assert diff == [], f'models and migrations differ; run `alembic revision --autogenerate`: {diff}'


def test_downgrade_to_base_and_back(alembic_config):
    config, _ = alembic_config
    command.upgrade(config, 'head')
    command.downgrade(config, 'base')
    command.upgrade(config, 'head')


def test_upgrade_to_head_stamps_legacy_unversioned_database(tmp_path):
    from app.migrations import current_revision, head_revision, upgrade_to_head
    engine = create_engine('sqlite:///' + str(tmp_path / 'legacy.db'))
    Base.metadata.create_all(engine)  # how databases were created before Alembic was authoritative
    upgrade_to_head(engine)
    assert current_revision(engine) == head_revision()
    engine.dispose()


def test_ready_reports_outdated_schema(monkeypatch):
    from fastapi.testclient import TestClient

    import app.migrations
    from app.main import app as api
    monkeypatch.setattr(app.migrations, 'is_up_to_date', lambda _engine: False)
    response = TestClient(api).get('/ready')
    assert response.status_code == 503
