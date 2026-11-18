"""Schema management helpers. Alembic (alembic/versions) is the only schema authority."""
from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[1]


def alembic_config(url: str) -> Config:
    config = Config(str(ROOT / 'alembic.ini'))
    config.set_main_option('script_location', str(ROOT / 'alembic'))
    config.set_main_option('sqlalchemy.url', url)
    config.attributes['configure_logging'] = False
    return config


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config('sqlite://')).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def is_up_to_date(engine: Engine) -> bool:
    return current_revision(engine) == head_revision()


def upgrade_to_head(engine: Engine) -> None:
    """Bring the database to the latest revision.

    A database created before Alembic was adopted (tables present, no
    ``alembic_version``) is stamped as the baseline instead of re-created.
    """
    config = alembic_config(engine.url.render_as_string(hide_password=False))
    tables = set(inspect(engine).get_table_names())
    if tables and 'alembic_version' not in tables:
        logger.warning('Unversioned database found; stamping it as the baseline revision')
        command.stamp(config, '0001_baseline')
    command.upgrade(config, 'head')
