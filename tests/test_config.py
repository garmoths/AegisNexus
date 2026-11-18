"""Typed settings (app/config.py)."""
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings, get_settings

ROOT = Path(__file__).resolve().parents[1]


def _env_names(field_name, field):
    alias = field.validation_alias
    return [a.upper() for a in alias.choices] if alias else [field_name.upper()]


def test_every_setting_is_documented_in_env_example():
    documented = set(re.findall(r'^#?\s*([A-Z][A-Z0-9_]+)=', (ROOT / '.env.example').read_text(), re.M))
    documented |= set(re.findall(r'\b([A-Z][A-Z0-9_]+)=', (ROOT / '.env.example').read_text()))
    undocumented = [n for n, f in Settings.model_fields.items() if not set(_env_names(n, f)) & documented]
    assert undocumented == []


def test_env_example_has_no_unknown_variables():
    known = {name for n, f in Settings.model_fields.items() for name in _env_names(n, f)}
    known |= {'VITE_API_BASE_URL', 'AEGIS_DATABASE_URL'}  # read by the frontend build / ./run.sh
    declared = set(re.findall(r'^#?\s*([A-Z][A-Z0-9_]+)=', (ROOT / '.env.example').read_text(), re.M))
    assert declared - known == set()


def test_csv_lists_and_aliases(monkeypatch):
    monkeypatch.setenv('VIRUSTOTAL_API_KEY', ' a , b ,, ')
    monkeypatch.setenv('CORS_ALLOW_ORIGINS', 'http://one,http://two')
    settings = get_settings()
    assert settings.virustotal_api_keys == ['a', 'b']
    assert settings.cors_allow_origins == ['http://one', 'http://two']


def test_settings_follow_environment_changes(monkeypatch):
    monkeypatch.setenv('DEMO_MODE', '1')
    assert get_settings().demo_mode is True
    monkeypatch.setenv('DEMO_MODE', '0')
    assert get_settings().demo_mode is False


def test_non_sqlite_database_is_rejected():
    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url='postgresql://localhost/aegis')


@pytest.mark.parametrize('value, expected', [('', False), ('CHANGE_ME_LONG', False), ('s3cr3t-value', True)])
def test_admin_key_placeholder_detection(value, expected):
    assert Settings(_env_file=None, admin_api_key=value).admin_api_key_configured is expected
