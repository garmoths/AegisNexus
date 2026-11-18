"""Typed application settings — the single place that reads the environment.

Values come from process environment variables first, then from ``.env`` in the
project root (override the file with ``AEGIS_ENV_FILE``; set it to an empty string
to disable it, as the test-suite does). Every variable is optional: a missing API
key simply disables the integration that needs it.

Use ``get_settings()`` everywhere instead of ``os.getenv``. The instance is cached
and rebuilt only when ``os.environ`` changes, so tests and the local launcher can
adjust variables at runtime without stale values.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / 'data'

CsvList = Annotated[list[str], NoDecode]


def _env_file() -> str | None:
    configured = os.environ.get('AEGIS_ENV_FILE')
    if configured is None:
        return str(ROOT_DIR / '.env')
    return configured or None


class Settings(BaseSettings):
    # env_ignore_empty: ``FOO=`` behaves like unset, so an empty FOO_KEYS falls back to FOO_KEY.
    model_config = SettingsConfigDict(extra='ignore', case_sensitive=False, env_file_encoding='utf-8', env_ignore_empty=True)

    # ── Application ───────────────────────────────────────────────────────
    demo_mode: bool = False
    cors_allow_origins: CsvList = ['http://localhost:8000', 'http://localhost:5173']
    log_level: str = 'INFO'
    log_format: str = Field('text', description='"text" for humans, "json" for log shippers')

    # ── Storage ───────────────────────────────────────────────────────────
    database_url: str = f'sqlite:///{DATA_DIR / "aegis.db"}'
    runtime_db_path: Path = DATA_DIR / 'runtime.db'
    pdf_output_dir: Path = DATA_DIR / 'reports'
    pdf_font_path: str = ''
    crawler_data_dir: Path = DATA_DIR / 'crawler'

    # ── Celery ────────────────────────────────────────────────────────────
    celery_broker_url: str = 'redis://127.0.0.1:6379/0'
    celery_result_backend: str = ''
    celery_timezone: str = 'Europe/Istanbul'
    celery_ioc_interval_seconds: int = 3600
    celery_phishing_interval_seconds: int = 3600
    celery_ioc_sources: CsvList = ['abuse_urlhaus', 'abuse_phishtank']
    celery_ioc_limit_per_source: int = 1000
    celery_worker_type: str = ''
    celery_preload_models: bool = False

    # ── Account recovery mail (STARTTLS) ──────────────────────────────────
    smtp_host: str = ''
    smtp_port: int = 587
    smtp_from: str = ''
    smtp_user: str = ''
    smtp_password: str = ''

    # ── Operator alerts (phishing detector) ───────────────────────────────
    slack_webhook_url: str = ''
    alert_email_from: str = Field('alerts@example.com', validation_alias=AliasChoices('ALERT_EMAIL_FROM', 'EMAIL_FROM'))
    alert_email_password: str = Field('', validation_alias=AliasChoices('ALERT_EMAIL_PASSWORD', 'EMAIL_PASSWORD'))
    alert_smtp_server: str = Field('smtp.gmail.com', validation_alias=AliasChoices('ALERT_SMTP_SERVER', 'SMTP_SERVER'))
    admin_email: str = 'admin@example.com'

    # ── AI providers ──────────────────────────────────────────────────────
    gemini_api_key: str = ''
    gemini_model: str = 'gemini-2.0-flash'
    groq_api_key: str = ''
    groq_base_url: str = 'https://api.groq.com/openai/v1'
    groq_model: str = 'llama-3.3-70b-versatile'
    ai_model: str = 'meta-llama/llama-4-scout-17b-16e-instruct'
    ai_skip_threshold: int = 50
    ai_daily_limit: int = 14000

    # ── Threat-intelligence API keys (comma-separated lists rotate) ───────
    virustotal_api_keys: CsvList = Field([], validation_alias=AliasChoices('VIRUSTOTAL_API_KEYS', 'VIRUSTOTAL_API_KEY'))
    google_safe_browsing_keys: CsvList = Field([], validation_alias=AliasChoices('GOOGLE_SAFE_BROWSING_KEYS', 'GOOGLE_SAFE_BROWSING_KEY'))
    abuseipdb_api_keys: CsvList = Field([], validation_alias=AliasChoices('ABUSEIPDB_API_KEYS', 'ABUSEIPDB_API_KEY'))
    abuse_ch_api_keys: CsvList = Field([], validation_alias=AliasChoices('ABUSE_API_KEYS', 'ABUSE_API_KEY'))
    urlhaus_api_keys: CsvList = Field([], validation_alias=AliasChoices('URLHAUS_API_KEYS', 'URLHAUS_API_KEY'))
    phishtank_api_keys: CsvList = []
    phishtank_app_key: str = ''
    phishtank_username: str = 'aegisnexus'
    alienvault_otx_api_key: str = ''
    spamhaus_username: str = ''
    spamhaus_password: str = ''
    kaggle_username: str = ''
    kaggle_key: str = ''
    kaggle_api_token: str = ''

    # ── Feed collection limits ────────────────────────────────────────────
    phishing_github_feeds: str = ''
    phishing_openphish_limit: int = 20000
    phishing_urlhaus_limit: int = 3000
    phishing_urlhaus_phishing_only: bool = False
    phishing_kaggle_dataset: str = 'taruntiwarihp/phishing-site-urls'
    phishing_kaggle_limit: int = 100000
    phishing_otx_limit: int = 200
    phishing_threatfox_limit: int = 500
    certstream_ws_url: str = 'wss://certstream.calidog.io/'
    certstream_max_urls: int = 500
    certstream_duration_seconds: int = 20
    certstream_keywords: str = ''
    certstream_allow_generic_domains: bool = False

    # ── Scanner tuning ────────────────────────────────────────────────────
    phishing_scoring_model: str = 'rule-based-v1'
    threat_cache_max_rows: int = 1000
    threat_scan_events_max_rows: int = 5000
    scan_cache_ttl: int = 21600
    phishing_job_ttl: int = 3600
    threat_intel_workers: int = 5
    playwright_pool_size: int = 1
    screenshot_network_idle: bool = True
    screenshot_network_idle_timeout_ms: int = 12000
    phash_threshold: int = 8
    easyocr_model_dir: str = str(ROOT_DIR / '.easyocr_models')
    aegis_chromium_path: str = ''

    # ── Discovery crawler (CertStream matcher) ────────────────────────────
    aegis_certstream_url: str = 'wss://certstream.calidog.io'
    aegis_certstream_rate: int = Field(20, ge=1)
    aegis_certstream_threshold: int = 40

    @field_validator('*', mode='before')
    @classmethod
    def _split_csv(cls, value: Any, info) -> Any:
        field = cls.model_fields[info.field_name]
        if field.annotation == list[str] and isinstance(value, str):
            return [item.strip() for item in value.replace('\n', ',').split(',') if item.strip()]
        return value

    @field_validator('database_url')
    @classmethod
    def _sqlite_only(cls, value: str) -> str:
        if not value.startswith('sqlite:///'):
            raise ValueError('DATABASE_URL must be a SQLite file URL, e.g. sqlite:///./data/aegis.db')
        return value

    # ── Derived values ────────────────────────────────────────────────────
    @property
    def recovery_mail_enabled(self) -> bool:
        return bool(self.smtp_host and self.smtp_from)

    @property
    def result_backend(self) -> str:
        if self.celery_result_backend:
            return self.celery_result_backend
        if self.celery_broker_url.startswith(('amqp:', 'amqps:', 'memory:')):
            return 'rpc://'
        return 'redis://127.0.0.1:6379/1'


_cached: tuple[int, Settings] | None = None


def get_settings() -> Settings:
    """Return the current settings, rebuilding them only if the environment changed."""
    global _cached
    fingerprint = hash(frozenset(os.environ.items()))
    if _cached is None or _cached[0] != fingerprint:
        _cached = (fingerprint, Settings(_env_file=_env_file()))
    return _cached[1]
