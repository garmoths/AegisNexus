"""add victim atlas and auth tables

Revision ID: 001
Revises:
Create Date: 2026-04-30

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Victim Atlas tabloları (SQLite'dan taşındı) ---
    op.create_table(
        'sources_registry',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('name', sa.String(200), unique=True, nullable=False),
        sa.Column('base_url', sa.String(500), nullable=False),
        sa.Column('trust_tier', sa.String(20), nullable=False),
        sa.Column('enabled', sa.Boolean(), default=True),
        sa.Column('last_success_at', sa.DateTime(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_sources_registry_id', 'sources_registry', ['id'])

    op.create_table(
        'raw_documents',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('source_id', sa.Integer(), sa.ForeignKey('sources_registry.id'), nullable=False),
        sa.Column('external_id', sa.String(200), nullable=False),
        sa.Column('url', sa.String(2000), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('fetched_at', sa.DateTime(), nullable=True),
        sa.Column('raw_text', sa.Text(), nullable=False),
        sa.Column('lang', sa.String(10), nullable=True),
        sa.Column('hash', sa.String(64), unique=True, nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_raw_documents_id', 'raw_documents', ['id'])
    op.create_index('ix_raw_source_external', 'raw_documents', ['source_id', 'external_id'], unique=True)
    op.create_index('ix_raw_source_published', 'raw_documents', ['source_id', 'published_at'])

    op.create_table(
        'victim_cases',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('case_slug', sa.String(200), unique=True, nullable=False),
        sa.Column('case_title', sa.String(500), nullable=False),
        sa.Column('incident_period_start', sa.DateTime(), nullable=True),
        sa.Column('incident_period_end', sa.DateTime(), nullable=True),
        sa.Column('attack_method', sa.String(50), nullable=False),
        sa.Column('loss_type', sa.String(50), nullable=False),
        sa.Column('target_platform', sa.String(50), nullable=False),
        sa.Column('critical_warning', sa.Text(), nullable=False),
        sa.Column('narrative_summary', sa.Text(), nullable=False),
        sa.Column('defense_steps_json', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Integer(), nullable=False),
        sa.Column('severity_score', sa.Integer(), nullable=False),
        sa.Column('region', sa.String(100), nullable=True),
        sa.Column('is_hot', sa.Boolean(), default=True),
        sa.Column('is_published', sa.Boolean(), default=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_victim_cases_id', 'victim_cases', ['id'])
    op.create_index('ix_cases_attack_method', 'victim_cases', ['attack_method'])
    op.create_index('ix_cases_loss_type', 'victim_cases', ['loss_type'])
    op.create_index('ix_cases_last_seen', 'victim_cases', ['last_seen'])
    op.create_index('ix_cases_hot', 'victim_cases', ['is_hot'])

    op.create_table(
        'victim_case_evidence',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('case_id', sa.Integer(), sa.ForeignKey('victim_cases.id'), nullable=False),
        sa.Column('raw_document_id', sa.Integer(), sa.ForeignKey('raw_documents.id'), nullable=False),
        sa.Column('evidence_snippet', sa.Text(), nullable=False),
        sa.Column('evidence_weight', sa.Float(), default=1.0),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_evidence_unique', 'victim_case_evidence', ['case_id', 'raw_document_id'], unique=True)

    op.create_table(
        'ingest_runs',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('documents_fetched', sa.Integer(), default=0),
        sa.Column('cases_created', sa.Integer(), default=0),
        sa.Column('cases_updated', sa.Integer(), default=0),
        sa.Column('errors_json', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )

    # --- Auth & User tabloları ---
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False),
        sa.Column('full_name', sa.String(256), nullable=True),
        sa.Column('role', sa.Enum('free', 'premium', 'corporate', 'admin', name='userrole'), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_users_id', 'users', ['id'])
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('key_hash', sa.String(64), unique=True, nullable=False),
        sa.Column('key_prefix', sa.String(8), nullable=False),
        sa.Column('label', sa.String(100), nullable=True),
        sa.Column('role', sa.Enum('free', 'premium', 'corporate', 'admin', name='userrole'), nullable=False),
        sa.Column('rate_limit_tier', sa.String(20), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_api_keys_id', 'api_keys', ['id'])
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True)

    op.create_table(
        'case_tags',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('case_id', sa.Integer(), sa.ForeignKey('victim_cases.id'), nullable=False),
        sa.Column('tag', sa.String(100), nullable=False),
    )
    op.create_index('ix_case_tag_unique', 'case_tags', ['case_id', 'tag'], unique=True)

    op.create_table(
        'user_reports',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('case_id', sa.Integer(), sa.ForeignKey('victim_cases.id'), nullable=True),
        sa.Column('user_description', sa.Text(), nullable=False),
        sa.Column('ai_analysis', sa.JSON(), nullable=True),
        sa.Column('protection_plan', sa.Text(), nullable=True),
        sa.Column('pdf_path', sa.String(500), nullable=True),
        sa.Column('report_quota_month', sa.String(7), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_user_reports_id', 'user_reports', ['id'])

    op.create_table(
        'subscriptions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('plan', sa.Enum('free', 'premium', 'corporate', 'admin', name='userrole'), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('payment_ref', sa.String(255), nullable=True),
    )

    op.create_table(
        'alert_subscriptions',
        sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('region', sa.String(100), nullable=True),
        sa.Column('attack_method', sa.String(50), nullable=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('alert_subscriptions')
    op.drop_table('subscriptions')
    op.drop_table('user_reports')
    op.drop_table('case_tags')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('ingest_runs')
    op.drop_table('victim_case_evidence')
    op.drop_table('victim_cases')
    op.drop_table('raw_documents')
    op.drop_table('sources_registry')

    # Enum type cleanup
    op.execute("DROP TYPE IF EXISTS userrole")
