"""Operator CLI (python -m app.cli)."""
from app import cli
from app.auth import _hash_key
from app.database import SessionLocal
from app.models import APIKey, User, UserRole


def test_create_admin_creates_user_and_usable_key(capsys):
    assert cli.main(['create-admin', '--email', 'ops@example.com', '--name', 'Ops']) == 0
    raw = capsys.readouterr().out.rsplit(' ', 1)[-1].strip()
    with SessionLocal() as db:
        user = db.query(User).filter_by(email='ops@example.com').one()
        key = db.query(APIKey).filter_by(key_hash=_hash_key(raw)).one()
        assert user.role == UserRole.admin and key.role == UserRole.admin and key.user_id == user.id


def test_create_admin_promotes_existing_user():
    with SessionLocal() as db:
        db.add(User(email='promote@example.com', role=UserRole.free))
        db.commit()
    cli.create_admin('promote@example.com', None)
    with SessionLocal() as db:
        assert db.query(User).filter_by(email='promote@example.com').one().role == UserRole.admin
