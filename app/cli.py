"""Operator commands: ``python -m app.cli <command>``.

Commands
--------
create-admin   Create (or promote) an admin user and print a new API key once.
"""
import argparse
import sys

from app.auth import generate_api_key
from app.database import SessionLocal
from app.models import APIKey, User, UserRole


def create_admin(email: str, full_name: str | None) -> str:
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=email).first()
        if user is None:
            user = User(email=email, full_name=full_name, role=UserRole.admin)
            db.add(user)
            db.flush()
        else:
            user.role = UserRole.admin
        raw, key_hash, prefix = generate_api_key()
        db.add(APIKey(user_id=user.id, key_hash=key_hash, key_prefix=prefix, label='cli-admin',
                      role=UserRole.admin, rate_limit_tier='admin', is_active=True))
        db.commit()
        return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='python -m app.cli')
    commands = parser.add_subparsers(dest='command', required=True)
    admin = commands.add_parser('create-admin', help='create or promote an admin user')
    admin.add_argument('--email')
    admin.add_argument('--name')
    args = parser.parse_args(argv)

    if args.command == 'create-admin':
        email = args.email or input('Email: ').strip()
        name = args.name if args.name is not None else (input('Full name (optional): ').strip() or None)
        key = create_admin(email, name)
        sys.stdout.write(f'Admin API key (shown once): {key}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
