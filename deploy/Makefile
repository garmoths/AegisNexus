# Tek başlangıç noktası: ./run.sh (bu Makefile için: make -f deploy/Makefile up)
PROJECT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
VENV = $(PROJECT_DIR)/.venv/bin
PYTHON = $(VENV)/python

.PHONY: up down migrate logs status create-admin build-frontend setup shell
up:
	cd "$(PROJECT_DIR)" && ./run.sh
setup:
	cd "$(PROJECT_DIR)" && ./run.sh setup
down:
	cd "$(PROJECT_DIR)" && ./run.sh stop
status:
	cd "$(PROJECT_DIR)" && ./run.sh status
migrate:
	cd "$(PROJECT_DIR)" && $(VENV)/alembic upgrade head
logs:
	tail -F "$(PROJECT_DIR)/data/local/logs/api.log"
logs-worker:
	tail -F "$(PROJECT_DIR)/data/local/logs/phishing.log"
logs-beat:
	tail -F "$(PROJECT_DIR)/data/local/logs/beat.log"
build-frontend:
	cd "$(PROJECT_DIR)/frontend-react" && npm run build
shell:
	cd "$(PROJECT_DIR)" && $(PYTHON)

# ── Admin API key oluştur ──────────────────────────────
create-admin:
	cd $(PROJECT_DIR) && $(PYTHON) -c "\
from app.database import SessionLocal; \
from app.models import User, UserRole, APIKey; \
from app.auth import generate_api_key; \
db = SessionLocal(); \
email = input('Email: '); \
name = input('Ad Soyad: '); \
u = User(email=email, full_name=name, role=UserRole.admin); \
db.add(u); db.commit(); \
key, key_hash, key_prefix = generate_api_key(); \
ak = APIKey(user_id=u.id, key_hash=key_hash, key_prefix=key_prefix, role=UserRole.admin, rate_limit_tier='admin', is_active=True); \
db.add(ak); db.commit(); \
print(f'Admin API Key: {key}'); \
db.close()"
