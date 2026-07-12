# AegisNexus Makefile
# Sunucuda: make up | make down | make migrate | make logs | make shell

PROJECT_DIR = /var/www/aegisnexus
VENV = $(PROJECT_DIR)/venv/bin
PYTHON = $(VENV)/python
CELERY = $(VENV)/celery
UVICORN = $(VENV)/uvicorn

.PHONY: up down restart migrate logs shell status create-admin build-frontend

# ── Servisleri başlat ──────────────────────────────────
up:
	sudo systemctl start aegis-api
	sudo systemctl start aegis-celery-worker
	sudo systemctl start aegis-celery-beat
	sudo systemctl start aegis-celery-honeypot
	sudo systemctl start nginx
	@echo "✅ Tüm servisler başlatıldı"

# ── Servisleri durdur ──────────────────────────────────
down:
	sudo systemctl stop aegis-celery-beat
	sudo systemctl stop aegis-celery-worker
	sudo systemctl stop aegis-celery-honeypot
	sudo systemctl stop aegis-api
	sudo systemctl stop nginx
	@echo "⏹ Tüm servisler durduruldu"

# ── Servisleri yeniden başlat ──────────────────────────
restart:
	sudo systemctl restart aegis-api
	sudo systemctl restart aegis-celery-worker
	sudo systemctl restart aegis-celery-beat
	sudo systemctl restart aegis-celery-honeypot
	sudo systemctl restart nginx
	@echo "🔄 Tüm servisler yeniden başlatıldı"

# ── Alembic migration ──────────────────────────────────
migrate:
	cd $(PROJECT_DIR) && $(VENV)/alembic upgrade head
	@echo "✅ Migration tamamlandı"

# ── SQLite → PostgreSQL veri taşıma ────────────────────
migrate-sqlite:
	cd $(PROJECT_DIR) && $(PYTHON) scripts/migrate_sqlite_to_pg.py
	@echo "✅ SQLite → PostgreSQL taşıma tamamlandı"

# ── Logları izle ──────────────────────────────────────
logs:
	sudo journalctl -u aegis-api -f

logs-worker:
	sudo journalctl -u aegis-celery-worker -f

logs-beat:
	sudo journalctl -u aegis-celery-beat -f

# ── Status ─────────────────────────────────────────────
status:
	@systemctl is-active aegis-api aegis-celery-worker aegis-celery-beat aegis-celery-honeypot nginx 2>/dev/null | paste -sd' ' - ; \
	echo "---"; \
	systemctl status aegis-api --no-pager -l 2>/dev/null | head -5

# ── Admin API key oluştur ──────────────────────────────
create-admin:
	cd $(PROJECT_DIR) && $(PYTHON) -c "\
from app.database import SessionLocal; \
from app.models import User, UserRole, APIKey; \
import secrets; \
db = SessionLocal(); \
email = input('Email: '); \
name = input('Ad Soyad: '); \
u = User(email=email, full_name=name, role=UserRole.admin); \
db.add(u); db.commit(); \
key = secrets.token_urlsafe(32); \
ak = APIKey(user_id=u.id, key_hash=__import__('hashlib').sha256(key.encode()).hexdigest(), role=UserRole.admin, is_active=True); \
db.add(ak); db.commit(); \
print(f'Admin API Key: {key}'); \
db.close()"

# ── Frontend build ─────────────────────────────────────
build-frontend:
	cd $(PROJECT_DIR)/frontend-react && npm run build
	@echo "✅ Frontend build tamamlandı → dist/"

# ── Shell ──────────────────────────────────────────────
shell:
	cd $(PROJECT_DIR) && $(PYTHON) -m bpython || $(PYTHON) -m ipython || $(PYTHON)

# ── Pull + deploy ──────────────────────────────────────
deploy:
	cd $(PROJECT_DIR) && git pull origin main
	$(MAKE) migrate
	$(MAKE) build-frontend
	$(MAKE) restart
	@echo "🚀 Deploy tamamlandı"
