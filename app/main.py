import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import engine
from app.discovery.router import router as discovery_router
from app.middleware.rate_limit import RateLimitMiddleware
from app.routers.admin import router as admin_router
from app.routers.auth import router as auth_router
from app.routers.contact import router as contact_router
from app.routers.reports import router as reports_router
from app.routers.workspace import router as workspace_router

# Çekirdek modüller
from modules import (
    ai_analyzer_router,  # 05 - AI Güvenlik Asistanı
    honeypot_router,  # 02 - IP Avcısı
    phishing_detector_router,  # 01 - Phishing Detector
    sms_guard_router,  # 07 - SMS Guard
)
from modules.honeypot.ioc_api import router as honeypot_ioc_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.migrations import current_revision, head_revision
    current, head = current_revision(engine), head_revision()
    if current != head:
        logger.warning("Database schema is at %s, expected %s. Run `make migrate` (./run.sh does this).", current, head)
    else:
        logger.info("Aegis Nexus - Güvenlik Platformu hazır (schema %s)", head)

    # Event Bus: Modüller arası listener'ları kaydet
    try:
        from modules.shared.event_listeners import register_event_listeners
        register_event_listeners()
    except Exception as e:
        logger.warning(f"[Lifespan] Event listener kayıt başarısız (devam ediliyor): {e}")

    yield


app = FastAPI(
    title="Aegis Nexus — Modüler Siber Güvenlik Platformu",
    description="""\
    Bireylerin dijital tehlikelere karşı proaktif korunmasını sağlayan
    yapay zeka ve istihbarat destekli güvenlik platformu.

    Çekirdek:
    - Phishing Tarayıcı — URL tarama, tehdit veritabanı, SSL/domain analizi
    - İçerik Analizi    — SMS, e-posta (AI) ve olay bildirimi analizi
    - IOC / Tuzak       — Zararlı IP, alan adı ve URL göstergeleri
    - Keşif             — CertStream ile otomatik phishing adayı toplama
    """,
    lifespan=lifespan,
    version="2.0.0",
)

allowed_origins = get_settings().cors_allow_origins
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
REACT_BUILD_DIR = BASE_DIR / "frontend-react" / "dist"

if REACT_BUILD_DIR.exists():
    app.mount("/react", StaticFiles(directory=str(REACT_BUILD_DIR), html=True), name="react")
    react_assets_dir = REACT_BUILD_DIR / "assets"
    if react_assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(react_assets_dir)), name="react-assets")
    logger.info("React build mount edildi: %s", REACT_BUILD_DIR)
else:
    logger.warning("React build klasörü yok: %s", REACT_BUILD_DIR)

# 8 Modüler Router
app.include_router(phishing_detector_router, prefix="/api/v2/phishing")
app.include_router(honeypot_router, prefix="/api/v2/honeypot")
app.include_router(honeypot_ioc_router, prefix="/api/v2/ioc")
app.include_router(ai_analyzer_router, prefix="/api/v2/ai-analyzer")
app.include_router(auth_router, prefix="/api/v2/auth")
app.include_router(reports_router, prefix="/api/v2/reports")
app.include_router(admin_router, prefix="/api/v2/admin")
app.include_router(sms_guard_router, prefix="/api/v2/sms")
app.include_router(contact_router)
app.include_router(workspace_router, prefix="/api/v2")
app.include_router(discovery_router)


@app.get('/health')
def health():
    return {'status': 'ok', 'service': 'AegisNexus'}


@app.get('/ready')
def ready():
    from sqlalchemy import text

    from app import runtime_store
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT id FROM users LIMIT 1'))
        with runtime_store.connection() as connection:
            connection.execute('SELECT 1')
    except Exception as exc:
        raise HTTPException(503, 'Veri deposu hazır değil.') from exc
    from app.migrations import is_up_to_date
    if not is_up_to_date(engine):
        raise HTTPException(503, 'Veritabanı şeması güncel değil; migration çalıştırın.')
    return {'status': 'ready', 'database': True, 'runtime_store': True, 'schema': 'current'}


@app.get("/app")
async def read_react_app():
    """React SPA uygulaması"""
    react_index = REACT_BUILD_DIR / "index.html"
    if react_index.exists():
        return FileResponse(react_index)
    return {"Hata": "React build index.html bulunamadı."}


@app.get("/favicon.svg")
async def read_react_favicon():
    favicon_path = REACT_BUILD_DIR / "favicon.svg"
    if favicon_path.exists():
        return FileResponse(favicon_path)
    return {"Hata": "favicon.svg bulunamadı.", "Aranan_Yol": str(favicon_path)}


@app.get("/icons.svg")
async def read_react_icons():
    icons_path = REACT_BUILD_DIR / "icons.svg"
    if icons_path.exists():
        return FileResponse(icons_path)
    return {"Hata": "icons.svg bulunamadı.", "Aranan_Yol": str(icons_path)}


@app.get("/")
async def read_root():
    react_index = REACT_BUILD_DIR / "index.html"
    if react_index.exists():
        return FileResponse(react_index)
    return {"Hata": "Ana sayfa index dosyası bulunamadı.", "Aranan_Yol": [str(react_index)]}


@app.get("/{full_path:path}")
async def spa_catch_all(full_path: str):
    """React SPA catch-all: /modules, /app gibi client-side route'ları yakalar."""
    if full_path == 'api' or full_path.startswith(('api/', 'assets/')):
        raise HTTPException(404, 'Endpoint bulunamadı.')
    react_index = REACT_BUILD_DIR / 'index.html'
    if react_index.exists():
        return FileResponse(react_index)
    raise HTTPException(503, 'Frontend henüz derlenmedi.')
