import logging
from contextlib import asynccontextmanager
from pathlib import Path
from dotenv import load_dotenv

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.database import Base, engine
from app.routers.contact import router as contact_router
from app.routers.auth import router as auth_router
from app.routers.reports import router as reports_router
# Stats routes victim atlas router altında mount ediliyor
from app.routers.subscription import router as subscription_router
from app.routers.corporate import router as corporate_router
from app.routers.admin import router as admin_router
from app.middleware.rate_limit import RateLimitMiddleware

# Load environment variables
load_dotenv()
# Modüler yapı - 6 Katmanlı Güvenlik Kalkanı
from modules import (
    phishing_detector_router,    # 01 - Phishing Detector
    honeypot_router,             # 02 - IP Avcısı
    breach_intel_router,         # 03 - Veri Radarı
    password_shield_router,      # 04 - Kriptografik Kalkan
    ai_analyzer_router,          # 05 - AI Güvenlik Asistanı
    victim_atlas_router,         # 06 - Magduriyet Atlasi
    sms_guard_router,            # 07 - SMS Guard
)
from modules.honeypot.ioc_api import router as honeypot_ioc_router

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı hazır")
    except Exception as e:
        logger.warning("Veritabanı tabloları oluşturulamadı (devam ediliyor): %s", e)
    yield


app = FastAPI(
    title="Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı",
    description="""
    Bireylerin ve KOBİ'lerin dijital dünyadaki tehlikelere karşı 
    'reaktif' değil 'proaktif' korunmasını sağlayan yapay zeka ve istihbarat kalkanı.
    
    5 Modül:
    01. Phishing Detector - Tehdit veritabanı, URL tarama ve SSL/domain analizi
    02. Honeypot (IP Avcısı) - Dolandırıcıları tersine mühendislik ile avlama
    03. Breach Intel (Veri Radarı) - Deep Web sızıntı takibi
    04. Password Shield (Kriptografik Kalkan) - Yüz yıllar süren şifreler
    05. Threat Responder (Tehdit Yanıtlayıcı) - IOC'leri operatörlere uyarı
    """,
    lifespan=lifespan,
    version="2.0.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOW_ORIGINS",
        "https://modules.aegisnexus.dev,https://aegisnexus.dev,http://localhost:5173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "frontend" / "static"
HTML_FILE = BASE_DIR / "frontend" / "templates" / "index.html"
LLM_REPORT_FILE = BASE_DIR / "frontend" / "templates" / "llm_report.html"
AI_ANALYZER_DEMO_FILE = BASE_DIR / "frontend" / "templates" / "ai-analyzer-demo.html"
DASHBOARD_FILE = BASE_DIR / "frontend" / "templates" / "dashboard.html"

REACT_BUILD_DIR = BASE_DIR / "frontend-react" / "dist"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning("Static klasör yok: %s", STATIC_DIR)

if REACT_BUILD_DIR.exists():
    app.mount("/react", StaticFiles(directory=str(REACT_BUILD_DIR), html=True), name="react")
    react_assets_dir = REACT_BUILD_DIR / "assets"
    if react_assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(react_assets_dir)), name="react-assets")
    logger.info("React build mount edildi: %s", REACT_BUILD_DIR)
else:
    logger.warning("React build klasörü yok: %s", REACT_BUILD_DIR)

# 6 Modüler Router
app.include_router(phishing_detector_router, prefix="/api/v2/phishing")
app.include_router(honeypot_router, prefix="/api/v2/honeypot")
app.include_router(honeypot_ioc_router, prefix="/api/v2/ioc")
app.include_router(breach_intel_router, prefix="/api/v2/breach")
app.include_router(password_shield_router, prefix="/api/v2/shield")
app.include_router(ai_analyzer_router, prefix="/api/v2/ai-analyzer")
app.include_router(victim_atlas_router, prefix="/api/v2/victim-atlas")
app.include_router(auth_router, prefix="/api/v2/auth")
app.include_router(reports_router, prefix="/api/v2/reports")
app.include_router(subscription_router, prefix="/api/v2/subscription")
app.include_router(corporate_router, prefix="/api/v2/corporate")
app.include_router(admin_router, prefix="/api/v2/admin")
app.include_router(sms_guard_router, prefix="/api/v2/sms")
app.include_router(contact_router)


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
    if HTML_FILE.exists():
        return FileResponse(HTML_FILE)
    return {
        "Hata": "Ana sayfa index dosyası bulunamadı.",
        "Aranan_Yol": [str(react_index), str(HTML_FILE)],
    }


@app.get("/llm-report")
async def llm_report_page():
    if LLM_REPORT_FILE.exists():
        return FileResponse(LLM_REPORT_FILE)
    return {
        "Hata": "llm_report.html bulunamadı.",
        "Aranan_Yol": str(LLM_REPORT_FILE),
    }


@app.get("/ai-analyzer-demo")
async def ai_analyzer_demo_page():
    if AI_ANALYZER_DEMO_FILE.exists():
        return FileResponse(AI_ANALYZER_DEMO_FILE)
    return {
        "Hata": "ai-analyzer-demo.html bulunamadı.",
        "Aranan_Yol": str(AI_ANALYZER_DEMO_FILE),
    }


@app.get("/dashboard")
async def dashboard_page():
    if DASHBOARD_FILE.exists():
        return FileResponse(DASHBOARD_FILE)
    return {
        "Hata": "dashboard.html bulunamadı.",
        "Aranan_Yol": str(DASHBOARD_FILE),
    }
