import logging
from contextlib import asynccontextmanager
from pathlib import Path
from dotenv import load_dotenv

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine

# Load environment variables
load_dotenv()
# Modüler yapı - 5 Katmanlı Güvenlik Kalkanı
from modules import (
    phishing_detector_router,    # 01 - Phishing Detector
    honeypot_router,             # 02 - IP Avcısı
    breach_intel_router,         # 03 - Veri Radarı
    password_shield_router,      # 04 - Kriptografik Kalkan
    threat_responder_router,     # 05 - Tehdit Yanıtlayıcı
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı hazır")
    except Exception as e:
        logger.warning("Veritabanı tabloları: %s", e)
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

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "frontend" / "static"
HTML_FILE = BASE_DIR / "frontend" / "templates" / "index.html"
LLM_REPORT_FILE = BASE_DIR / "frontend" / "templates" / "llm_report.html"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning("Static klasör yok: %s", STATIC_DIR)

# 5 Modüler Router
app.include_router(phishing_detector_router, prefix="/api/v2/phishing")
app.include_router(honeypot_router, prefix="/api/v2/honeypot")
app.include_router(breach_intel_router, prefix="/api/v2/breach")
app.include_router(password_shield_router, prefix="/api/v2/shield")
app.include_router(threat_responder_router, prefix="/api/v2/responder")


@app.get("/")
async def read_root():
    if HTML_FILE.exists():
        return FileResponse(HTML_FILE)
    return {
        "Hata": "index.html bulunamadı.",
        "Aranan_Yol": str(HTML_FILE),
    }


@app.get("/llm-report")
async def llm_report_page():
    if LLM_REPORT_FILE.exists():
        return FileResponse(LLM_REPORT_FILE)
    return {
        "Hata": "llm_report.html bulunamadı.",
        "Aranan_Yol": str(LLM_REPORT_FILE),
    }
