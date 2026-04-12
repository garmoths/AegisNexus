import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app.routers import breach, contact, honeypot, infra, shield, system, threat

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
    except Exception as e:
        logger.warning("Veritabanı tabloları: %s", e)
    yield


app = FastAPI(
    title="Aegis Nexus",
    description="Phishing tespiti, altyapı özeti, sızıntı sorgusu, şifre üretimi ve demo tuzak modüllerini bir araya getiren yerel güvenlik paneli.",
    lifespan=lifespan,
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "frontend" / "static"
HTML_FILE = BASE_DIR / "frontend" / "templates" / "index.html"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning("Static klasör yok: %s", STATIC_DIR)

app.include_router(threat.router)
app.include_router(system.router)
app.include_router(infra.router)
app.include_router(breach.router)
app.include_router(shield.router)
app.include_router(honeypot.router)
app.include_router(contact.router)


@app.get("/")
async def read_root():
    if HTML_FILE.exists():
        return FileResponse(HTML_FILE)
    return {
        "Hata": "index.html bulunamadı.",
        "Aranan_Yol": str(HTML_FILE),
    }
