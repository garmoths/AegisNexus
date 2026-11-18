"""FastAPI application factory.

``app.main:app`` is what uvicorn serves (``./run.sh``). ``create_app()`` builds a
fresh instance — routers, middleware, error handlers and the React SPA — so tests
and tools can create isolated apps.
"""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import ROOT_DIR, get_settings
from app.database import engine
from app.discovery.router import router as discovery_router
from app.errors import install_error_handlers
from app.middleware.rate_limit import RateLimitMiddleware
from app.observability import RequestContextMiddleware, configure_logging
from app.routers.admin import router as admin_router
from app.routers.auth import router as auth_router
from app.routers.reports import router as reports_router
from app.routers.workspace import router as workspace_router
from modules import ai_analyzer_router, honeypot_router, phishing_detector_router, sms_guard_router
from modules.honeypot.ioc_api import router as honeypot_ioc_router

logger = logging.getLogger("aegis")

API_VERSION = "2.1.0"
REACT_BUILD_DIR = ROOT_DIR / "frontend-react" / "dist"

# (router, prefix, OpenAPI tag group) — every module mounts under /api/v2.
ROUTERS = [
    (phishing_detector_router, "/api/v2/phishing"),
    (honeypot_router, "/api/v2/honeypot"),
    (honeypot_ioc_router, "/api/v2/ioc"),
    (ai_analyzer_router, "/api/v2/ai-analyzer"),
    (sms_guard_router, "/api/v2/sms"),
    (auth_router, "/api/v2/auth"),
    (reports_router, "/api/v2/reports"),
    (admin_router, "/api/v2/admin"),
    (workspace_router, "/api/v2"),
    (discovery_router, ""),
]


@asynccontextmanager
async def lifespan(_app: FastAPI):
    from app.migrations import current_revision, head_revision
    current, head = current_revision(engine), head_revision()
    if current != head:
        logger.warning("Database schema is at %s, expected %s. Run `make migrate` (./run.sh does this).", current, head)
    else:
        logger.info("Aegis Nexus ready (schema %s)", head)

    try:
        from modules.shared.event_listeners import register_event_listeners
        register_event_listeners()
    except Exception:
        logger.warning("Event listener registration failed; continuing without in-process listeners", exc_info=True)

    yield


def _spa_file(name: str) -> Path:
    path = REACT_BUILD_DIR / name
    if not path.is_file():
        raise HTTPException(503, "Frontend henüz derlenmedi: cd frontend-react && npm run build")
    return path


def _mount_frontend(app: FastAPI) -> None:
    if REACT_BUILD_DIR.exists():
        app.mount("/react", StaticFiles(directory=str(REACT_BUILD_DIR), html=True), name="react")
        assets = REACT_BUILD_DIR / "assets"
        if assets.exists():
            app.mount("/assets", StaticFiles(directory=str(assets)), name="react-assets")
    else:
        logger.warning("React build not found at %s; only the API is served", REACT_BUILD_DIR)

    @app.get("/favicon.svg", include_in_schema=False)
    async def favicon():
        return FileResponse(_spa_file("favicon.svg"))

    @app.get("/icons.svg", include_in_schema=False)
    async def icons():
        return FileResponse(_spa_file("icons.svg"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str):
        """Client-side routes (/, /app, /admin, ...) all serve the SPA shell."""
        if full_path == "api" or full_path.startswith(("api/", "assets/")):
            raise HTTPException(404, "Endpoint bulunamadı.")
        return FileResponse(_spa_file("index.html"))


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_format)

    app = FastAPI(
        title="Aegis Nexus API",
        description=(
            "Self-hosted, modular cybersecurity platform.\n\n"
            "- **Phishing detector** — URL scanning, threat-intel aggregation, SSL/domain and visual analysis\n"
            "- **Content analysis** — SMS, e-mail (AI) and incident-report analysis\n"
            "- **IOC / honeypot** — malicious IP, domain and URL indicators, STIX export\n"
            "- **Discovery** — CertStream-driven phishing candidate crawler\n\n"
            "Authenticate with an `X-API-Key` header or the session cookie from `POST /api/v2/auth/login`. "
            "Errors share one shape: `{detail, error: {code, status, request_id}}`."
        ),
        version=API_VERSION,
        lifespan=lifespan,
    )
    install_error_handlers(app)

    # Starlette runs the last-added middleware first: request context wraps everything.
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "Retry-After"],
    )
    app.add_middleware(RequestContextMiddleware)

    for router, prefix in ROUTERS:
        app.include_router(router, prefix=prefix)

    @app.get("/health", tags=["system"], summary="Liveness probe")
    def health():
        return {"status": "ok", "service": "AegisNexus", "version": API_VERSION}

    @app.get("/ready", tags=["system"], summary="Readiness probe (databases reachable, schema current)")
    def ready():
        from sqlalchemy import text

        from app import runtime_store
        from app.migrations import is_up_to_date
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            with runtime_store.connection() as connection:
                connection.execute("SELECT 1")
        except Exception as exc:
            raise HTTPException(503, "Veri deposu hazır değil.") from exc
        if not is_up_to_date(engine):
            raise HTTPException(503, "Veritabanı şeması güncel değil; migration çalıştırın.")
        return {"status": "ready", "database": True, "runtime_store": True, "schema": "current"}

    _mount_frontend(app)
    return app


app = create_app()
