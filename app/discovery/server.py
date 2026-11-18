"""Loopback-only operator console: no account, Redis or external provider needed."""
import ipaddress
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import engine
from app.discovery.router import operator, router


def local_operator(request: Request):
    try:
        local = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
    except (ValueError, AttributeError):
        local = False
    if not local or request.url.hostname not in ('localhost', '127.0.0.1', '::1'):
        raise HTTPException(403, 'Bu konsol yalnızca bu bilgisayardan kullanılabilir.')
    origin = request.headers.get('origin')
    if origin and origin != f'{request.url.scheme}://{request.url.netloc}':
        raise HTTPException(403, 'İstek kaynağına izin verilmedi.')
    if request.method not in ('GET', 'HEAD') and request.headers.get('x-aegis-local') != '1':
        raise HTTPException(403, 'Yerel konsol başlığı gerekli.')
    return 'local-operator'


@asynccontextmanager
async def lifespan(app):
    from app.migrations import upgrade_to_head
    upgrade_to_head(engine)
    stop = threading.Event()
    def loop():
        from app.discovery.tasks import tick
        while not stop.wait(2):
            try:
                tick()
            except Exception:
                # Leases are durable and expire; no private request data is logged.
                from app import runtime_store as store
                store.put('crawler:heartbeat', {'state': 'worker_error'}, 600)
    def certstream_loop():
        # Long-lived CT listener; only connects while discovery and a source are enabled.
        from app.discovery.certstream import run
        try:
            run(stop)
        except Exception:
            from app import runtime_store as store
            store.put('crawler:certstream:state', {'state': 'worker_error'}, 600)
    worker = threading.Thread(target=loop, name='aegis-discovery', daemon=True)
    listener = threading.Thread(target=certstream_loop, name='aegis-certstream', daemon=True)
    worker.start()
    listener.start()
    yield
    stop.set()
    worker.join(timeout=3)
    listener.join(timeout=3)


app = FastAPI(title='AegisNexus Keşif Konsolu', lifespan=lifespan)
app.dependency_overrides[operator] = local_operator
app.include_router(router)
DIST = Path(__file__).resolve().parents[2] / 'frontend-react/dist-crawler'
if (DIST / 'assets').exists():
    app.mount('/assets', StaticFiles(directory=DIST / 'assets'), name='assets')


@app.get('/health')
def health():
    return {'service': 'aegis-discovery', 'mode': 'local'}


@app.get('/{path:path}')
def frontend(path: str):
    if path.startswith('api/'):
        raise HTTPException(404)
    file = DIST / ('favicon.svg' if path == 'favicon.svg' else 'index.html')
    if not file.exists():
        raise HTTPException(503, 'Önce arayüzü derleyin.')
    return FileResponse(file)
