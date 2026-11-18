"""CertStream (Certificate Transparency) canlı dinleyici.

Yeni yayımlanan TLS sertifikalarının alan adlarını ücretsiz genel CT akışından
okur, süzgeçten (:mod:`app.discovery.matcher`) geçenleri aday kuyruğuna ekler.

Sınırlar:
- İnternete YALNIZCA bu WebSocket için bağlanır. Hiçbir sayfayı ziyaret/fetch
  etmez; ziyaret, skorlama ve insan onayı mevcut worker/servis akışındadır.
- Yalnızca ``settings.enabled`` açıkken ve etkin bir ``certstream`` kaynağı
  varken çalışır. Aksi halde bağlanmaz.
- Dakika başına alım tavanı + mevcut günlük bütçe + 10.000'lik kuyruk sınırı,
  CT firehose'unu üç katmanda frenler.
- API anahtarı, ücretli servis veya Redis gerektirmez.
"""
import json
import logging

import websocket

from app import runtime_store as store
from app.config import get_settings
from app.database import SessionLocal
from app.discovery import matcher, service
from app.models import CrawlSource

logger = logging.getLogger(__name__)

DEFAULT_URL = get_settings().aegis_certstream_url
RATE_PER_MIN = get_settings().aegis_certstream_rate
MAX_DOMAINS_PER_CERT = 50
RECV_TIMEOUT = 30
MAX_BACKOFF = 60
STATE_KEY = 'crawler:certstream:state'


def active_source(db):
    """Keşif açık ve etkin bir certstream kaynağı varsa o kaydı döndürür."""
    if not service.settings(db).enabled:
        return None
    return (db.query(CrawlSource)
            .filter_by(kind='certstream', enabled=True)
            .order_by(CrawlSource.id).first())


def _state(label):
    try:
        store.put(STATE_KEY, {'state': label, 'seen_at': service.now().isoformat()}, 600)
    except Exception:
        logger.debug('Ignored non-fatal error', exc_info=True)


def handle_domains(db, domains, source_row=None):
    """Bir sertifikanın alan adlarını süzüp eşleşenleri kuyruğa ekler. Eklenen sayısı."""
    minute = service.now().strftime('%Y-%m-%dT%H:%M')
    added = 0
    for raw in domains[:MAX_DOMAINS_PER_CERT]:
        domain = matcher.normalize_domain(raw)
        if not domain:
            continue
        matched, _score, reason = matcher.classify(domain)
        if not matched:
            continue
        # Dakika başına alım tavanı: reddedilen kota deneme hakkını tüketmez.
        if not store.increment('crawler:certstream:' + minute, ttl=120, limit=RATE_PER_MIN)[1]:
            break
        try:
            _, created = service.enqueue(
                db, 'https://' + domain, source='certstream',
                reason=('CT kaydı (' + reason + '); phishing doğrulanmadı')[:500])
            added += int(created)
        except ValueError:
            # Hariç tutulmuş alan veya kuyruk dolu: bu adayı atla, akışa devam et.
            continue
    if added and source_row is not None:
        source_row.added_count += added
        source_row.last_checked_at = service.now()
        source_row.last_error = None
        db.commit()
    return added


def _consume(ws, source_id, sessions):
    """Bağlantı açık olduğu sürece mesajları işler; durması gerekince True döndürür."""
    while True:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            # Boşta kalındı: hâlâ etkin mi diye bak, değilse dur.
            with sessions() as db:
                if active_source(db) is None:
                    return True
            continue
        if not raw:
            continue
        try:
            message = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if message.get('message_type') != 'certificate_update':
            continue
        leaf = ((message.get('data') or {}).get('leaf_cert') or {})
        domains = leaf.get('all_domains')
        if not isinstance(domains, list) or not domains:
            continue
        with sessions() as db:
            row = db.get(CrawlSource, source_id)
            if row is None or not row.enabled or not service.settings(db).enabled:
                return True
            handle_domains(db, domains, row)


def run(stop_event, sessions=SessionLocal, url=None):
    """Durdurulana dek dinler; bağlantı düştüğünde artan beklemeyle yeniden bağlanır."""
    url = url or DEFAULT_URL
    backoff = 1
    while not stop_event.is_set():
        with sessions() as db:
            source = active_source(db)
            source_id = source.id if source else None
        if source_id is None:
            stop_event.wait(5)
            continue
        ws = None
        try:
            ws = websocket.create_connection(
                url, timeout=RECV_TIMEOUT,
                header=['User-Agent: AegisNexus-Discovery'])
            backoff = 1
            _state('running')
            if _consume(ws, source_id, sessions):
                _state('paused')
        except Exception:
            # Hassas veri loglanmaz; genel CT sunucusu ara sıra kesilebilir.
            _state('disconnected')
            if not stop_event.is_set():
                stop_event.wait(min(backoff, MAX_BACKOFF))
                backoff = min(backoff * 2, MAX_BACKOFF)
        finally:
            if ws is not None:
                try:
                    ws.close()
                except Exception:
                    logger.debug('Ignored non-fatal error', exc_info=True)
