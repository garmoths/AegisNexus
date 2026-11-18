"""
modules/shared/events.py — AegisNexus Modüller Arası Event Bus

Senkron, in-process event yayın/dinleme sistemi.
Bir listener hata fırlatsa diğerleri çalışmaya devam eder.

Kullanım:
    from modules.shared.events import publish, subscribe

    # Abone ol (startup'ta):
    subscribe("url.phishing_confirmed", my_handler)

    # Yayınla (herhangi bir yerden):
    publish("url.phishing_confirmed", {"url": "...", "score": 95})
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("aegis.events")

# { event_name: [handler_fn, ...] }
_listeners: dict[str, list[Callable[[dict[str, Any]], None]]] = {}


def subscribe(event: str, fn: Callable[[dict[str, Any]], None]) -> None:
    """Bir event'e handler kaydet."""
    if fn not in _listeners.setdefault(event, []):
        _listeners[event].append(fn)
    logger.debug(f"[EventBus] subscribed: {event} → {fn.__module__}.{fn.__name__}")


def publish(event: str, payload: dict[str, Any], *, durable=False, strict=False) -> None:
    """
    Event yayınla. Kayıtlı tüm handler'ları sırayla çağırır.
    Bir handler exception fırlatırsa log alınır ama akış kesilmez.
    """
    if durable:
        from app.database import SessionLocal
        from app.models import EventOutbox
        with SessionLocal() as db:
            db.add(EventOutbox(event=event, payload=payload))
            db.commit()
        return
    handlers = _listeners.get(event, [])
    if not handlers:
        if strict:
            raise RuntimeError("No registered event handler")
        logger.debug(f"[EventBus] no listeners for: {event}")
        return

    logger.info(f"[EventBus] publish '{event}' → {len(handlers)} handler(s)")
    for fn in handlers:
        try:
            fn(payload)
        except Exception as exc:
            logger.error(
                f"[EventBus] handler {fn.__module__}.{fn.__name__} "
                f"failed for '{event}': {exc}",
                exc_info=True,
            )
            if strict:
                raise


def clear_all() -> None:
    """Test amaçlı: tüm listener'ları temizle."""
    _listeners.clear()


def registered_events() -> list[str]:
    """Kayıtlı event isimlerini döner (debug/test)."""
    return list(_listeners.keys())
