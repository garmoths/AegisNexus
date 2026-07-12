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
from typing import Any, Callable, Dict, List

logger = logging.getLogger("aegis.events")

# { event_name: [handler_fn, ...] }
_listeners: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}


def subscribe(event: str, fn: Callable[[Dict[str, Any]], None]) -> None:
    """Bir event'e handler kaydet."""
    _listeners.setdefault(event, []).append(fn)
    logger.debug(f"[EventBus] subscribed: {event} → {fn.__module__}.{fn.__name__}")


def publish(event: str, payload: Dict[str, Any]) -> None:
    """
    Event yayınla. Kayıtlı tüm handler'ları sırayla çağırır.
    Bir handler exception fırlatırsa log alınır ama akış kesilmez.
    """
    handlers = _listeners.get(event, [])
    if not handlers:
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


def clear_all() -> None:
    """Test amaçlı: tüm listener'ları temizle."""
    _listeners.clear()


def registered_events() -> List[str]:
    """Kayıtlı event isimlerini döner (debug/test)."""
    return list(_listeners.keys())
