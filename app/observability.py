"""Logging, request correlation and access logs.

* ``configure_logging()`` sets one format for the API, workers and scripts:
  human-readable text by default, one JSON object per line with ``LOG_FORMAT=json``.
* ``RequestContextMiddleware`` accepts or creates an ``X-Request-ID``, exposes it
  to every log record emitted while handling the request, echoes it in the
  response and writes one access-log line per request (method, path, status,
  duration). Query strings are never logged: they may carry user URLs.
"""
from __future__ import annotations

import contextvars
import json
import logging
import re
import sys
import time
import uuid
from datetime import UTC, datetime

from starlette.types import ASGIApp, Message, Receive, Scope, Send

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar('request_id', default='-')
_VALID_REQUEST_ID = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
access_logger = logging.getLogger('aegis.access')


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    _EXTRA = ('request_id', 'method', 'path', 'status', 'duration_ms', 'client')

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            'ts': datetime.fromtimestamp(record.created, UTC).isoformat(timespec='milliseconds'),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        for key in self._EXTRA:
            value = getattr(record, key, None)
            if value not in (None, '-'):
                payload[key] = value
        if record.exc_info:
            payload['exc'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class _StderrHandler(logging.StreamHandler):
    """Writes to whatever ``sys.stderr`` is *now* (test runners swap it)."""

    _aegis = True  # marks handlers installed by configure_logging()

    @property
    def stream(self):
        return sys.stderr

    @stream.setter
    def stream(self, _value) -> None:
        pass


def configure_logging(level: str = 'INFO', fmt: str = 'text') -> None:
    handler = _StderrHandler()
    handler.addFilter(RequestIdFilter())
    if fmt == 'json':
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-7s %(name)s [%(request_id)s] %(message)s'))
    root = logging.getLogger()
    # Replace only our own handler, so repeated calls (and pytest's caplog) keep working.
    root.handlers[:] = [h for h in root.handlers if not getattr(h, '_aegis', False)] + [handler]
    root.setLevel(level.upper())
    # Uvicorn's own access log duplicates ours and logs query strings.
    logging.getLogger('uvicorn.access').disabled = True


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


class RequestContextMiddleware:
    """Pure ASGI middleware (no response buffering, works with streaming)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope['type'] != 'http':
            await self.app(scope, receive, send)
            return
        incoming = dict(scope.get('headers') or []).get(b'x-request-id', b'').decode('latin-1')
        request_id = incoming if _VALID_REQUEST_ID.match(incoming) else new_request_id()
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        status_code = 500

        async def send_with_id(message: Message) -> None:
            nonlocal status_code
            if message['type'] == 'http.response.start':
                status_code = message['status']
                headers = list(message.get('headers', []))
                headers.append((b'x-request-id', request_id.encode()))
                message['headers'] = headers
            await send(message)

        response_started = False

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            response_started = response_started or message['type'] == 'http.response.start'
            await send_with_id(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            # Handle here (not in Starlette's outer ServerErrorMiddleware) so the
            # 500 body, header and log line still carry this request's id.
            logging.getLogger('aegis.errors').exception('Unhandled error on %s %s', scope.get('method'), scope.get('path'))
            if response_started:
                raise
            from app.errors import error_response
            response = error_response(500, 'Beklenmeyen bir sunucu hatası oluştu.')
            await response(scope, receive, send_with_id)
        finally:
            path = scope.get('path', '')
            if path.startswith('/api/') or path in ('/health', '/ready'):
                duration = round((time.perf_counter() - started) * 1000, 1)
                access_logger.info('%s %s %s %.1fms', scope.get('method'), path, status_code, duration,
                                   extra={'method': scope.get('method'), 'path': path,
                                          'status': status_code, 'duration_ms': duration})
            request_id_var.reset(token)
