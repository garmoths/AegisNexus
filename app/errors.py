"""One error shape for every API response.

    {"detail": "<human-readable message>",
     "error": {"code": "not_found", "status": 404, "request_id": "9f2c..."}}

``detail`` stays FastAPI-compatible (string, or the validation-error list for
422) so existing clients keep working; ``error.code`` is a stable,
machine-readable identifier and ``error.request_id`` matches the
``X-Request-ID`` response header and the server logs.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.observability import request_id_var

ERROR_CODES = {
    400: 'bad_request', 401: 'unauthorized', 403: 'forbidden', 404: 'not_found', 405: 'method_not_allowed',
    409: 'conflict', 413: 'payload_too_large', 422: 'validation_error', 429: 'rate_limited',
    500: 'internal_error', 502: 'bad_gateway', 503: 'service_unavailable', 504: 'gateway_timeout',
}


class AppError(Exception):
    """Raised by service code; mapped to the standard envelope without HTTP imports in services."""

    status = 500
    code: str | None = None

    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code


class BadRequest(AppError):
    status = 400


class NotFound(AppError):
    status = 404


class Conflict(AppError):
    status = 409


class Unprocessable(AppError):
    status = 422


class ServiceUnavailable(AppError):
    status = 503


class UpstreamError(AppError):
    status = 502


def error_body(status: int, detail: Any, code: str | None = None) -> dict[str, Any]:
    return {'detail': detail,
            'error': {'code': code or ERROR_CODES.get(status, 'error'), 'status': status, 'request_id': request_id_var.get()}}


def error_response(status: int, detail: Any, code: str | None = None, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse(jsonable_encoder(error_body(status, detail, code)), status_code=status, headers=headers)


async def _http_exception(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
    return error_response(exc.status_code, exc.detail, headers=getattr(exc, 'headers', None))


async def _app_error(_request: Request, exc: AppError) -> JSONResponse:
    return error_response(exc.status, exc.message, exc.code)


async def _validation_exception(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return error_response(422, exc.errors())


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, _validation_exception)  # type: ignore[arg-type]
    app.add_exception_handler(AppError, _app_error)  # type: ignore[arg-type]
    # Unhandled exceptions become this same 500 shape in RequestContextMiddleware.
