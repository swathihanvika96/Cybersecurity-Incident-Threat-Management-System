"""Domain exceptions and the centralized exception handlers (consistent error envelope)."""
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, request_id_var

logger = get_logger("app.errors")

_STATUS_CODES = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
    405: "method_not_allowed", 409: "conflict", 422: "validation_error", 429: "too_many_requests",
}


class AppException(Exception):
    status_code = 500
    code = "internal_error"

    def __init__(self, message: str, details: Any = None, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.details = details
        if code:
            self.code = code


class BadRequestError(AppException):
    status_code, code = 400, "bad_request"


class UnauthorizedError(AppException):
    status_code, code = 401, "unauthorized"


class ForbiddenError(AppException):
    status_code, code = 403, "forbidden"


class NotFoundError(AppException):
    status_code, code = 404, "not_found"


class ConflictError(AppException):
    status_code, code = 409, "conflict"


def get_or_404(db: Session, model: type, pk: Any, label: str | None = None):
    obj = db.get(model, pk)
    if obj is None:
        raise NotFoundError(f"{label or model.__name__} {pk} not found")
    return obj


def error_body(code: str, message: str, details: Any = None) -> dict:
    return {"success": False, "error": {"code": code, "message": message, "details": details},
            "request_id": request_id_var.get()}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppException)
    async def _app_exception(_: Request, exc: AppException):
        headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else None
        return JSONResponse(error_body(exc.code, exc.message, exc.details), exc.status_code, headers=headers)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception(_: Request, exc: StarletteHTTPException):
        code = _STATUS_CODES.get(exc.status_code, "http_error")
        return JSONResponse(error_body(code, str(exc.detail)), exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def _validation_exception(_: Request, exc: RequestValidationError):
        details = [
            {"field": ".".join(str(p) for p in err["loc"] if p != "body") or "body",
             "message": err["msg"], "type": err["type"]}
            for err in exc.errors()
        ]
        return JSONResponse(error_body("validation_error", "Request validation failed", details), 422)

    @app.exception_handler(IntegrityError)
    async def _integrity_exception(_: Request, exc: IntegrityError):
        logger.warning("integrity error: %s", exc.orig)
        return JSONResponse(error_body("conflict", "The operation conflicts with existing data"), 409)

    @app.exception_handler(Exception)
    async def _unhandled_exception(_: Request, exc: Exception):
        logger.exception("unhandled error")
        return JSONResponse(error_body("internal_error", "An unexpected error occurred"), 500)
