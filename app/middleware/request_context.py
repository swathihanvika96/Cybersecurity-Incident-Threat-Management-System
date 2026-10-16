"""Attaches a request id and client IP to the logging/audit context."""
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.core.logging import client_ip_var, request_id_var


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        forwarded = request.headers.get("X-Forwarded-For")
        client_ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else None)
        rid_token = request_id_var.set(request_id)
        ip_token = client_ip_var.set(client_ip)
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(rid_token)
            client_ip_var.reset(ip_token)
        response.headers["X-Request-ID"] = request_id
        return response
