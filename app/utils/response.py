"""Consistent response builders.

Success: resource body (or `Page[T]` for lists, `MessageResponse` for actions).
Errors : {"success": false, "error": {"code", "message", "details"}, "request_id"} (see core.exceptions).
"""
import math

from app.utils.pagination import PageParams


def make_page(items: list, total: int, params: PageParams) -> dict:
    return {
        "items": items,
        "total": total,
        "page": params.page,
        "size": params.size,
        "pages": math.ceil(total / params.size) if total else 0,
    }


def message(text: str) -> dict:
    return {"message": text}
