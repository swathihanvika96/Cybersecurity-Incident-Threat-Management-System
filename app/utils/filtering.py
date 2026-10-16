"""Reusable query filters."""
from datetime import date

from sqlalchemy import Select, or_

from app.core.exceptions import BadRequestError
from app.utils.date_utils import end_exclusive, start_of_day


def escape_like(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def text_search(stmt: Select, term: str | None, *columns) -> Select:
    """Case-insensitive 'contains' search across several columns (LIKE wildcards escaped)."""
    if not term or not term.strip():
        return stmt
    pattern = f"%{escape_like(term.strip())}%"
    return stmt.where(or_(*[col.ilike(pattern, escape="\\") for col in columns]))


def validate_date_range(date_from: date | None, date_to: date | None) -> None:
    if date_from and date_to and date_from > date_to:
        raise BadRequestError("date_from must not be after date_to")


def date_range(stmt: Select, column, date_from: date | None, date_to: date | None) -> Select:
    """Inclusive date range on a datetime column."""
    validate_date_range(date_from, date_to)
    if date_from:
        stmt = stmt.where(column >= start_of_day(date_from))
    if date_to:
        stmt = stmt.where(column < end_exclusive(date_to))
    return stmt
