"""Pagination helpers."""
from dataclasses import dataclass

from fastapi import Query
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session


@dataclass
class PageParams:
    page: int = 1
    size: int = 20

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.size


def page_params(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    size: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
) -> PageParams:
    return PageParams(page=page, size=size)


def count_rows(db: Session, stmt: Select) -> int:
    return db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0


def paginate(db: Session, stmt: Select, params: PageParams, *, unique: bool = False) -> tuple[list, int]:
    """Runs a COUNT and a LIMIT/OFFSET query. Returns (items, total)."""
    total = count_rows(db, stmt)
    result = db.scalars(stmt.limit(params.size).offset(params.offset))
    return list(result.unique() if unique else result), total
