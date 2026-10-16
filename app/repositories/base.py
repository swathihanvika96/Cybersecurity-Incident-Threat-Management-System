"""Generic repository: thin, session-bound data access. Business rules live in services."""
from typing import Generic, TypeVar

from sqlalchemy import Select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.utils.pagination import PageParams, paginate

M = TypeVar("M")


class BaseRepository(Generic[M]):
    model: type[M]
    label: str = "Resource"

    def __init__(self, db: Session):
        self.db = db

    def get(self, pk) -> M | None:
        return self.db.get(self.model, pk)

    def require(self, pk, label: str | None = None) -> M:
        obj = self.db.get(self.model, pk)
        if obj is None:
            raise NotFoundError(f"{label or self.label} {pk} not found")
        return obj

    def add(self, obj: M) -> M:
        self.db.add(obj)
        self.db.flush()
        return obj

    def page(self, stmt: Select, params: PageParams, *, unique: bool = False) -> tuple[list[M], int]:
        return paginate(self.db, stmt, params, unique=unique)
