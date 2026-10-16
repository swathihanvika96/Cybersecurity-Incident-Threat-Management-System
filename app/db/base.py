"""Declarative base, shared mixins and column types."""
from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from app.utils.date_utils import utcnow


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class EnumString(TypeDecorator):
    """VARCHAR column that accepts Enum members or plain strings (portable across SQLite/MySQL/PostgreSQL)."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if isinstance(value, Enum):
            return str(value.value)
        return value
