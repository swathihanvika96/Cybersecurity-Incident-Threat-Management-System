"""Date/time helpers. All datetimes are stored as naive UTC and serialized as UTC ('Z')."""
from datetime import date, datetime, timedelta, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_naive_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def attach_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def start_of_day(value: date) -> datetime:
    return datetime(value.year, value.month, value.day)


def end_exclusive(value: date) -> datetime:
    return start_of_day(value) + timedelta(days=1)


def week_start(value: date) -> date:
    return value - timedelta(days=value.weekday())


def minutes_between(start: datetime, end: datetime) -> float:
    return round((end - start).total_seconds() / 60.0, 2)


def make_reference(prefix: str, pk: int, when: datetime | None = None) -> str:
    return f"{prefix}-{(when or utcnow()).year}-{pk:06d}"
