"""Whitelist-based sorting (prevents ordering by arbitrary/unindexed columns)."""
from typing import Literal

from typing import Any

from sqlalchemy import Select, case

from app.core.exceptions import BadRequestError

SortOrder = Literal["asc", "desc"]


def rank_case(column, ranks: dict[str, int]):
    """ORDER BY helper: sort an enum-like string column by a logical rank instead of alphabetically."""
    return case(ranks, value=column, else_=-1)


def apply_sorting(
    stmt: Select,
    sort_map: dict[str, Any],
    sort_by: str | None,
    sort_order: str,
    default: str,
    tiebreak: Any | None = None,
) -> Select:
    key = sort_by or default
    column = sort_map.get(key)
    if column is None:
        raise BadRequestError(f"Unsupported sort field '{key}'", details={"allowed": sorted(sort_map)})
    descending = sort_order == "desc"
    stmt = stmt.order_by(column.desc() if descending else column.asc())
    if tiebreak is not None:
        stmt = stmt.order_by(tiebreak.desc() if descending else tiebreak.asc())
    return stmt
