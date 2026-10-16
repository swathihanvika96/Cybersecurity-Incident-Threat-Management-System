"""CSV export with spreadsheet-formula-injection protection."""
import csv
import io
from datetime import date, datetime
from typing import Any, Iterable

from fastapi import Response

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    text = str(value)
    # neutralise CSV/Excel formula injection from user-controlled text
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def rows_to_csv(rows: Iterable[dict], fieldnames: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _cell(row.get(key)) for key in fieldnames})
    return buffer.getvalue()


def csv_response(filename: str, rows: list[dict], fieldnames: list[str]) -> Response:
    return Response(
        content=rows_to_csv(rows, fieldnames),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
