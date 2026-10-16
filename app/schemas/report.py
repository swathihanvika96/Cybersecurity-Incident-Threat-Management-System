from typing import Any

from pydantic import Field

from app.schemas.common import DT, ORMModel


class ReportResponse(ORMModel):
    report: str = Field(description="Report identifier")
    generated_at: DT
    parameters: dict[str, Any]
    summary: dict[str, Any]
    rows: list[dict[str, Any]]
