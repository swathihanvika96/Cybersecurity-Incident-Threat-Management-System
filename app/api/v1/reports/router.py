from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentUser, DbSession
from app.core.constants import RiskLevel, Severity
from app.repositories.report_repository import ReportFilters
from app.schemas.common import COMMON_RESPONSES
from app.schemas.report import ReportResponse
from app.services import report_service
from app.services.report_service import ReportType
from app.utils.csv_export import csv_response

router = APIRouter(prefix="/reports", tags=["Reports"], responses=COMMON_RESPONSES)


def report_filters(
    date_from: date | None = Query(None, description="Start date (UTC). Defaults depend on the report"),
    date_to: date | None = Query(None, description="End date (UTC)"),
    severity: Annotated[list[Severity] | None, Query()] = None,
    status: Annotated[list[str] | None, Query(description="Status of the reported record type")] = None,
    risk_level: Annotated[list[RiskLevel] | None, Query()] = None,
    department_id: int | None = None,
    asset_id: int | None = None,
    analyst_id: int | None = None,
) -> ReportFilters:
    return ReportFilters(date_from=date_from, date_to=date_to, severity=[s.value for s in severity] if severity else None,
                         status=status, risk_level=[r.value for r in risk_level] if risk_level else None,
                         department_id=department_id, asset_id=asset_id, analyst_id=analyst_id)


Filters = Annotated[ReportFilters, Depends(report_filters)]
Granularity = Annotated[Literal["day", "week", "month"], Query(description="Only used by incident-resolution-trends")]


@router.get("", response_model=list[dict], summary="Available reports")
def available_reports(user: CurrentUser):
    """Reports you may run (analyst-performance needs `report:analyst_performance`)."""
    out = []
    for report_type in ReportType:
        try:
            report_service.ensure_report_access(user, report_type)
        except Exception:  # noqa: BLE001 - not permitted -> simply not listed
            continue
        out.append({"report": report_type.value, "columns": report_service.COLUMNS[report_type],
                    "csv_export": user.has_permission("report:export")})
    return out


@router.get("/{report_type}", response_model=ReportResponse, summary="Generate a report")
def generate(report_type: ReportType, db: DbSession, user: CurrentUser, filters: Filters,
             granularity: Granularity = "day"):
    """Computed from live data. Examples: `daily-incident-summary`, `vulnerability-analysis`, `sla-compliance`."""
    return report_service.generate(db, user, report_type, filters, granularity)


@router.get("/{report_type}/export", summary="Export a report as CSV",
            responses={200: {"content": {"text/csv": {}}, "description": "CSV file"}})
def export(report_type: ReportType, db: DbSession, user: CurrentUser, filters: Filters,
           granularity: Granularity = "day"):
    """Requires `report:export`. Every export is recorded in the audit log."""
    filename, rows, columns = report_service.export_csv(db, user, report_type, filters, granularity)
    return csv_response(filename, rows, columns)
