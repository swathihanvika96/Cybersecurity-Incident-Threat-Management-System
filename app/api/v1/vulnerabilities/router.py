from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P, VulnerabilitySeverity, VulnerabilityStatus
from app.models import User, Vulnerability
from app.repositories import vulnerability_repository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.vulnerability import (
    AssetVulnerabilityOut,
    MapAssets,
    VulnerabilityCreate,
    VulnerabilityHistoryOut,
    VulnerabilityOut,
    VulnerabilityStatusUpdate,
    VulnerabilityUpdate,
)
from app.services import vulnerability_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page
from app.utils.sorting import apply_sorting

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.VULN_READ))]
Writer = Annotated[User, Depends(require_permission(P.VULN_WRITE))]


@router.post("", response_model=VulnerabilityOut, status_code=status.HTTP_201_CREATED,
             summary="Record a vulnerability (optionally mapped to affected assets)")
def create_vulnerability(data: VulnerabilityCreate, db: DbSession, actor: Writer):
    """Severity is derived from the CVSS v3 band when omitted; the remediation deadline defaults by severity.
    Mapping assets immediately calculates the risk score of every (asset, vulnerability) pair."""
    return vulnerability_service.create(db, actor, data)


@router.get("", response_model=Page[VulnerabilityOut], summary="Search and filter vulnerabilities")
def list_vulnerabilities(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    q: str | None = Query(None, description="Search title, CVE, reference or description"),
    severity: Annotated[list[VulnerabilitySeverity] | None, Query()] = None,
    status: Annotated[list[VulnerabilityStatus] | None, Query()] = None,
    cve_id: str | None = Query(None, description="Exact CVE id"),
    asset_id: int | None = Query(None, description="Only vulnerabilities mapped to this asset"),
    overdue: bool | None = Query(None, description="Remediation deadline passed while unresolved"),
    deadline_from: date | None = None,
    deadline_to: date | None = None,
    sort_by: str | None = Query(None, description="created_at | cvss_score | severity | remediation_deadline | status | title"),
    sort_order: Literal["asc", "desc"] = "desc",
):
    repo = VulnerabilityRepository(db)
    stmt = repo.filtered(q=q, severity=severity, status=status, cve_id=cve_id, asset_id=asset_id, overdue=overdue,
                         deadline_from=deadline_from, deadline_to=deadline_to)
    stmt = apply_sorting(stmt, vulnerability_repository.SORT_MAP, sort_by, sort_order, "created_at",
                         tiebreak=Vulnerability.id)
    items, total = repo.page(stmt, params)
    return make_page(items, total, params)


@router.get("/{vulnerability_id}", response_model=VulnerabilityOut, summary="Get a vulnerability")
def get_vulnerability(vulnerability_id: int, db: DbSession, _: Reader):
    return VulnerabilityRepository(db).require(vulnerability_id)


@router.patch("/{vulnerability_id}", response_model=VulnerabilityOut, summary="Update a vulnerability")
def update_vulnerability(vulnerability_id: int, data: VulnerabilityUpdate, db: DbSession, actor: Writer):
    """Changing the CVSS score or severity re-calculates the linked risk assessments."""
    return vulnerability_service.update(db, actor, vulnerability_id, data)


@router.patch("/{vulnerability_id}/status", response_model=VulnerabilityOut, summary="Change the status")
def set_status(vulnerability_id: int, data: VulnerabilityStatusUpdate, db: DbSession, actor: Writer):
    return vulnerability_service.set_status(db, actor, vulnerability_id, data.status, data.comment)


@router.post("/{vulnerability_id}/assets", response_model=list[AssetVulnerabilityOut],
             status_code=status.HTTP_201_CREATED, summary="Map the vulnerability to affected assets")
def map_assets(vulnerability_id: int, data: MapAssets, db: DbSession, actor: Writer):
    return vulnerability_service.map_assets(db, actor, vulnerability_id, data.asset_ids, data.notes)


@router.get("/{vulnerability_id}/assets", response_model=Page[AssetVulnerabilityOut], summary="Affected assets")
def affected_assets(vulnerability_id: int, db: DbSession, _: Reader,
                    params: Annotated[PageParams, Depends(page_params)]):
    repo = VulnerabilityRepository(db)
    repo.require(vulnerability_id)
    items, total = repo.page(repo.mappings_stmt(vulnerability_id=vulnerability_id), params)
    return make_page(items, total, params)


@router.get("/{vulnerability_id}/history", response_model=Page[VulnerabilityHistoryOut],
            summary="Vulnerability history")
def history(vulnerability_id: int, db: DbSession, _: Reader, params: Annotated[PageParams, Depends(page_params)]):
    repo = VulnerabilityRepository(db)
    repo.require(vulnerability_id)
    items, total = repo.page(repo.history_stmt(vulnerability_id), params)
    return make_page(items, total, params)
