from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import DbSession, require_permission
from app.core.constants import P, RiskLevel
from app.models import User
from app.repositories.risk_repository import RiskRepository
from app.schemas.common import COMMON_RESPONSES, Page
from app.schemas.risk_acceptance import RiskAcceptanceCreate, RiskAcceptanceOut, RiskAcceptanceRevoke
from app.schemas.risk_assessment import (
    AssetRiskOut,
    RiskAssessmentOut,
    RiskCalculateRequest,
    RiskCalculateResult,
    RiskFormulaOut,
)
from app.services import risk_service
from app.utils.pagination import PageParams, page_params
from app.utils.response import make_page

router = APIRouter(prefix="/risks", tags=["Risk Assessment"], responses=COMMON_RESPONSES)

Reader = Annotated[User, Depends(require_permission(P.RISK_READ))]
Writer = Annotated[User, Depends(require_permission(P.RISK_WRITE))]
Acceptor = Annotated[User, Depends(require_permission(P.RISK_ACCEPT))]


@router.get("/formula", response_model=RiskFormulaOut, summary="The documented risk-scoring formula")
def formula(_: Reader):
    """Returns the formula, weights, level bands and worked examples (version `v1`)."""
    return risk_service.formula_description()


@router.post("/calculate", response_model=RiskCalculateResult, summary="Calculate / re-calculate risk scores")
def calculate(db: DbSession, actor: Writer, data: RiskCalculateRequest | None = None):
    """Scores every open (asset, vulnerability) pair, optionally limited to one asset or vulnerability. A new
    assessment row is written only when the score changed, so history stays meaningful."""
    data = data or RiskCalculateRequest()
    return risk_service.calculate(db, actor, data.asset_id, data.vulnerability_id)


@router.get("/assessments", response_model=Page[RiskAssessmentOut], summary="Risk assessments")
def list_assessments(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    asset_id: int | None = None,
    vulnerability_id: int | None = None,
    risk_level: Annotated[list[RiskLevel] | None, Query()] = None,
    current_only: bool = Query(True, description="false = include superseded assessments (history)"),
):
    repo = RiskRepository(db)
    items, total = repo.page(repo.filtered(asset_id=asset_id, vulnerability_id=vulnerability_id,
                                           risk_level=risk_level, current_only=current_only), params)
    return make_page(items, total, params)


@router.get("/high-risk-assets", response_model=list[AssetRiskOut], summary="Highest-risk assets")
def high_risk_assets(
    db: DbSession,
    _: Reader,
    min_level: RiskLevel = RiskLevel.HIGH,
    limit: int = Query(20, ge=1, le=200),
):
    return risk_service.high_risk_assets(db, min_level.value, limit)


@router.get("/assets/{asset_id}", response_model=AssetRiskOut, summary="Risk summary of one asset")
def asset_risk(asset_id: int, db: DbSession, _: Reader):
    return risk_service.asset_risk(db, asset_id)


@router.post("/acceptances", response_model=RiskAcceptanceOut, status_code=status.HTTP_201_CREATED,
             summary="Formally accept the risk of a vulnerability on an asset")
def accept_risk(data: RiskAcceptanceCreate, db: DbSession, actor: Acceptor):
    """Accepted pairs no longer count towards the asset's risk score until revoked or expired."""
    return risk_service.accept_risk(db, actor, data)


@router.get("/acceptances", response_model=Page[RiskAcceptanceOut], summary="Risk acceptances")
def list_acceptances(
    db: DbSession,
    _: Reader,
    params: Annotated[PageParams, Depends(page_params)],
    status: str | None = Query(None, pattern="^(active|revoked|expired)$"),
    asset_id: int | None = None,
    vulnerability_id: int | None = None,
):
    repo = RiskRepository(db)
    items, total = repo.page(repo.acceptances_stmt(status=status, asset_id=asset_id,
                                                   vulnerability_id=vulnerability_id), params)
    return make_page(items, total, params)


@router.post("/acceptances/{acceptance_id}/revoke", response_model=RiskAcceptanceOut,
             summary="Revoke a risk acceptance")
def revoke_acceptance(acceptance_id: int, data: RiskAcceptanceRevoke, db: DbSession, actor: Acceptor):
    return risk_service.revoke_acceptance(db, actor, acceptance_id, data.reason)
