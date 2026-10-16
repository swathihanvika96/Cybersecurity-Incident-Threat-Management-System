from pydantic import Field

from app.core.constants import AssetCriticality, RiskLevel, VulnerabilitySeverity
from app.schemas.asset import AssetBrief
from app.schemas.common import DT, ORMModel, RequestModel


class RiskCalculateRequest(RequestModel):
    asset_id: int | None = Field(None, description="Limit to one asset")
    vulnerability_id: int | None = Field(None, description="Limit to one vulnerability")


class RiskAssessmentOut(ORMModel):
    id: int
    asset_id: int
    vulnerability_id: int
    asset_criticality: AssetCriticality
    vulnerability_severity: VulnerabilitySeverity
    cvss_score: float
    risk_score: float = Field(description="0-100")
    risk_level: RiskLevel
    formula_version: str
    is_current: bool
    assessed_by_id: int | None = None
    assessed_at: DT


class RiskCalculateResult(ORMModel):
    calculated: int = Field(description="New assessments recorded")
    unchanged: int = Field(description="Pairs whose score did not change (no new history row)")
    assessments: list[RiskAssessmentOut]


class AssetRiskOut(ORMModel):
    asset: AssetBrief
    risk_score: float = Field(description="Highest current risk score among the asset's open vulnerabilities")
    risk_level: RiskLevel
    open_vulnerabilities: int
    accepted_vulnerabilities: int


class RiskFormulaOut(ORMModel):
    version: str
    formula: str
    criticality_weights: dict[str, int]
    severity_weights: dict[str, int]
    level_bands: list[dict]
    asset_aggregation: str
    examples: list[dict]
