"""Risk assessment engine.

SCORING FORMULA (version v1) - the single source of truth, also served by GET /risks/formula:

    impact_component     = (criticality_weight * severity_weight) / 16 * 70      (0 - 70)
    exploitability_comp. = (cvss_score / 10) * 30                                (0 - 30)
    risk_score           = round(impact_component + exploitability_component, 2) (0 - 100)

    criticality_weight : low=1, medium=2, high=3, critical=4   (asset criticality)
    severity_weight    : low=1, medium=2, high=3, critical=4   (vulnerability severity)

    risk level : score >= 75 -> critical | >= 50 -> high | >= 25 -> medium | otherwise low

An asset's risk is the HIGHEST current score among its OPEN vulnerabilities. Mitigated / closed vulnerabilities no
longer count, and accepted risks are excluded from the asset score (they are tracked separately). Every change of
an input or of the result writes a new assessment row; the previous one is kept as history (is_current=False).
"""
from sqlalchemy.orm import Session

from app.core.constants import (
    CRITICALITY_WEIGHT,
    RISK_FORMULA_VERSION,
    RISK_LEVEL_BANDS,
    VULN_SEVERITY_WEIGHT,
    NotificationType,
    P,
)
from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.models import AssetVulnerability, RiskAcceptance, RiskAssessment, User
from app.repositories.asset_repository import AssetRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.vulnerability_repository import VulnerabilityRepository
from app.schemas.risk_acceptance import RiskAcceptanceCreate
from app.services import audit_service, notification_service
from app.utils.date_utils import utcnow

LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- pure calculation
def level_for_score(score: float) -> str:
    for threshold, level in RISK_LEVEL_BANDS:
        if score >= threshold:
            return level
    return "low"


def compute_risk(asset_criticality: str, vulnerability_severity: str, cvss_score: float) -> tuple[float, str]:
    """Returns (score 0-100, level). Raises ValueError for unknown criticality/severity or a CVSS outside 0-10."""
    if asset_criticality not in CRITICALITY_WEIGHT:
        raise ValueError(f"Unknown asset criticality: {asset_criticality}")
    if vulnerability_severity not in VULN_SEVERITY_WEIGHT:
        raise ValueError(f"Unknown vulnerability severity: {vulnerability_severity}")
    if not 0 <= cvss_score <= 10:
        raise ValueError("CVSS score must be between 0 and 10")
    impact = CRITICALITY_WEIGHT[asset_criticality] * VULN_SEVERITY_WEIGHT[vulnerability_severity] / 16 * 70
    exploitability = cvss_score / 10 * 30
    score = round(impact + exploitability, 2)
    return score, level_for_score(score)


def formula_description() -> dict:
    examples = []
    for crit, sev, cvss in (("critical", "critical", 9.8), ("high", "high", 7.5), ("medium", "medium", 5.0),
                            ("low", "low", 2.0)):
        score, level = compute_risk(crit, sev, cvss)
        examples.append({"asset_criticality": crit, "vulnerability_severity": sev, "cvss_score": cvss,
                         "risk_score": score, "risk_level": level})
    return {
        "version": RISK_FORMULA_VERSION,
        "formula": "risk_score = (criticality_weight * severity_weight) / 16 * 70 + (cvss_score / 10) * 30",
        "criticality_weights": CRITICALITY_WEIGHT,
        "severity_weights": VULN_SEVERITY_WEIGHT,
        "level_bands": [{"min_score": t, "level": lvl} for t, lvl in RISK_LEVEL_BANDS],
        "asset_aggregation": "Highest current score among the asset's open vulnerabilities "
                             "(mitigated, closed and accepted-risk vulnerabilities are excluded).",
        "examples": examples,
    }


# --------------------------------------------------------------------------- assessment engine
def recalculate(
    db: Session,
    actor: User | None,
    *,
    asset_id: int | None = None,
    vulnerability_id: int | None = None,
    notify: bool = True,
) -> tuple[list[RiskAssessment], int]:
    """(Re)assess every open/accepted asset-vulnerability pair in scope. Flushes, never commits.
    Returns (new assessments, number of pairs left unchanged)."""
    vrepo, rrepo = VulnerabilityRepository(db), RiskRepository(db)
    mappings = [
        m
        for m in db.scalars(vrepo.mappings_stmt(asset_id=asset_id, vulnerability_id=vulnerability_id))
        if m.status in ("open", "accepted_risk")
    ]
    created: list[RiskAssessment] = []
    unchanged = 0
    for m in mappings:
        asset, vuln = m.asset, m.vulnerability
        score, level = compute_risk(asset.criticality, vuln.severity, vuln.cvss_score)
        current = rrepo.current(asset.id, vuln.id)
        if (
            current
            and current.risk_score == score
            and current.asset_criticality == asset.criticality
            and current.vulnerability_severity == vuln.severity
            and current.cvss_score == vuln.cvss_score
            and current.formula_version == RISK_FORMULA_VERSION
        ):
            unchanged += 1
            continue
        if current:
            current.is_current = False
        row = RiskAssessment(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            asset_criticality=asset.criticality,
            vulnerability_severity=vuln.severity,
            cvss_score=vuln.cvss_score,
            risk_score=score,
            risk_level=level,
            formula_version=RISK_FORMULA_VERSION,
            is_current=True,
            assessed_by_id=actor.id if actor else None,
        )
        db.add(row)
        created.append(row)
        crossed_up = LEVEL_RANK[level] >= LEVEL_RANK["high"] and (
            current is None or LEVEL_RANK[current.risk_level] < LEVEL_RANK[level]
        )
        if notify and crossed_up and m.status == "open":
            _notify_high_risk(db, m, score, level)
    db.flush()
    return created, unchanged


def _notify_high_risk(db: Session, mapping: AssetVulnerability, score: float, level: str) -> None:
    asset, vuln = mapping.asset, mapping.vulnerability
    notification_service.notify_permission_holders(
        db,
        P.RISK_ACCEPT,
        NotificationType.HIGH_RISK_VULNERABILITY,
        f"{level.capitalize()}-risk vulnerability on {asset.name}",
        f"{vuln.reference or vuln.title} ({vuln.cve_id or 'no CVE'}) scores {score} ({level}) on asset "
        f"'{asset.name}' ({asset.criticality} criticality).",
        extra_user_ids=[asset.owner_id],
        entity_type="asset_vulnerability",
        entity_id=mapping.id,
        dedupe=True,
    )


def calculate(db: Session, actor: User, asset_id: int | None, vulnerability_id: int | None) -> dict:
    if asset_id is not None:
        AssetRepository(db).require(asset_id)
    if vulnerability_id is not None:
        VulnerabilityRepository(db).require(vulnerability_id)
    created, unchanged = recalculate(db, actor, asset_id=asset_id, vulnerability_id=vulnerability_id)
    audit_service.record(
        db, user_id=actor.id, action="risk.calculate", entity_type="risk_assessment", entity_id=None,
        new={"asset_id": asset_id, "vulnerability_id": vulnerability_id, "calculated": len(created),
             "unchanged": unchanged},
    )
    db.commit()
    return {"calculated": len(created), "unchanged": unchanged, "assessments": created}


# --------------------------------------------------------------------------- asset risk views
def asset_risk_items(db: Session, rows: list[tuple[int, float, int]]) -> list[dict]:
    rrepo = RiskRepository(db)
    assets = rrepo.assets_by_ids([r[0] for r in rows])
    accepted = rrepo.accepted_counts()
    return [
        {
            "asset": assets[asset_id],
            "risk_score": score,
            "risk_level": level_for_score(score),
            "open_vulnerabilities": count,
            "accepted_vulnerabilities": accepted.get(asset_id, 0),
        }
        for asset_id, score, count in rows
        if asset_id in assets
    ]


def high_risk_assets(db: Session, min_level: str = "high", limit: int = 20) -> list[dict]:
    rows = [r for r in RiskRepository(db).asset_risk_rows() if LEVEL_RANK[level_for_score(r[1])] >= LEVEL_RANK[min_level]]
    return asset_risk_items(db, rows[:limit])


def asset_risk(db: Session, asset_id: int) -> dict:
    asset = AssetRepository(db).require(asset_id)
    rows = RiskRepository(db).asset_risk_rows(asset_id=asset_id)
    if not rows:
        return {
            "asset": asset,
            "risk_score": 0.0,
            "risk_level": "low",
            "open_vulnerabilities": 0,
            "accepted_vulnerabilities": RiskRepository(db).accepted_counts().get(asset_id, 0),
        }
    return asset_risk_items(db, rows)[0]


# --------------------------------------------------------------------------- risk acceptance
def _sync_vulnerability_after_acceptance_change(db: Session, vuln, user_id: int | None) -> None:
    vrepo = VulnerabilityRepository(db)
    mappings = vrepo.mappings_for_vulnerability(vuln.id)
    has_open = any(m.status == "open" for m in mappings)
    has_accepted = any(m.status == "accepted_risk" for m in mappings)
    if has_accepted and not has_open and vuln.status in ("open", "under_review", "in_remediation"):
        vrepo.change_status(vuln, "accepted_risk", user_id, "All remaining affected assets have an accepted risk")
    elif not has_accepted and vuln.status == "accepted_risk":
        vrepo.change_status(vuln, "open", user_id, "No accepted risk remains")


def accept_risk(db: Session, actor: User, data: RiskAcceptanceCreate) -> RiskAcceptance:
    vrepo, rrepo = VulnerabilityRepository(db), RiskRepository(db)
    vuln = vrepo.require(data.vulnerability_id)
    AssetRepository(db).require(data.asset_id)
    mapping = vrepo.get_mapping(data.asset_id, data.vulnerability_id)
    if mapping is None:
        raise NotFoundError("This vulnerability is not mapped to the given asset")
    if vuln.status == "closed":
        raise ConflictError("Risk cannot be accepted for a closed vulnerability")
    if rrepo.active_acceptance(data.asset_id, data.vulnerability_id):
        raise ConflictError("An active risk acceptance already exists for this asset and vulnerability")
    if mapping.status != "open":
        raise ConflictError(f"Only open findings can be accepted (current status: {mapping.status})")
    if data.expires_at is not None and data.expires_at <= utcnow():
        raise BadRequestError("expires_at must be in the future")
    acceptance = RiskAcceptance(
        asset_id=data.asset_id,
        vulnerability_id=data.vulnerability_id,
        justification=data.justification,
        status="active",
        accepted_by_id=actor.id,
        expires_at=data.expires_at,
    )
    db.add(acceptance)
    mapping.status = "accepted_risk"
    db.flush()
    vrepo.add_history(vuln.id, actor.id, "risk_accepted", "asset_id", None, data.asset_id)
    _sync_vulnerability_after_acceptance_change(db, vuln, actor.id)
    audit_service.record(
        db, user_id=actor.id, action="risk.accept", entity_type="risk_acceptance", entity_id=acceptance.id,
        previous={"mapping_status": "open"},
        new={"asset_id": data.asset_id, "vulnerability_id": data.vulnerability_id,
             "justification": data.justification, "expires_at": data.expires_at},
    )
    db.commit()
    return acceptance


def _end_acceptance(db: Session, acceptance: RiskAcceptance, new_status: str, actor_id: int | None,
                    reason: str | None) -> None:
    vrepo = VulnerabilityRepository(db)
    acceptance.status = new_status
    if new_status == "revoked":
        acceptance.revoked_by_id, acceptance.revoked_at, acceptance.revoke_reason = actor_id, utcnow(), reason
    mapping = vrepo.get_mapping(acceptance.asset_id, acceptance.vulnerability_id)
    if mapping and mapping.status == "accepted_risk":
        mapping.status = "open"
    db.flush()
    vuln = vrepo.require(acceptance.vulnerability_id)
    vrepo.add_history(vuln.id, actor_id, f"risk_acceptance_{new_status}", "asset_id", acceptance.asset_id, None)
    _sync_vulnerability_after_acceptance_change(db, vuln, actor_id)
    recalculate(db, None, asset_id=acceptance.asset_id, vulnerability_id=acceptance.vulnerability_id)


def revoke_acceptance(db: Session, actor: User, acceptance_id: int, reason: str) -> RiskAcceptance:
    acceptance = RiskRepository(db).get_acceptance(acceptance_id)
    if acceptance is None:
        raise NotFoundError(f"Risk acceptance {acceptance_id} not found")
    if acceptance.status != "active":
        raise ConflictError(f"Acceptance is already {acceptance.status}")
    _end_acceptance(db, acceptance, "revoked", actor.id, reason)
    audit_service.record(
        db, user_id=actor.id, action="risk.accept_revoke", entity_type="risk_acceptance", entity_id=acceptance.id,
        previous={"status": "active"}, new={"status": "revoked", "reason": reason},
    )
    db.commit()
    return acceptance


def expire_acceptances(db: Session) -> int:
    """Lapse acceptances whose expiry has passed; the finding re-opens and is re-assessed. Caller commits."""
    now = utcnow()
    expired = [
        a for a in db.scalars(RiskRepository(db).acceptances_stmt(status="active"))
        if a.expires_at is not None and a.expires_at < now
    ]
    for acceptance in expired:
        _end_acceptance(db, acceptance, "expired", None, None)
        audit_service.record(db, user_id=None, action="risk.accept_expired", entity_type="risk_acceptance",
                             entity_id=acceptance.id, previous={"status": "active"}, new={"status": "expired"})
        notification_service.notify_permission_holders(
            db, P.RISK_ACCEPT, NotificationType.RISK_ACCEPTANCE_EXPIRED,
            "Risk acceptance expired",
            f"The accepted risk for vulnerability {acceptance.vulnerability_id} on asset {acceptance.asset_id} "
            "has expired and the finding is open again.",
            extra_user_ids=[acceptance.accepted_by_id],
            entity_type="risk_acceptance", entity_id=acceptance.id, dedupe=True,
        )
    return len(expired)
