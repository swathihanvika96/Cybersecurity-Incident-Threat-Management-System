"""Alert correlation.

Business rule (documented in README): alerts of the SAME CATEGORY on the SAME ASSET belong together when they
form a chain in which each alert is detected within `window_minutes` of the previous one. A chain with at least
`min_alerts` alerts is a "repeated alert" group and can be grouped into a correlation (automatically or by hand).
Duplicate alerts count - they are exactly the repetition we want to surface.
"""
from datetime import timedelta
from typing import Any, Sequence

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.models import AlertCorrelation, CorrelationHistory, SecurityAlert, User
from app.repositories.alert_repository import AlertRepository
from app.repositories.asset_repository import AssetRepository
from app.repositories.correlation_repository import CorrelationRepository
from app.services import audit_service
from app.utils.date_utils import make_reference, utcnow


# --------------------------------------------------------------------------- pure clustering
def cluster_alerts(alerts: Sequence[Any], window_minutes: int, min_alerts: int) -> list[list[Any]]:
    """Chain-cluster alerts (objects with asset_id, category, detected_at). Input order does not matter."""
    window = timedelta(minutes=window_minutes)
    by_key: dict[tuple, list[Any]] = {}
    for alert in alerts:
        by_key.setdefault((alert.asset_id, alert.category), []).append(alert)
    clusters: list[list[Any]] = []
    for key in sorted(by_key, key=lambda k: (k[0], str(k[1]))):
        group = sorted(by_key[key], key=lambda a: (a.detected_at, getattr(a, "id", 0)))
        current = [group[0]]
        for alert in group[1:]:
            if alert.detected_at - current[-1].detected_at <= window:
                current.append(alert)
            else:
                if len(current) >= min_alerts:
                    clusters.append(current)
                current = [alert]
        if len(current) >= min_alerts:
            clusters.append(current)
    return clusters


# --------------------------------------------------------------------------- helpers
def _history(db: Session, correlation_id: int, user_id: int | None, action: str, alert_id: int | None = None,
             details: str | None = None) -> None:
    db.add(CorrelationHistory(correlation_id=correlation_id, user_id=user_id, action=action, alert_id=alert_id,
                              details=details))


def record_incident_link(db: Session, correlation_id: int, user_id: int | None, incident_reference: str) -> None:
    _history(db, correlation_id, user_id, "linked_to_incident", details=f"Incident {incident_reference}")


def _params(window_minutes, min_alerts, lookback_hours) -> tuple[int, int, int]:
    return (
        window_minutes or settings.CORRELATION_WINDOW_MINUTES,
        min_alerts or settings.CORRELATION_MIN_ALERTS,
        lookback_hours or settings.CORRELATION_LOOKBACK_HOURS,
    )


def _refresh(db: Session, correlation: AlertCorrelation) -> AlertCorrelation:
    db.flush()
    db.expire(correlation, ["alerts"])
    return correlation


def _load_alerts(db: Session, alert_ids: list[int]) -> list[SecurityAlert]:
    ids = list(dict.fromkeys(alert_ids))
    if len(ids) != len(alert_ids):
        raise BadRequestError("alert_ids must not contain duplicates")
    alerts = AlertRepository(db).by_ids(ids)
    missing = sorted(set(ids) - {a.id for a in alerts})
    if missing:
        raise NotFoundError(f"Alert(s) not found: {missing}")
    bad = [a.id for a in alerts if a.status == "false_positive"]
    if bad:
        raise BadRequestError(f"False-positive alerts cannot be correlated: {bad}")
    taken = [a.id for a in alerts if a.correlation_id is not None]
    if taken:
        raise ConflictError(f"Alert(s) already belong to a correlation: {taken}")
    return alerts


# --------------------------------------------------------------------------- queries
def find_repeated_groups(db: Session, window_minutes: int | None, min_alerts: int | None,
                         lookback_hours: int | None) -> list[dict]:
    window, minimum, lookback = _params(window_minutes, min_alerts, lookback_hours)
    since = utcnow() - timedelta(hours=lookback)
    alerts = AlertRepository(db).all_since(since)
    groups = []
    for cluster in cluster_alerts(alerts, window, minimum):
        asset = cluster[0].asset
        groups.append(
            {
                "asset_id": cluster[0].asset_id,
                "asset_name": asset.name,
                "category": cluster[0].category,
                "alert_count": len(cluster),
                "alert_ids": [a.id for a in cluster],
                "first_detected_at": cluster[0].detected_at,
                "last_detected_at": cluster[-1].detected_at,
                "already_correlated": all(a.correlation_id is not None for a in cluster),
            }
        )
    return sorted(groups, key=lambda g: (-g["alert_count"], g["asset_id"]))


# --------------------------------------------------------------------------- commands
def create_manual(db: Session, actor: User, name: str, alert_ids: list[int]) -> AlertCorrelation:
    alerts = _load_alerts(db, alert_ids)
    assets, categories = {a.asset_id for a in alerts}, {a.category for a in alerts}
    corr = AlertCorrelation(
        name=name,
        rule="manual",
        asset_id=next(iter(assets)) if len(assets) == 1 else None,
        category=next(iter(categories)) if len(categories) == 1 else None,
        status="open",
        created_by_id=actor.id,
    )
    CorrelationRepository(db).add(corr)
    corr.reference = make_reference("COR", corr.id)
    for alert in alerts:
        alert.correlation_id = corr.id
        _history(db, corr.id, actor.id, "alert_added", alert.id)
    _history(db, corr.id, actor.id, "created", details=f"Manual correlation of {len(alerts)} alerts")
    audit_service.record(db, user_id=actor.id, action="correlation.create", entity_type="correlation",
                         entity_id=corr.id, new={"name": name, "alert_ids": [a.id for a in alerts]})
    _refresh(db, corr)
    db.commit()
    return corr


def auto_correlate(db: Session, actor: User, window_minutes: int | None, min_alerts: int | None,
                   lookback_hours: int | None) -> dict[str, list[AlertCorrelation]]:
    window, minimum, lookback = _params(window_minutes, min_alerts, lookback_hours)
    since = utcnow() - timedelta(hours=lookback)
    repo = CorrelationRepository(db)
    created: dict[int, AlertCorrelation] = {}
    updated: dict[int, AlertCorrelation] = {}
    for cluster in cluster_alerts(AlertRepository(db).uncorrelated_since(since), window, minimum):
        asset_id, category = cluster[0].asset_id, cluster[0].category
        corr = repo.open_for(asset_id, category, cluster[0].detected_at - timedelta(minutes=window))
        if corr is None:
            asset = AssetRepository(db).require(asset_id)
            corr = AlertCorrelation(
                name=f"Repeated {str(category).replace('_', ' ')} alerts on {asset.name}",
                rule="same_asset_category", asset_id=asset_id, category=category, status="open",
                created_by_id=actor.id,
            )
            repo.add(corr)
            corr.reference = make_reference("COR", corr.id)
            _history(db, corr.id, actor.id, "created",
                     details=f"Auto-correlated {len(cluster)} alerts (window {window} min)")
            created[corr.id] = corr
        else:
            _history(db, corr.id, actor.id, "auto_extended", details=f"{len(cluster)} more alerts matched")
            if corr.id not in created:
                updated[corr.id] = corr
        for alert in cluster:
            alert.correlation_id = corr.id
            _history(db, corr.id, actor.id, "alert_added", alert.id)
        _refresh(db, corr)
        audit_service.record(db, user_id=actor.id, action="correlation.auto", entity_type="correlation",
                             entity_id=corr.id, new={"alert_ids": [a.id for a in cluster]})
    db.commit()
    return {"created": list(created.values()), "updated": list(updated.values())}


def add_alerts(db: Session, actor: User, correlation_id: int, alert_ids: list[int]) -> AlertCorrelation:
    corr = CorrelationRepository(db).require(correlation_id)
    if corr.status != "open":
        raise ConflictError("Correlation is closed")
    alerts = _load_alerts(db, alert_ids)
    if corr.rule == "same_asset_category":
        wrong = [a.id for a in alerts if a.asset_id != corr.asset_id or a.category != corr.category]
        if wrong:
            raise BadRequestError(
                f"Alerts must match the correlation's asset and category: {wrong}"
            )
    for alert in alerts:
        alert.correlation_id = corr.id
        _history(db, corr.id, actor.id, "alert_added", alert.id)
    audit_service.record(db, user_id=actor.id, action="correlation.add_alerts", entity_type="correlation",
                         entity_id=corr.id, new={"alert_ids": [a.id for a in alerts]})
    _refresh(db, corr)
    db.commit()
    return corr


def remove_alert(db: Session, actor: User, correlation_id: int, alert_id: int) -> AlertCorrelation:
    corr = CorrelationRepository(db).require(correlation_id)
    alert = AlertRepository(db).get(alert_id)
    if alert is None or alert.correlation_id != corr.id:
        raise NotFoundError(f"Alert {alert_id} is not part of correlation {correlation_id}")
    from app.repositories.incident_repository import IncidentRepository

    incident = IncidentRepository(db).incident_of_alert(alert_id)
    if incident is not None and incident.correlation_id == corr.id:
        raise ConflictError(f"Alert is linked to incident {incident.reference} created from this correlation")
    alert.correlation_id = None
    _history(db, corr.id, actor.id, "alert_removed", alert.id)
    audit_service.record(db, user_id=actor.id, action="correlation.remove_alert", entity_type="correlation",
                         entity_id=corr.id, previous={"alert_id": alert_id})
    _refresh(db, corr)
    db.commit()
    return corr
