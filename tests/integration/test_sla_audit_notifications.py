from datetime import datetime, timedelta

import pytest

from app.models import AuditLog, Incident, IncidentSLA
from app.models.audit_log import AuditLogImmutableError
from tests.conftest import API


def new_incident(client, manager, asset, make_alert, severity="critical"):
    a = make_alert(asset["id"], severity=severity)
    r = client.post(f"{API}/incidents", headers=manager["headers"], json={"title": "SLA test incident", "alert_ids": [a["id"]]})
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ SLA
def test_default_policies_follow_severity(client, manager):
    pol = {p["severity"]: p for p in client.get(f"{API}/slas/policies", headers=manager["headers"]).json()}
    assert pol["critical"]["resolution_minutes"] < pol["low"]["resolution_minutes"]
    assert pol["critical"]["ack_minutes"] <= pol["critical"]["investigation_minutes"] <= pol["critical"]["resolution_minutes"]


def test_policy_update_rules(client, manager, analyst):
    body = {"ack_minutes": 10, "investigation_minutes": 30, "resolution_minutes": 120}
    assert client.put(f"{API}/slas/policies/critical", headers=analyst["headers"], json=body).status_code == 403
    assert client.put(f"{API}/slas/policies/critical", headers=manager["headers"],
                      json={**body, "ack_minutes": 500}).status_code == 422  # must be ordered
    assert client.put(f"{API}/slas/policies/critical", headers=manager["headers"], json=body).status_code == 200


def test_breach_detection_and_escalation(client, manager, asset, make_alert, db):
    inc = new_incident(client, manager, asset, make_alert)
    sla = db.query(IncidentSLA).filter_by(incident_id=inc["id"]).one()
    past = datetime.utcnow() - timedelta(minutes=5)
    sla.ack_deadline = past
    db.commit()
    r = client.get(f"{API}/slas/breached", headers=manager["headers"]).json()
    assert r["total"] == 1 and "acknowledgment" in r["items"][0]["at_risk_phases"]
    detail = client.get(f"{API}/slas/incidents/{inc['id']}", headers=manager["headers"]).json()
    assert detail["ack_breached"] is True and detail["sla_status"] == "breached" and detail["escalation_level"] >= 1
    assert client.get(f"{API}/slas/escalated", headers=manager["headers"]).json()["total"] == 1
    assert client.get(f"{API}/slas/incidents/{inc['id']}/history", headers=manager["headers"]).json()["total"] >= 1
    # managers are notified about the breach
    client.post(f"{API}/notifications/process", headers=manager["headers"])
    types = {n["notification_type"] for n in client.get(f"{API}/notifications", headers=manager["headers"]).json()["items"]}
    assert any("sla" in t for t in types), types


def test_approaching_deadline(client, manager, asset, make_alert, db):
    inc = new_incident(client, manager, asset, make_alert)
    sla = db.query(IncidentSLA).filter_by(incident_id=inc["id"]).one()
    now = datetime.utcnow()
    db.get(Incident, inc["id"]).created_at = now - timedelta(minutes=9)   # window = 10 min, 1 min left (< 25%)
    sla.ack_deadline = now + timedelta(minutes=1)
    db.commit()
    r = client.get(f"{API}/slas/approaching", headers=manager["headers"]).json()
    assert r["total"] == 1 and r["items"][0]["sla"]["sla_status"] == "at_risk"


def test_met_sla_after_timely_resolution(client, manager, analyst, asset, make_alert):
    inc = new_incident(client, manager, asset, make_alert)
    iid = inc["id"]
    client.post(f"{API}/incidents/{iid}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    client.patch(f"{API}/incidents/{iid}/status", headers=analyst["headers"], json={"status": "investigating"})
    client.post(f"{API}/incidents/{iid}/resolve", headers=analyst["headers"], json={
        "resolution_summary": "Done", "resolution_details": "Contained quickly and verified clean."})
    sla = client.get(f"{API}/slas/incidents/{iid}", headers=manager["headers"]).json()
    assert sla["sla_status"] == "met" and sla["response_time_minutes"] is not None and sla["resolution_time_minutes"] is not None
    assert client.get(f"{API}/slas/breached", headers=manager["headers"]).json()["total"] == 0


def test_manual_escalation_permissions(client, manager, analyst, asset, make_alert):
    inc = new_incident(client, manager, asset, make_alert, severity="low")
    url = f"{API}/slas/incidents/{inc['id']}/escalate"
    assert client.post(url, headers=analyst["headers"], json={"reason": "Customer impact"}).status_code == 403
    r = client.post(url, headers=manager["headers"], json={"reason": "Customer impact"})
    assert r.status_code == 200 and r.json()["escalation_status"] != "none"
    assert client.post(url, headers=manager["headers"], json={"reason": ""}).status_code == 422


def test_evaluate_endpoint(client, manager):
    r = client.post(f"{API}/slas/evaluate", headers=manager["headers"])
    assert r.status_code == 200 and set(r.json()) == {"evaluated", "newly_breached", "escalated"}


# ------------------------------------------------------------------ audit log
def test_audit_log_is_append_only_in_orm(db, client, admin_h):
    entry = db.query(AuditLog).first()
    assert entry is not None
    entry.action = "tampered"
    with pytest.raises(AuditLogImmutableError):
        db.commit()
    db.rollback()
    db.delete(db.query(AuditLog).first())
    with pytest.raises(AuditLogImmutableError):
        db.commit()
    db.rollback()


def test_audit_log_has_no_write_endpoints(client, admin_h):
    entry = client.get(f"{API}/audit-logs", headers=admin_h).json()["items"][0]
    for method in ("put", "patch", "delete"):
        r = getattr(client, method)(f"{API}/audit-logs/{entry['id']}", headers=admin_h)
        assert r.status_code == 405
    assert client.post(f"{API}/audit-logs", headers=admin_h, json={}).status_code == 405


def test_audit_records_before_and_after_values(client, it_admin, asset, admin_h):
    client.patch(f"{API}/assets/{asset['id']}", headers=it_admin["headers"], json={"criticality": "low"})
    logs = client.get(f"{API}/audit-logs", headers=admin_h,
                      params={"entity_type": "asset", "entity_id": asset["id"], "action": "asset.update"}).json()
    assert logs["total"] == 1
    entry = logs["items"][0]
    assert entry["user_id"] == it_admin["id"] and entry["previous_value"]["criticality"] == "high"
    assert entry["new_value"]["criticality"] == "low" and entry["ip_address"]


def test_audit_filters(client, admin_h, manager, asset, make_alert):
    make_alert(asset["id"])
    r = client.get(f"{API}/audit-logs", headers=admin_h, params={"user_id": manager["id"]}).json()
    assert r["total"] >= 1 and all(e["user_id"] == manager["id"] for e in r["items"])
    assert client.get(f"{API}/audit-logs", headers=admin_h, params={"date_from": "2999-01-01"}).json()["total"] == 0


# ------------------------------------------------------------------ notifications
def test_notifications_are_private_and_markable(client, manager, analyst, analyst2, asset, make_alert):
    inc = new_incident(client, manager, asset, make_alert)
    client.post(f"{API}/incidents/{inc['id']}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    assert client.post(f"{API}/notifications/process", headers=manager["headers"]).json()["delivered"] >= 1
    mine = client.get(f"{API}/notifications", headers=analyst["headers"]).json()
    assert mine["total"] >= 1 and all(n["status"] == "delivered" for n in mine["items"])
    assert client.get(f"{API}/notifications", headers=analyst2["headers"]).json()["total"] == 0
    nid = mine["items"][0]["id"]
    assert client.post(f"{API}/notifications/{nid}/read", headers=analyst2["headers"]).status_code == 404
    unread = client.get(f"{API}/notifications/unread-count", headers=analyst["headers"]).json()["unread"]
    assert client.post(f"{API}/notifications/{nid}/read", headers=analyst["headers"]).json()["is_read"] is True
    assert client.get(f"{API}/notifications/unread-count", headers=analyst["headers"]).json()["unread"] == unread - 1
    assert client.post(f"{API}/notifications/read-all", headers=analyst["headers"]).status_code == 200
    assert client.get(f"{API}/notifications/unread-count", headers=analyst["headers"]).json()["unread"] == 0
    assert client.get(f"{API}/notifications", headers=analyst["headers"], params={"is_read": False}).json()["total"] == 0


def test_only_managers_trigger_delivery(client, analyst):
    assert client.post(f"{API}/notifications/process", headers=analyst["headers"]).status_code == 403
