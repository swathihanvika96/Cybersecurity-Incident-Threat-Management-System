from tests.conftest import API


def create_incident(client, headers, **body):
    body.setdefault("title", "Suspicious activity on web-01")
    r = client.post(f"{API}/incidents", headers=headers, json=body)
    return r


def test_incident_from_alerts_inherits_severity_and_sla(client, manager, asset, make_alert):
    a1, a2 = make_alert(asset["id"], severity="medium"), make_alert(asset["id"], title="Second alert", severity="high")
    r = create_incident(client, manager["headers"], alert_ids=[a1["id"], a2["id"]])
    assert r.status_code == 201, r.text
    inc = r.json()
    assert inc["severity"] == "high" and inc["asset"]["id"] == asset["id"] and len(inc["alerts"]) == 2
    sla = client.get(f"{API}/slas/incidents/{inc['id']}", headers=manager["headers"]).json()
    assert sla["severity"] == "high" and sla["sla_status"] == "on_track"


def test_manual_incident_requires_asset_and_category(client, manager):
    assert create_incident(client, manager["headers"]).status_code in (400, 422)


def test_duplicate_open_incident_rejected_unless_allowed(client, manager, asset, make_alert):
    a = make_alert(asset["id"])
    assert create_incident(client, manager["headers"], alert_ids=[a["id"]]).status_code == 201
    b = make_alert(asset["id"], title="Another one")
    r = create_incident(client, manager["headers"], alert_ids=[b["id"]])
    assert r.status_code == 409 and r.json()["error"]["code"] == "duplicate_incident"
    ok = create_incident(client, manager["headers"], alert_ids=[b["id"]], allow_duplicate=True)
    assert ok.status_code == 201


def test_alert_cannot_be_linked_to_two_incidents(client, manager, asset, make_alert):
    a = make_alert(asset["id"])
    inc = create_incident(client, manager["headers"], alert_ids=[a["id"]]).json()
    r = client.post(f"{API}/incidents/{inc['id']}/alerts", headers=manager["headers"], json={"alert_ids": [a["id"]]})
    assert r.status_code in (200, 409)  # idempotent re-link or conflict, never a 500


def test_assignment_rules(client, manager, analyst, analyst2, it_admin, asset, make_alert):
    inc = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"])["id"]]).json()
    url = f"{API}/incidents/{inc['id']}/assign"
    # an IT administrator cannot be assigned an incident
    assert client.post(url, headers=manager["headers"], json={"assigned_to_id": it_admin["id"]}).status_code in (400, 403)
    # an analyst cannot assign others, but can claim an unassigned incident
    assert client.post(url, headers=analyst["headers"], json={"assigned_to_id": analyst2["id"]}).status_code == 403
    assert client.post(url, headers=analyst["headers"], json={"assigned_to_id": analyst["id"]}).status_code == 200
    # the manager can reassign, history is kept
    assert client.post(url, headers=manager["headers"], json={"assigned_to_id": analyst2["id"]}).status_code == 200
    hist = client.get(f"{API}/incidents/{inc['id']}/assignments", headers=manager["headers"]).json()
    assert hist["total"] == 2 and sum(1 for h in hist["items"] if h["is_active"]) == 1


def test_status_workflow_is_enforced(client, manager, analyst, asset, make_alert):
    inc = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"])["id"]]).json()
    status_url = f"{API}/incidents/{inc['id']}/status"
    assert client.patch(status_url, headers=manager["headers"], json={"status": "investigating"}).status_code == 400
    client.post(f"{API}/incidents/{inc['id']}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    assert client.patch(status_url, headers=analyst["headers"], json={"status": "closed"}).status_code == 422  # closing only via approval
    assert client.patch(status_url, headers=analyst["headers"], json={"status": "containment"}).status_code in (200, 400)
    assert client.patch(status_url, headers=analyst["headers"], json={"status": "investigating"}).status_code == 200
    assert client.patch(status_url, headers=analyst["headers"], json={"status": "containment"}).status_code == 200


def test_closure_requires_resolution_and_different_approver(client, manager, manager2, analyst, asset, make_alert):
    inc = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"])["id"]]).json()
    iid = inc["id"]
    assert client.post(f"{API}/incidents/{iid}/closure/request", headers=manager["headers"]).status_code in (400, 409)
    client.post(f"{API}/incidents/{iid}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    client.patch(f"{API}/incidents/{iid}/status", headers=analyst["headers"], json={"status": "investigating"})
    assert client.post(f"{API}/incidents/{iid}/resolve", headers=analyst["headers"],
                       json={"resolution_summary": "ok", "resolution_details": "short"}).status_code == 422
    assert client.post(f"{API}/incidents/{iid}/resolve", headers=analyst["headers"], json={
        "resolution_summary": "Contained", "resolution_details": "Isolated host and rotated credentials."}).status_code == 200
    assert client.post(f"{API}/incidents/{iid}/closure/request", headers=manager["headers"]).status_code == 200
    assert client.post(f"{API}/incidents/{iid}/closure/approve", headers=analyst["headers"]).status_code == 403
    assert client.post(f"{API}/incidents/{iid}/closure/approve", headers=manager["headers"]).status_code == 403
    r = client.post(f"{API}/incidents/{iid}/closure/approve", headers=manager2["headers"])
    assert r.status_code == 200 and r.json()["status"] == "closed"
    # closed incidents are final
    assert client.patch(f"{API}/incidents/{iid}/status", headers=manager["headers"],
                        json={"status": "investigating"}).status_code in (400, 409)


def test_closure_rejection_reopens(client, manager, manager2, analyst, asset, make_alert):
    inc = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"])["id"]]).json()
    iid = inc["id"]
    client.post(f"{API}/incidents/{iid}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    client.patch(f"{API}/incidents/{iid}/status", headers=analyst["headers"], json={"status": "investigating"})
    client.post(f"{API}/incidents/{iid}/resolve", headers=analyst["headers"], json={
        "resolution_summary": "Contained", "resolution_details": "Isolated host and rotated credentials."})
    client.post(f"{API}/incidents/{iid}/closure/request", headers=manager["headers"])
    assert client.post(f"{API}/incidents/{iid}/closure/reject", headers=manager2["headers"], json={}).status_code == 400
    r = client.post(f"{API}/incidents/{iid}/closure/reject", headers=manager2["headers"], json={"comment": "Need RCA"})
    assert r.status_code == 200 and r.json()["status"] == "investigating"


def test_sensitive_incident_visibility(client, manager, analyst, analyst2, auditor, asset, make_alert):
    inc = create_incident(client, manager["headers"], is_sensitive=True, title="Exec mailbox compromise",
                          alert_ids=[make_alert(asset["id"])["id"]], assigned_to_id=analyst["id"]).json()
    iid = inc["id"]
    assert client.get(f"{API}/incidents/{iid}", headers=manager["headers"]).status_code == 200      # incident:sensitive
    assert client.get(f"{API}/incidents/{iid}", headers=analyst["headers"]).status_code == 200      # assignee
    assert client.get(f"{API}/incidents/{iid}", headers=analyst2["headers"]).status_code == 403     # unrelated
    assert client.get(f"{API}/incidents/{iid}", headers=auditor["headers"]).status_code == 403
    assert client.get(f"{API}/incidents", headers=analyst2["headers"]).json()["total"] == 0
    assert client.get(f"{API}/incidents", headers=analyst["headers"]).json()["total"] == 1
    # also hidden from search, SLA views and sub-resources
    assert client.get(f"{API}/search", headers=analyst2["headers"], params={"entity_types": "incident"}).json()["total"] == 0
    assert client.get(f"{API}/incidents/{iid}/notes", headers=analyst2["headers"]).status_code == 403
    assert client.get(f"{API}/slas/incidents/{iid}", headers=auditor["headers"]).status_code == 403
    assert client.post(f"{API}/incidents/{iid}/notes", headers=analyst2["headers"], json={"content": "hi"}).status_code == 403


def test_incident_history_and_notes(client, manager, analyst, asset, make_alert):
    inc = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"])["id"]]).json()
    iid = inc["id"]
    assert client.patch(f"{API}/incidents/{iid}", headers=manager["headers"], json={"severity": "critical"}).status_code == 200
    assert client.post(f"{API}/incidents/{iid}/notes", headers=manager["headers"], json={"content": "Looking"}).status_code == 201
    assert client.post(f"{API}/incidents/{iid}/notes", headers=manager["headers"], json={"content": ""}).status_code == 422
    assert client.get(f"{API}/incidents/{iid}/history", headers=manager["headers"]).json()["total"] >= 2
    sla = client.get(f"{API}/slas/incidents/{iid}", headers=manager["headers"]).json()
    assert sla["severity"] == "critical"  # severity change re-applies the SLA policy


def test_list_filters(client, manager, analyst, asset, make_alert, make_asset):
    other = make_asset("other-asset")
    i1 = create_incident(client, manager["headers"], alert_ids=[make_alert(asset["id"], severity="low")["id"]]).json()
    create_incident(client, manager["headers"], alert_ids=[make_alert(other["id"], severity="critical")["id"]])
    h = manager["headers"]
    assert client.get(f"{API}/incidents", headers=h, params={"severity": "critical"}).json()["total"] == 1
    assert client.get(f"{API}/incidents", headers=h, params={"asset_id": asset["id"]}).json()["total"] == 1
    assert client.get(f"{API}/incidents", headers=h, params={"reference": i1["reference"]}).json()["total"] == 1
    assert client.get(f"{API}/incidents", headers=h, params={"status": "new", "size": 1}).json()["pages"] == 2
    assert client.get(f"{API}/incidents/999999", headers=h).status_code == 404
