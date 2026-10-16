from tests.conftest import API


def incident_for(client, manager, asset, make_alert, sensitive=False, assignee=None, title="Incident for tests"):
    body = {"title": title, "alert_ids": [make_alert(asset["id"], title=title)["id"]], "is_sensitive": sensitive}
    if assignee:
        body["assigned_to_id"] = assignee["id"]
    r = client.post(f"{API}/incidents", headers=manager["headers"], json=body)
    assert r.status_code == 201, r.text
    return r.json()


def open_investigation(client, headers, **body):
    body.setdefault("title", "Investigate beaconing")
    r = client.post(f"{API}/investigations", headers=headers, json=body)
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------------ investigations
def test_investigation_lifecycle(client, analyst, manager):
    inv = open_investigation(client, analyst["headers"])
    base = f"{API}/investigations/{inv['id']}"
    assert inv["status"] == "open" and inv["owner"]["id"] == analyst["id"]
    assert client.post(f"{base}/complete", headers=analyst["headers"], json={"summary": "too short"}).status_code == 422
    assert client.post(f"{base}/notes", headers=analyst["headers"], json={"content": "Pulled logs"}).status_code == 201
    assert client.get(f"{base}", headers=analyst["headers"]).json()["status"] == "in_progress"  # auto-start
    r = client.post(f"{base}/complete", headers=analyst["headers"], json={"summary": "No compromise confirmed."})
    assert r.status_code == 200 and r.json()["status"] == "completed"
    # completed investigations are read-only
    assert client.post(f"{base}/notes", headers=analyst["headers"], json={"content": "late"}).status_code == 409
    assert client.post(f"{base}/close", headers=manager["headers"]).status_code == 200


def test_only_owner_or_manager_can_modify(client, analyst, analyst2, manager):
    inv = open_investigation(client, analyst["headers"])
    base = f"{API}/investigations/{inv['id']}"
    assert client.patch(base, headers=analyst2["headers"], json={"title": "Hijacked title"}).status_code == 403
    assert client.patch(base, headers=manager["headers"], json={"title": "Renamed by manager"}).status_code == 200


def test_evidence_access_control_and_audit(client, analyst, analyst2, auditor, manager, admin_h):
    inv = open_investigation(client, analyst["headers"])
    base = f"{API}/investigations/{inv['id']}"
    ev = {"title": "Disk image", "evidence_type": "memory_dump", "reference": "s3://vault/img.dd",
          "sha256": "a" * 64}
    r = client.post(f"{base}/evidence", headers=analyst["headers"], json=ev)
    assert r.status_code == 201, r.text
    eid = r.json()["id"]
    assert client.post(f"{base}/evidence", headers=analyst["headers"], json={**ev, "sha256": "xyz"}).status_code == 422
    # auditors lack evidence:read -> forbidden (they may see the investigation itself)
    assert client.get(f"{base}", headers=auditor["headers"]).status_code == 200
    assert client.get(f"{base}/evidence", headers=auditor["headers"]).status_code == 403
    assert client.get(f"{base}/evidence/{eid}", headers=auditor["headers"]).status_code == 403
    assert client.get(f"{base}/evidence", headers=manager["headers"]).status_code == 200
    # every successful access is audited
    logs = client.get(f"{API}/audit-logs", headers=admin_h, params={"action": "evidence.access"}).json()
    assert logs["total"] >= 1
    assert client.get(f"{base}/evidence/9999", headers=manager["headers"]).status_code == 404


def test_investigation_on_sensitive_incident_is_restricted(client, manager, analyst, analyst2, asset, make_alert):
    inc = incident_for(client, manager, asset, make_alert, sensitive=True, assignee=analyst)
    r = client.post(f"{API}/investigations", headers=analyst2["headers"],
                    json={"title": "Snooping around", "incident_ids": [inc["id"]]})
    assert r.status_code == 403
    inv = open_investigation(client, analyst["headers"], incident_ids=[inc["id"]])
    assert client.get(f"{API}/investigations/{inv['id']}", headers=analyst2["headers"]).status_code == 403
    assert client.get(f"{API}/investigations", headers=analyst2["headers"]).json()["total"] == 0
    assert client.get(f"{API}/investigations/{inv['id']}", headers=analyst["headers"]).status_code == 200


def test_linking_validates_targets(client, analyst):
    inv = open_investigation(client, analyst["headers"])
    base = f"{API}/investigations/{inv['id']}"
    assert client.post(f"{base}/links", headers=analyst["headers"], json={}).status_code == 422
    assert client.post(f"{base}/links", headers=analyst["headers"], json={"incident_ids": [9999]}).status_code == 404


# ------------------------------------------------------------------ playbooks
PLAYBOOK = {
    "name": "Malware containment", "incident_category": "unauthorized_access",
    "steps": [
        {"title": "Collect logs", "step_type": "investigation", "simulated_action": "collect_logs"},
        {"title": "Isolate host", "step_type": "containment", "is_sensitive": True, "simulated_action": "isolate_host"},
        {"title": "Restore service", "step_type": "recovery"},
    ],
}


def test_playbook_management_permissions_and_validation(client, manager, analyst):
    assert client.post(f"{API}/playbooks", headers=analyst["headers"], json=PLAYBOOK).status_code == 403
    assert client.post(f"{API}/playbooks", headers=manager["headers"], json={**PLAYBOOK, "steps": []}).status_code == 422
    r = client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK)
    assert r.status_code == 201 and [s["step_order"] for s in r.json()["steps"]] == [1, 2, 3]
    assert client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK).status_code == 409


def test_playbook_execution_with_sensitive_step_approval(client, manager, manager2, analyst, asset, make_alert):
    pb = client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK).json()
    inc = incident_for(client, manager, asset, make_alert, assignee=analyst)
    r = client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst["headers"], json={
        "incident_id": inc["id"], "assignments": [{"step_order": i, "user_id": analyst["id"]} for i in (1, 2, 3)]})
    assert r.status_code == 201, r.text
    ex = r.json()
    assert ex["status"] == "running" and len(ex["tasks"]) == 3 and ex["progress_percent"] == 0
    t1, t2, t3 = [t["id"] for t in ex["tasks"]]
    task = lambda tid, action, who=analyst, **b: client.post(f"{API}/playbooks/tasks/{tid}/{action}", headers=who["headers"], json=b)

    assert task(t1, "start").status_code == 200
    done = task(t1, "complete", notes="Logs collected")
    assert done.status_code == 200 and done.json()["status"] == "completed"
    assert "SIMULATED" in done.json()["simulated_result"].upper()  # never a real action

    assert task(t2, "start").status_code == 200
    held = task(t2, "complete").json()
    assert held["status"] == "awaiting_approval"
    assert task(t2, "approve", who=analyst).status_code == 403          # no playbook:approve permission
    assert task(t2, "reject", who=manager2).status_code == 400          # comment required
    assert task(t2, "approve", who=manager2).status_code == 200

    assert task(t3, "start").status_code == 200 and task(t3, "complete").status_code == 200
    final = client.get(f"{API}/playbooks/executions/{ex['id']}", headers=manager["headers"]).json()
    assert final["status"] == "completed" and final["progress_percent"] == 100
    assert client.get(f"{API}/playbooks/executions/{ex['id']}/history", headers=manager["headers"]).json()["total"] >= 6


def test_sensitive_step_cannot_be_self_approved(client, manager, asset, make_alert):
    pb = client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK).json()
    inc = incident_for(client, manager, asset, make_alert)
    ex = client.post(f"{API}/playbooks/{pb['id']}/execute", headers=manager["headers"], json={"incident_id": inc["id"]}).json()
    t1, t2, _ = [t["id"] for t in ex["tasks"]]
    for tid in (t1,):
        client.post(f"{API}/playbooks/tasks/{tid}/assign", headers=manager["headers"], json={"assigned_to_id": manager["id"]})
        client.post(f"{API}/playbooks/tasks/{tid}/start", headers=manager["headers"])
        client.post(f"{API}/playbooks/tasks/{tid}/complete", headers=manager["headers"], json={})
    client.post(f"{API}/playbooks/tasks/{t2}/assign", headers=manager["headers"], json={"assigned_to_id": manager["id"]})
    client.post(f"{API}/playbooks/tasks/{t2}/start", headers=manager["headers"])
    assert client.post(f"{API}/playbooks/tasks/{t2}/complete", headers=manager["headers"], json={}).json()["status"] == "awaiting_approval"
    assert client.post(f"{API}/playbooks/tasks/{t2}/approve", headers=manager["headers"], json={}).status_code == 403


def test_playbook_execution_rules(client, manager, analyst, analyst2, asset, make_alert):
    pb = client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK).json()
    wrong = client.post(f"{API}/playbooks", headers=manager["headers"], json={**PLAYBOOK, "name": "Phishing flow", "incident_category": "phishing"}).json()
    inc = incident_for(client, manager, asset, make_alert, assignee=analyst)
    assert client.post(f"{API}/playbooks/{wrong['id']}/execute", headers=analyst["headers"], json={"incident_id": inc["id"]}).status_code == 400
    ex = client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst["headers"], json={"incident_id": inc["id"]})
    assert ex.status_code == 201
    assert client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst["headers"], json={"incident_id": inc["id"]}).status_code == 409
    first = ex.json()["tasks"][0]["id"]
    assert client.post(f"{API}/playbooks/tasks/{first}/start", headers=analyst2["headers"]).status_code == 403  # not assignee
    assert client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst["headers"], json={"incident_id": 9999}).status_code == 404
    assert client.post(f"{API}/playbooks/executions/{ex.json()['id']}/cancel", headers=analyst["headers"], json={"reason": "False alarm"}).status_code == 200
    assert client.get(f"{API}/playbooks/tasks/mine", headers=analyst["headers"]).json()["total"] == 0


def test_playbook_on_sensitive_incident_hidden(client, manager, analyst, analyst2, asset, make_alert):
    pb = client.post(f"{API}/playbooks", headers=manager["headers"], json=PLAYBOOK).json()
    inc = incident_for(client, manager, asset, make_alert, sensitive=True, assignee=analyst)
    assert client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst2["headers"], json={"incident_id": inc["id"]}).status_code == 403
    ex = client.post(f"{API}/playbooks/{pb['id']}/execute", headers=analyst["headers"], json={"incident_id": inc["id"]}).json()
    assert client.get(f"{API}/playbooks/executions/{ex['id']}", headers=analyst2["headers"]).status_code == 403
    assert client.get(f"{API}/playbooks/executions", headers=analyst2["headers"]).json()["total"] == 0
