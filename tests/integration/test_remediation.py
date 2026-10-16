from datetime import datetime, timedelta, timezone

from tests.conftest import API


def due(days=5):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def setup_task(client, manager, analyst, asset, **extra):
    v = client.post(f"{API}/vulnerabilities", headers=manager["headers"],
                    json={"title": "Outdated TLS config", "cvss_score": 7.5, "asset_ids": [asset["id"]]}).json()
    body = {"vulnerability_id": v["id"], "asset_id": asset["id"], "title": "Fix TLS", "due_date": due(),
            "assigned_to_id": analyst["id"], **extra}
    r = client.post(f"{API}/remediation/tasks", headers=manager["headers"], json=body)
    assert r.status_code == 201, r.text
    return v, r.json()


def test_full_remediation_workflow(client, manager, manager2, analyst, asset):
    v, task = setup_task(client, manager, analyst, asset)
    tid = task["id"]
    base = f"{API}/remediation/tasks/{tid}"
    assert client.post(f"{base}/submit", headers=analyst["headers"]).status_code in (400, 409)  # not started
    assert client.post(f"{base}/start", headers=analyst["headers"]).status_code == 200
    assert client.post(f"{base}/submit", headers=analyst["headers"]).status_code in (400, 409)  # no evidence
    assert client.post(f"{base}/evidence", headers=analyst["headers"], json={"description": "TLS 1.0 disabled"}).status_code == 201
    assert client.post(f"{base}/submit", headers=analyst["headers"]).status_code == 200
    assert client.post(f"{base}/approve", headers=analyst["headers"], json={}).status_code == 403  # no approve permission
    assert client.post(f"{base}/approve", headers=manager2["headers"], json={}).status_code == 200
    assert client.get(f"{base}", headers=manager["headers"]).json()["status"] == "approved"
    vuln = client.get(f"{API}/vulnerabilities/{v['id']}", headers=manager["headers"]).json()
    assert vuln["status"] in ("mitigated", "closed")
    assert client.get(f"{base}/history", headers=manager["headers"]).json()["total"] >= 4
    assert client.get(f"{base}/approvals", headers=manager["headers"]).json()["total"] == 1


def test_submitter_cannot_approve_own_work(client, manager, analyst, asset):
    _, task = setup_task(client, manager, analyst, asset)
    base = f"{API}/remediation/tasks/{task['id']}"
    client.post(f"{base}/start", headers=manager["headers"])
    client.post(f"{base}/evidence", headers=manager["headers"], json={"description": "Done by manager"})
    assert client.post(f"{base}/submit", headers=manager["headers"]).status_code == 200
    assert client.post(f"{base}/approve", headers=manager["headers"], json={}).status_code == 403


def test_rejection_needs_comment_and_returns_task(client, manager, manager2, analyst, asset):
    _, task = setup_task(client, manager, analyst, asset)
    base = f"{API}/remediation/tasks/{task['id']}"
    client.post(f"{base}/start", headers=analyst["headers"])
    client.post(f"{base}/evidence", headers=analyst["headers"], json={"description": "Attempted fix"})
    client.post(f"{base}/submit", headers=analyst["headers"])
    assert client.post(f"{base}/reject", headers=manager2["headers"], json={}).status_code == 400
    r = client.post(f"{base}/reject", headers=manager2["headers"], json={"comments": "Evidence insufficient"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert client.post(f"{base}/start", headers=analyst["headers"]).status_code == 200  # rework allowed


def test_invalid_transitions_and_unrelated_user(client, manager, analyst, analyst2, asset):
    _, task = setup_task(client, manager, analyst, asset)
    base = f"{API}/remediation/tasks/{task['id']}"
    assert client.post(f"{base}/approve", headers=manager["headers"], json={}).status_code in (400, 409)
    assert client.post(f"{base}/start", headers=analyst2["headers"]).status_code == 403  # not assignee / team member
    assert client.post(f"{base}/cancel", headers=manager["headers"], json={"reason": "No longer needed"}).status_code == 200
    assert client.post(f"{base}/start", headers=analyst["headers"]).status_code in (400, 409)


def test_task_validation(client, manager, analyst, asset, make_asset):
    v, _ = setup_task(client, manager, analyst, asset)
    other = make_asset("unrelated")
    body = {"vulnerability_id": v["id"], "title": "x", "due_date": due()}
    assert client.post(f"{API}/remediation/tasks", headers=manager["headers"], json=body).status_code == 422
    body.update(title="Valid title", asset_id=other["id"])
    assert client.post(f"{API}/remediation/tasks", headers=manager["headers"], json=body).status_code in (400, 404)
    body.update(asset_id=asset["id"], due_date="2001-01-01T00:00:00Z")
    assert client.post(f"{API}/remediation/tasks", headers=manager["headers"], json=body).status_code in (400, 422)


def test_overdue_filter_and_flag(client, manager, analyst, asset, db):
    from app.models import RemediationTask
    _, task = setup_task(client, manager, analyst, asset)
    row = db.get(RemediationTask, task["id"])
    row.due_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
    db.commit()
    r = client.get(f"{API}/remediation/tasks", headers=manager["headers"], params={"overdue": True}).json()
    assert r["total"] == 1 and r["items"][0]["is_overdue"] is True
