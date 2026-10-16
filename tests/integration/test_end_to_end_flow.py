"""Mandatory demo flow: Admin Login -> Register Assets -> Create Alerts -> Correlate -> Create Incident -> Assign
Analyst -> Identify Vulnerabilities -> Calculate Risk -> Remediation -> Investigation -> Track SLA -> Resolve ->
Notifications -> Dashboard -> Export Reports -> Verify Audit Logs."""
from datetime import datetime, timedelta, timezone

from tests.conftest import API, ADMIN, auth, login


def test_full_security_workflow(client, manager, manager2, analyst, it_admin, auditor, org, department, make_asset):
    # 1. Admin login
    tokens = login(client, *ADMIN)
    admin_h = auth(tokens["access_token"])
    me = client.get(f"{API}/auth/me", headers=admin_h).json()
    assert me["role"]["name"] == "super_admin"

    # 2. Register assets
    db_asset = make_asset("db-01", "critical", asset_type="database")
    web_asset = make_asset("web-01", "high")
    assert db_asset["criticality"] == "critical"

    # 3. Create alerts (same asset + category, different titles, within the correlation window)
    base = datetime.now(timezone.utc) - timedelta(minutes=50)
    alert_ids = []
    for i in range(3):
        r = client.post(f"{API}/alerts", headers=manager["headers"], json={
            "title": f"Brute force attempt #{i}", "source": "SIEM", "category": "unauthorized_access",
            "severity": "high" if i < 2 else "critical", "asset_id": db_asset["id"],
            "detected_at": (base + timedelta(minutes=i * 15)).isoformat()})
        assert r.status_code == 201, r.text
        alert_ids.append(r.json()["id"])

    # 4. Correlate alerts
    r = client.get(f"{API}/correlations/repeated-alerts", headers=manager["headers"])
    assert r.status_code == 200 and len(r.json()) == 1
    r = client.post(f"{API}/correlations/auto", headers=manager["headers"])
    assert r.status_code == 200, r.text
    correlations = client.get(f"{API}/correlations", headers=manager["headers"]).json()
    assert correlations["total"] == 1
    correlation_id = correlations["items"][0]["id"]

    # 5. Create incident from the correlation group
    r = client.post(f"{API}/incidents", headers=manager["headers"],
                    json={"title": "Credential attack on db-01", "correlation_id": correlation_id,
                          "description": "Repeated failed logins"})
    assert r.status_code == 201, r.text
    incident = r.json()
    assert incident["severity"] == "critical" and incident["status"] == "new"
    assert incident["reference"].startswith("INC-")
    incident_id = incident["id"]

    # 6. Assign analyst
    r = client.post(f"{API}/incidents/{incident_id}/assign", headers=manager["headers"],
                    json={"assigned_to_id": analyst["id"]})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "assigned"

    # 7. Identify vulnerabilities
    r = client.post(f"{API}/vulnerabilities", headers=manager["headers"], json={
        "title": "OpenSSH remote code execution", "cve_id": "CVE-2024-6387", "cvss_score": 8.1,
        "asset_ids": [db_asset["id"], web_asset["id"]], "recommendation": "Upgrade OpenSSH"})
    assert r.status_code == 201, r.text
    vuln = r.json()
    assert vuln["severity"] == "high"

    # 8. Calculate risk
    r = client.post(f"{API}/risks/calculate", headers=manager["headers"], json={})
    assert r.status_code == 200, r.text
    r = client.get(f"{API}/risks/assets/{db_asset['id']}", headers=manager["headers"])
    assert r.status_code == 200
    db_risk, web_risk = r.json()["risk_score"], client.get(
        f"{API}/risks/assets/{web_asset['id']}", headers=manager["headers"]).json()["risk_score"]
    assert db_risk > web_risk > 0  # critical asset scores higher than high asset for the same vulnerability

    # 9. Create remediation task, work it, submit and approve (different person)
    due = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    r = client.post(f"{API}/remediation/tasks", headers=manager["headers"], json={
        "vulnerability_id": vuln["id"], "asset_id": db_asset["id"], "title": "Patch OpenSSH on db-01",
        "assigned_to_id": analyst["id"], "priority": "high", "due_date": due})
    assert r.status_code == 201, r.text
    task_id = r.json()["id"]
    assert client.post(f"{API}/remediation/tasks/{task_id}/start", headers=analyst["headers"]).status_code == 200
    r = client.post(f"{API}/remediation/tasks/{task_id}/submit", headers=analyst["headers"])
    assert r.status_code == 400 or r.status_code == 409, "submit without evidence must be refused"
    r = client.post(f"{API}/remediation/tasks/{task_id}/evidence", headers=analyst["headers"],
                    json={"description": "Upgraded to 9.8p1", "reference_type": "patch"})
    assert r.status_code == 201, r.text
    r = client.post(f"{API}/remediation/tasks/{task_id}/submit", headers=analyst["headers"])
    assert r.status_code == 200, r.text
    r = client.post(f"{API}/remediation/tasks/{task_id}/approve", headers=manager2["headers"], json={})
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    # approval re-calculates risk: db-01 no longer has an open exposure
    assert client.get(f"{API}/risks/assets/{db_asset['id']}", headers=manager["headers"]).json()["risk_score"] < db_risk

    # 10. Investigation
    r = client.post(f"{API}/investigations", headers=analyst["headers"],
                    json={"title": "db-01 credential attack", "incident_ids": [incident_id],
                          "asset_ids": [db_asset["id"]]})
    assert r.status_code == 201, r.text
    inv_id = r.json()["id"]
    assert client.post(f"{API}/incidents/{incident_id}/notes", headers=analyst["headers"],
                       json={"content": "Source IP blocked at the firewall (simulated)"}).status_code == 201
    r = client.post(f"{API}/investigations/{inv_id}/evidence", headers=analyst["headers"], json={
        "title": "Auth log extract", "evidence_type": "log", "reference": "s3://evidence/auth-2026.log"})
    assert r.status_code == 201, r.text
    r = client.post(f"{API}/investigations/{inv_id}/complete", headers=analyst["headers"],
                    json={"summary": "Credential stuffing from a single botnet range; no compromise."})
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text

    # 11. Track SLA
    assert client.patch(f"{API}/incidents/{incident_id}/status", headers=analyst["headers"],
                        json={"status": "investigating"}).status_code == 200
    r = client.get(f"{API}/slas/incidents/{incident_id}", headers=manager["headers"])
    assert r.status_code == 200, r.text
    sla = r.json()
    assert sla["acknowledged_at"] and sla["investigation_started_at"] and sla["sla_status"] in ("on_track", "at_risk")

    # 12. Resolve incident, then closure with four-eyes approval
    r = client.post(f"{API}/incidents/{incident_id}/resolve", headers=analyst["headers"], json={
        "resolution_summary": "Attack blocked", "resolution_details": "Blocked range, enforced MFA, patched SSH."})
    assert r.status_code == 200 and r.json()["status"] == "resolved", r.text
    assert client.post(f"{API}/incidents/{incident_id}/closure/request",
                       headers=manager["headers"]).status_code == 200
    r = client.post(f"{API}/incidents/{incident_id}/closure/approve", headers=manager["headers"])
    assert r.status_code == 403, "requester cannot approve their own closure"
    r = client.post(f"{API}/incidents/{incident_id}/closure/approve", headers=manager2["headers"])
    assert r.status_code == 200 and r.json()["status"] == "closed", r.text

    # 13. Notifications
    r = client.post(f"{API}/notifications/process", headers=admin_h)
    assert r.status_code == 200 and r.json()["delivered"] > 0
    r = client.get(f"{API}/notifications", headers=analyst["headers"])
    assert r.status_code == 200 and r.json()["total"] > 0
    types = {n["notification_type"] for n in r.json()["items"]}
    assert types, types

    # 14. Dashboard (live data)
    r = client.get(f"{API}/dashboard", headers=manager["headers"])
    assert r.status_code == 200, r.text
    dash = r.json()
    assert dash["incidents"]["total"] == 1 and dash["alerts"]["total"] == 3
    assert dash["vulnerabilities"]["total"] == 1

    # 15. Reports + CSV export
    r = client.get(f"{API}/reports/vulnerability-analysis", headers=manager["headers"])
    assert r.status_code == 200 and r.json()["rows"][0]["cve_id"] == "CVE-2024-6387"
    r = client.get(f"{API}/reports/sla-compliance/export", headers=auditor["headers"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.text.splitlines()[0].startswith("severity,incidents")

    # 16. Audit logs
    r = client.get(f"{API}/audit-logs", headers=auditor["headers"], params={"size": 100})
    assert r.status_code == 200, r.text
    actions = {e["action"] for e in r.json()["items"]}
    for expected in ("auth.login", "incident.create", "incident.assign", "vulnerability.create",
                     "remediation.approve", "report.export"):
        assert expected in actions, f"missing audit action {expected}: {sorted(actions)}"
