from tests.conftest import API


def seed(client, manager, analyst, asset, make_alert):
    a = make_alert(asset["id"], severity="critical")
    inc = client.post(f"{API}/incidents", headers=manager["headers"], json={"title": "Dash incident", "alert_ids": [a["id"]]}).json()
    client.post(f"{API}/incidents/{inc['id']}/assign", headers=manager["headers"], json={"assigned_to_id": analyst["id"]})
    client.post(f"{API}/vulnerabilities", headers=manager["headers"],
                json={"title": "Dash vuln", "cvss_score": 9.9, "cve_id": "CVE-2025-0001", "asset_ids": [asset["id"]]})
    return inc


def test_dashboard_on_empty_database_is_zeroed(client, manager):
    r = client.get(f"{API}/dashboard", headers=manager["headers"])
    assert r.status_code == 200
    d = r.json()
    assert d["incidents"]["total"] == 0 and d["alerts"]["total"] == 0 and d["vulnerabilities"]["total"] == 0
    assert d["high_risk_assets"] == [] and d["analyst_workload"] == []


def test_dashboard_reflects_live_records(client, manager, analyst, asset, make_alert):
    seed(client, manager, analyst, asset, make_alert)
    d = client.get(f"{API}/dashboard", headers=manager["headers"]).json()
    assert d["incidents"]["total"] == 1 and d["alerts"]["total"] == 1 and d["vulnerabilities"]["total"] == 1
    assert d["high_risk_assets"][0]["asset"]["id"] == asset["id"]
    assert any(w["user_id"] == analyst["id"] for w in d["analyst_workload"])
    assert sum(t["created"] for t in d["incident_trend"]) == 1
    # a change shows up on the very next call (no stale data)
    seed_alert = make_alert(asset["id"], title="Fresh alert", severity="low", category="phishing")
    assert client.get(f"{API}/dashboard/alerts", headers=manager["headers"]).json()["total"] == 2
    assert seed_alert["id"]


def test_dashboard_section_endpoints(client, manager, analyst, asset, make_alert):
    seed(client, manager, analyst, asset, make_alert)
    for section in ("incidents", "alerts", "vulnerabilities", "high-risk-assets", "response-times", "sla",
                    "remediation", "analyst-workload", "incident-trend"):
        assert client.get(f"{API}/dashboard/{section}", headers=manager["headers"]).status_code == 200, section
    assert client.get(f"{API}/dashboard", headers=manager["headers"], params={"days": 0}).status_code == 422


def test_dashboard_requires_permission(client, make_user):
    assert client.get(f"{API}/dashboard").status_code == 401


def test_report_catalogue_depends_on_permissions(client, manager, analyst):
    names = lambda u: {r["report"] for r in client.get(f"{API}/reports", headers=u["headers"]).json()}
    assert "analyst-performance" in names(manager) and "analyst-performance" not in names(analyst)
    assert len(names(manager)) == 8


def test_every_report_generates(client, manager, analyst, asset, make_alert):
    seed(client, manager, analyst, asset, make_alert)
    types = [r["report"] for r in client.get(f"{API}/reports", headers=manager["headers"]).json()]
    for t in types:
        r = client.get(f"{API}/reports/{t}", headers=manager["headers"])
        assert r.status_code == 200, (t, r.text)
        body = r.json()
        assert body["report"] == t and isinstance(body["rows"], list) and "summary" in body


def test_report_content_matches_data(client, manager, analyst, asset, make_alert):
    seed(client, manager, analyst, asset, make_alert)
    daily = client.get(f"{API}/reports/daily-incident-summary", headers=manager["headers"]).json()
    assert sum(r["incidents_created"] for r in daily["rows"]) == 1
    vul = client.get(f"{API}/reports/vulnerability-analysis", headers=manager["headers"], params={"severity": "critical"}).json()
    assert [r["cve_id"] for r in vul["rows"]] == ["CVE-2025-0001"]
    risk = client.get(f"{API}/reports/asset-risk", headers=manager["headers"]).json()
    assert risk["rows"][0]["asset_id"] == asset["id"]


def test_report_access_and_validation(client, analyst, auditor, manager):
    assert client.get(f"{API}/reports/analyst-performance", headers=analyst["headers"]).status_code == 403
    assert client.get(f"{API}/reports/analyst-performance", headers=manager["headers"]).status_code == 200
    assert client.get(f"{API}/reports/no-such-report", headers=manager["headers"]).status_code == 422
    assert client.get(f"{API}/reports/daily-incident-summary", headers=manager["headers"],
                      params={"date_from": "2026-02-01", "date_to": "2026-01-01"}).status_code == 400
    assert client.get(f"{API}/reports/daily-incident-summary", headers=manager["headers"],
                      params={"date_from": "2020-01-01", "date_to": "2026-01-01"}).status_code == 400  # > 366 days


def test_csv_export_permissions_content_and_audit(client, manager, analyst, auditor, asset, make_alert, admin_h):
    seed(client, manager, analyst, asset, make_alert)
    assert client.get(f"{API}/reports/vulnerability-analysis/export", headers=analyst["headers"]).status_code == 403
    r = client.get(f"{API}/reports/vulnerability-analysis/export", headers=auditor["headers"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"] and ".csv" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("reference,cve_id,title") and "CVE-2025-0001" in lines[1]
    logs = client.get(f"{API}/audit-logs", headers=admin_h, params={"action": "report.export"}).json()
    assert logs["total"] == 1 and logs["items"][0]["user_id"] == auditor["id"]


def test_csv_export_neutralises_formula_injection(client, manager, asset):
    client.post(f"{API}/vulnerabilities", headers=manager["headers"],
                json={"title": "=HYPERLINK(\"http://evil\")", "cvss_score": 5, "asset_ids": [asset["id"]]})
    r = client.get(f"{API}/reports/vulnerability-analysis/export", headers=manager["headers"])
    assert "'=HYPERLINK" in r.text and "\n=HYPERLINK" not in r.text and ",=HYPERLINK" not in r.text
