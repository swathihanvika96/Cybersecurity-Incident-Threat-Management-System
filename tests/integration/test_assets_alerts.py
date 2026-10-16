from datetime import datetime, timedelta, timezone

from tests.conftest import API


def test_asset_crud_filter_and_history(client, it_admin, asset, make_asset, org):
    make_asset("db-9", "low", asset_type="database")
    r = client.get(f"{API}/assets", headers=it_admin["headers"], params={"asset_type": "database"})
    assert r.json()["total"] == 1 and r.json()["items"][0]["name"] == "db-9"
    r = client.get(f"{API}/assets", headers=it_admin["headers"], params={"q": "web-01"})
    assert r.json()["total"] == 1
    r = client.patch(f"{API}/assets/{asset['id']}", headers=it_admin["headers"], json={"criticality": "critical"})
    assert r.status_code == 200 and r.json()["criticality"] == "critical"
    hist = client.get(f"{API}/assets/{asset['id']}/history", headers=it_admin["headers"]).json()
    assert hist["total"] >= 1


def test_asset_validation(client, it_admin, org):
    base = {"name": "bad", "asset_type": "server", "criticality": "low", "organization_id": org["id"]}
    assert client.post(f"{API}/assets", headers=it_admin["headers"], json={**base, "ip_address": "999.1.1.1"}).status_code == 422
    assert client.post(f"{API}/assets", headers=it_admin["headers"], json={**base, "asset_type": "toaster"}).status_code == 422
    assert client.post(f"{API}/assets", headers=it_admin["headers"], json={**base, "organization_id": 9999}).status_code == 404


def test_pagination_bounds(client, it_admin):
    assert client.get(f"{API}/assets", headers=it_admin["headers"], params={"size": 0}).status_code == 422
    assert client.get(f"{API}/assets", headers=it_admin["headers"], params={"page": 0}).status_code == 422


def test_duplicate_alert_is_flagged_and_original_counts(client, asset, make_alert):
    first = make_alert(asset["id"])
    dup = make_alert(asset["id"], title="  multiple FAILED logins ")
    assert dup["is_duplicate"] is True and dup["duplicate_of_id"] == first["id"]


def test_original_alert_occurrence_count_increments(client, manager, asset, make_alert):
    first = make_alert(asset["id"])
    make_alert(asset["id"])
    make_alert(asset["id"], severity="critical")
    got = client.get(f"{API}/alerts/{first['id']}", headers=manager["headers"]).json()
    assert got["occurrence_count"] == 3 and got["severity"] == "critical"


def test_same_title_outside_window_is_not_duplicate(client, asset, make_alert):
    old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    make_alert(asset["id"], detected_at=old)
    assert make_alert(asset["id"])["is_duplicate"] is False


def test_different_asset_is_not_duplicate(client, asset, make_asset, make_alert):
    make_alert(asset["id"])
    assert make_alert(make_asset("other")["id"])["is_duplicate"] is False


def test_alert_validation_and_missing_asset(client, manager, asset):
    body = {"title": "ab", "source": "SIEM", "category": "malware", "severity": "high", "asset_id": asset["id"]}
    assert client.post(f"{API}/alerts", json=body, headers=manager["headers"]).status_code == 422
    body.update(title="Valid title", severity="apocalyptic")
    assert client.post(f"{API}/alerts", json=body, headers=manager["headers"]).status_code == 422
    body.update(severity="high", asset_id=9999)
    assert client.post(f"{API}/alerts", json=body, headers=manager["headers"]).status_code == 404


def test_alert_status_transitions(client, manager, asset, make_alert):
    alert = make_alert(asset["id"])
    url = f"{API}/alerts/{alert['id']}/status"
    assert client.patch(url, json={"status": "resolved"}, headers=manager["headers"]).status_code == 400  # new -> resolved
    assert client.patch(url, json={"status": "acknowledged"}, headers=manager["headers"]).status_code == 200
    assert client.patch(url, json={"status": "resolved"}, headers=manager["headers"]).status_code == 200


def test_alert_filters_sorting_and_search(client, manager, asset, make_alert):
    make_alert(asset["id"], title="Ransomware on host", severity="critical", category="malware")
    make_alert(asset["id"], title="Phishing mail reported", severity="low", category="phishing", source="Mail")
    h = manager["headers"]
    assert client.get(f"{API}/alerts", headers=h, params={"severity": "critical"}).json()["total"] == 1
    assert client.get(f"{API}/alerts", headers=h, params=[("severity", "critical"), ("severity", "low")]).json()["total"] == 2
    assert client.get(f"{API}/alerts", headers=h, params={"category": "phishing"}).json()["total"] == 1
    assert client.get(f"{API}/alerts", headers=h, params={"q": "ransom"}).json()["total"] == 1
    items = client.get(f"{API}/alerts", headers=h, params={"sort_by": "severity", "sort_order": "desc"}).json()["items"]
    assert [a["severity"] for a in items] == ["critical", "low"]
    assert client.get(f"{API}/alerts", headers=h, params={"sort_by": "password"}).status_code in (400, 422)
    assert client.get(f"{API}/alerts", headers=h, params={"date_from": "2030-01-02", "date_to": "2030-01-01"}).status_code in (400, 422)


def test_unified_search_across_incidents_and_alerts(client, manager, auditor, asset, make_alert):
    a = make_alert(asset["id"], title="Beacon to rare domain")
    client.post(f"{API}/incidents", headers=manager["headers"],
                json={"title": "Beacon incident", "alert_ids": [a["id"]]})
    r = client.get(f"{API}/search", headers=auditor["headers"], params={"q": "beacon"})
    assert r.status_code == 200 and r.json()["total"] == 2
    assert {i["entity_type"] for i in r.json()["items"]} == {"incident", "alert"}
    only = client.get(f"{API}/search", headers=auditor["headers"], params={"q": "beacon", "entity_types": "alert"})
    assert only.json()["total"] == 1
    ref = client.get(f"{API}/search", headers=auditor["headers"], params={"q": r.json()["items"][0]["reference"]})
    assert ref.json()["total"] >= 1
