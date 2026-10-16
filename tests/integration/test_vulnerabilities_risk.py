from tests.conftest import API


def make_vuln(client, headers, assets, **extra):
    body = {"title": "Heap overflow in libfoo", "cvss_score": 9.5, "asset_ids": [a["id"] for a in assets], **extra}
    return client.post(f"{API}/vulnerabilities", headers=headers, json=body)


def test_create_derives_severity_and_deadline(client, manager, asset):
    r = make_vuln(client, manager["headers"], [asset], cve_id="cve-2024-1111")
    assert r.status_code == 201, r.text
    v = r.json()
    assert v["severity"] == "critical" and v["cve_id"] == "CVE-2024-1111" and v["remediation_deadline"]
    assert v["status"] == "open" and v["reference"].startswith("VULN-")


def test_vulnerability_validation(client, manager, asset):
    assert make_vuln(client, manager["headers"], [asset], cvss_score=11).status_code == 422
    assert make_vuln(client, manager["headers"], [asset], cve_id="not-a-cve").status_code == 422
    assert make_vuln(client, manager["headers"], [{"id": 9999}]).status_code == 404


def test_duplicate_cve_conflict(client, manager, asset):
    assert make_vuln(client, manager["headers"], [asset], cve_id="CVE-2024-2222").status_code == 201
    assert make_vuln(client, manager["headers"], [asset], cve_id="CVE-2024-2222").status_code == 409


def test_it_admin_cannot_write_vulnerabilities(client, it_admin, asset):
    assert make_vuln(client, it_admin["headers"], [asset]).status_code == 403
    assert client.get(f"{API}/vulnerabilities", headers=it_admin["headers"]).status_code == 200


def test_mapping_is_idempotent_and_filterable(client, manager, asset, make_asset):
    other = make_asset("other")
    v = make_vuln(client, manager["headers"], [asset]).json()
    r = client.post(f"{API}/vulnerabilities/{v['id']}/assets", headers=manager["headers"],
                    json={"asset_ids": [asset["id"], other["id"]]})
    assert r.status_code == 201
    assert client.get(f"{API}/vulnerabilities/{v['id']}/assets", headers=manager["headers"]).json()["total"] == 2
    assert client.get(f"{API}/vulnerabilities", headers=manager["headers"],
                      params={"asset_id": other["id"]}).json()["total"] == 1


def test_risk_scores_follow_documented_formula(client, manager, asset):
    v = make_vuln(client, manager["headers"], [asset], cvss_score=9.5).json()  # high-criticality asset, critical vuln
    items = client.get(f"{API}/risks/assessments", headers=manager["headers"],
                       params={"vulnerability_id": v["id"]}).json()["items"]
    assert len(items) == 1
    expected = round(3 * 4 / 16 * 70 + 9.5 / 10 * 30, 2)
    assert items[0]["risk_score"] == expected and items[0]["formula_version"] == "v1"
    formula = client.get(f"{API}/risks/formula", headers=manager["headers"]).json()
    assert formula["version"] == "v1" and formula["level_bands"]


def test_changing_asset_criticality_recalculates_risk(client, manager, it_admin, asset):
    make_vuln(client, manager["headers"], [asset])
    before = client.get(f"{API}/risks/assets/{asset['id']}", headers=manager["headers"]).json()["risk_score"]
    client.patch(f"{API}/assets/{asset['id']}", headers=it_admin["headers"], json={"criticality": "low"})
    after = client.get(f"{API}/risks/assets/{asset['id']}", headers=manager["headers"]).json()["risk_score"]
    assert after < before
    history = client.get(f"{API}/risks/assessments", headers=manager["headers"], params={"current_only": False}).json()
    assert history["total"] == 2  # old assessment kept as history


def test_high_risk_asset_ranking(client, manager, asset, make_asset):
    critical = make_asset("crown-jewel", "critical")
    make_vuln(client, manager["headers"], [asset, critical])
    ranked = client.get(f"{API}/risks/high-risk-assets", headers=manager["headers"], params={"min_level": "low"}).json()
    assert [r["asset"]["name"] for r in ranked][0] == "crown-jewel"


def test_risk_acceptance_removes_risk_and_can_be_revoked(client, manager, analyst, asset):
    v = make_vuln(client, manager["headers"], [asset]).json()
    body = {"asset_id": asset["id"], "vulnerability_id": v["id"], "justification": "Legacy system, compensating controls"}
    assert client.post(f"{API}/risks/acceptances", headers=analyst["headers"], json=body).status_code == 403
    r = client.post(f"{API}/risks/acceptances", headers=manager["headers"], json=body)
    assert r.status_code == 201, r.text
    assert client.get(f"{API}/risks/assets/{asset['id']}", headers=manager["headers"]).json()["risk_score"] == 0
    assert client.post(f"{API}/risks/acceptances", headers=manager["headers"], json=body).status_code == 409
    rv = client.post(f"{API}/risks/acceptances/{r.json()['id']}/revoke", headers=manager["headers"], json={"reason": "No longer valid"})
    assert rv.status_code == 200 and rv.json()["status"] == "revoked"
    assert client.get(f"{API}/risks/assets/{asset['id']}", headers=manager["headers"]).json()["risk_score"] > 0


def test_vulnerability_status_and_history(client, manager, asset):
    v = make_vuln(client, manager["headers"], [asset]).json()
    assert client.patch(f"{API}/vulnerabilities/{v['id']}/status", headers=manager["headers"],
                        json={"status": "under_review"}).status_code == 200
    assert client.patch(f"{API}/vulnerabilities/{v['id']}", headers=manager["headers"], json={"cvss_score": 5.0}).status_code == 200
    hist = client.get(f"{API}/vulnerabilities/{v['id']}/history", headers=manager["headers"]).json()
    assert hist["total"] >= 3
