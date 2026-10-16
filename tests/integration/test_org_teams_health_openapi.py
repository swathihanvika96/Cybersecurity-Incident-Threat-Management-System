from openapi_spec_validator import validate

from tests.conftest import API


def test_organization_department_asset_hierarchy(client, it_admin, analyst, org, department, make_asset):
    assert client.post(f"{API}/organizations", headers=analyst["headers"], json={"name": "Nope Inc"}).status_code == 403
    assert client.post(f"{API}/organizations", headers=it_admin["headers"], json={"name": org["name"]}).status_code == 409
    assert client.post(f"{API}/departments", headers=it_admin["headers"],
                       json={"organization_id": org["id"], "name": department["name"]}).status_code == 409
    assert client.post(f"{API}/departments", headers=it_admin["headers"],
                       json={"organization_id": 999, "name": "Ghost"}).status_code == 404
    make_asset("a1"), make_asset("a2")
    r = client.get(f"{API}/departments/{department['id']}/assets", headers=analyst["headers"])
    assert r.status_code == 200 and r.json()["total"] == 2
    assert client.get(f"{API}/organizations", headers=analyst["headers"]).json()["total"] == 1
    assert client.patch(f"{API}/organizations/{org['id']}", headers=it_admin["headers"],
                        json={"industry": "Retail"}).json()["industry"] == "Retail"


def test_team_membership(client, manager, analyst, analyst2, it_admin):
    assert client.post(f"{API}/teams", headers=analyst["headers"], json={"name": "Blue Team"}).status_code == 403
    team = client.post(f"{API}/teams", headers=manager["headers"], json={"name": "Blue Team", "manager_id": manager["id"]})
    assert team.status_code == 201, team.text
    tid = team.json()["id"]
    assert client.post(f"{API}/teams", headers=manager["headers"], json={"name": "Blue Team"}).status_code == 409
    add = client.post(f"{API}/teams/{tid}/members", headers=manager["headers"], json={"user_id": analyst["id"]})
    assert add.status_code == 200 and len(add.json()["members"]) >= 1
    assert client.post(f"{API}/teams/{tid}/members", headers=manager["headers"], json={"user_id": analyst["id"]}).status_code == 409
    assert client.post(f"{API}/teams/{tid}/members", headers=manager["headers"], json={"user_id": 9999}).status_code == 404
    assert client.delete(f"{API}/teams/{tid}/members/{analyst['id']}", headers=manager["headers"]).status_code == 200
    assert client.delete(f"{API}/teams/{tid}/members/{analyst2['id']}", headers=manager["headers"]).status_code == 404


def test_team_members_can_work_team_remediation(client, manager, analyst, analyst2, asset):
    from datetime import datetime, timedelta, timezone
    tid = client.post(f"{API}/teams", headers=manager["headers"], json={"name": "Patch Team"}).json()["id"]
    client.post(f"{API}/teams/{tid}/members", headers=manager["headers"], json={"user_id": analyst["id"]})
    v = client.post(f"{API}/vulnerabilities", headers=manager["headers"],
                    json={"title": "Team vuln", "cvss_score": 6, "asset_ids": [asset["id"]]}).json()
    task = client.post(f"{API}/remediation/tasks", headers=manager["headers"], json={
        "vulnerability_id": v["id"], "title": "Team task", "assigned_team_id": tid,
        "due_date": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()}).json()
    assert client.post(f"{API}/remediation/tasks/{task['id']}/start", headers=analyst["headers"]).status_code == 200
    assert client.post(f"{API}/remediation/tasks/{task['id']}/start", headers=analyst2["headers"]).status_code == 403


def test_health_endpoints_are_public(client):
    assert client.get("/health").json()["status"] == "ok"
    ready = client.get("/health/ready")
    assert ready.status_code == 200 and ready.json()["database"] == "up"


def test_request_id_header_and_error_envelope(client):
    r = client.get(f"{API}/alerts", headers={"X-Request-ID": "abc-123"})
    assert r.headers["X-Request-ID"] == "abc-123" and r.json()["request_id"] == "abc-123"
    assert client.get("/no/such/route").json()["error"]["code"] == "not_found"


def test_openapi_document_is_valid_and_complete(client):
    spec = client.get("/openapi.json").json()
    validate(spec)
    assert spec["info"]["title"] and spec["openapi"].startswith("3.")
    assert "OAuth2PasswordBearer" in spec["components"]["securitySchemes"]
    tags = {t for path in spec["paths"].values() for op in path.values() for t in op.get("tags", [])}
    assert {"Authentication", "Incidents", "Vulnerabilities", "Audit Logs", "Reports", "SLA Management"} <= tags
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            assert op.get("summary"), f"{method.upper()} {path} has no summary"
            assert any(code.startswith("2") for code in op["responses"]), f"{method.upper()} {path} has no 2xx"
    public = {"/api/v1/auth/login", "/api/v1/auth/token", "/api/v1/auth/register", "/api/v1/auth/refresh",
              "/api/v1/auth/password-reset/request", "/api/v1/auth/password-reset/confirm", "/health", "/health/ready"}
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if path not in public:
                assert op.get("security"), f"{method.upper()} {path} is not protected in the schema"
    assert client.get("/docs").status_code == 200 and client.get("/redoc").status_code == 200
