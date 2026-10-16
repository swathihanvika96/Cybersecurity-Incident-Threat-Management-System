from tests.conftest import API, PASSWORD


def test_analyst_cannot_manage_users_or_assets(client, analyst, org):
    payload = {"email": "x@example.com", "full_name": "X Person", "password": PASSWORD}
    assert client.post(f"{API}/users", json=payload, headers=analyst["headers"]).status_code == 403
    assert client.post(f"{API}/assets", headers=analyst["headers"], json={
        "name": "a1", "asset_type": "server", "criticality": "low", "organization_id": org["id"]}).status_code == 403


def test_auditor_is_read_only(client, auditor, asset, make_alert):
    assert client.get(f"{API}/assets", headers=auditor["headers"]).status_code == 200
    assert client.post(f"{API}/alerts", headers=auditor["headers"], json={
        "title": "x y z", "source": "SIEM", "category": "malware", "severity": "low",
        "asset_id": asset["id"]}).status_code == 403
    assert client.get(f"{API}/audit-logs", headers=auditor["headers"]).status_code == 200


def test_it_admin_cannot_read_audit_logs(client, it_admin):
    assert client.get(f"{API}/audit-logs", headers=it_admin["headers"]).status_code == 403


def test_privilege_escalation_blocked(client, it_admin, roles, analyst):
    # nobody may grant a role holding permissions they lack
    r = client.put(f"{API}/users/{analyst['id']}/role", headers=it_admin["headers"],
                   json={"role_id": roles["security_manager"]})
    assert r.status_code == 403
    r = client.put(f"{API}/users/{analyst['id']}/role", headers=it_admin["headers"],
                   json={"role_id": roles["super_admin"]})
    assert r.status_code == 403


def test_super_admin_can_change_role(client, admin_h, analyst, roles):
    r = client.put(f"{API}/users/{analyst['id']}/role", headers=admin_h, json={"role_id": roles["auditor"]})
    assert r.status_code == 200 and r.json()["role"]["name"] == "auditor"


def test_duplicate_email_conflict(client, admin_h, analyst, roles):
    r = client.post(f"{API}/users", headers=admin_h, json={"email": analyst["email"].upper(), "full_name": "Dup Dup",
                                                          "password": PASSWORD, "role_id": roles["auditor"]})
    assert r.status_code == 409


def test_unknown_fields_rejected(client, admin_h, roles):
    r = client.post(f"{API}/users", headers=admin_h, json={"email": "m@example.com", "full_name": "Mass Assign",
                                                          "password": PASSWORD, "is_superuser": True})
    assert r.status_code == 422


def test_roles_expose_permissions(client, admin_h, roles):
    r = client.get(f"{API}/roles/{roles['auditor']}", headers=admin_h)
    assert r.status_code == 200
    names = {p["name"] if isinstance(p, dict) else p for p in r.json()["permissions"]}
    assert "audit:read" in names and "alert:write" not in names


def test_not_found_uses_error_envelope(client, admin_h):
    r = client.get(f"{API}/users/99999", headers=admin_h)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_phone_is_stored_normalised_and_validated(client, admin_h, roles):
    body = {"email": "swathi@example.com", "full_name": "Swathi", "phone": "98765 43210", "password": PASSWORD,
            "role_id": roles["auditor"]}
    r = client.post(f"{API}/users", headers=admin_h, json=body)
    assert r.status_code == 201 and r.json()["phone"] == "9876543210"
    assert client.patch(f"{API}/users/{r.json()['id']}", headers=admin_h, json={"phone": "+919876543210"}).json()["phone"] == "+919876543210"
    for bad in ("12345", "abcdefghij", "98765432101234567890"):
        assert client.post(f"{API}/users", headers=admin_h,
                           json={**body, "email": "x@example.com", "phone": bad}).status_code == 422
    reg = client.post(f"{API}/auth/register", json={"email": "reg@example.com", "full_name": "Reg User",
                                                    "password": PASSWORD, "phone": "9876543210"})
    assert reg.status_code == 201 and reg.json()["phone"] == "9876543210"
