from tests.conftest import API, PASSWORD, auth, login


def test_login_success_returns_tokens_and_me(client, analyst):
    tokens = login(client, analyst["email"], PASSWORD)
    assert tokens["token_type"] == "bearer" and tokens["expires_in"] > 0
    me = client.get(f"{API}/auth/me", headers=auth(tokens["access_token"])).json()
    assert me["email"] == analyst["email"] and "alert:read" in me["permissions"]


def test_wrong_password_and_unknown_user_are_indistinguishable(client, analyst):
    a = client.post(f"{API}/auth/login", json={"email": analyst["email"], "password": "Wrong1234x"})
    b = client.post(f"{API}/auth/login", json={"email": "nobody@example.com", "password": "Wrong1234x"})
    assert a.status_code == b.status_code == 401
    assert a.json()["error"]["message"] == b.json()["error"]["message"]
    assert a.json()["success"] is False and a.json()["request_id"]


def test_protected_endpoint_requires_token(client):
    assert client.get(f"{API}/alerts").status_code == 401
    assert client.get(f"{API}/alerts", headers=auth("garbage")).status_code == 401


def test_oauth2_form_login_for_swagger(client, analyst):
    r = client.post(f"{API}/auth/token", data={"username": analyst["email"], "password": PASSWORD})
    assert r.status_code == 200 and r.json()["access_token"]


def test_refresh_rotates_and_reuse_revokes_everything(client, analyst):
    first = login(client, analyst["email"], PASSWORD)
    second = client.post(f"{API}/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    # replaying the old refresh token is treated as theft: all sessions die
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.get(f"{API}/auth/me", headers=auth(second.json()["access_token"])).status_code == 401


def test_access_token_cannot_be_used_as_refresh(client, analyst):
    tokens = login(client, analyst["email"], PASSWORD)
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["access_token"]}).status_code == 401


def test_logout_invalidates_access_and_refresh_tokens(client, analyst):
    tokens = login(client, analyst["email"], PASSWORD)
    assert client.post(f"{API}/auth/logout", headers=auth(tokens["access_token"]), json={}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=auth(tokens["access_token"])).status_code == 401
    assert client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401


def test_registration_requires_activation(client, admin_h):
    r = client.post(f"{API}/auth/register", json={"email": "new@example.com", "full_name": "New Person",
                                                  "password": PASSWORD})
    assert r.status_code == 201 and r.json()["is_active"] is False
    assert client.post(f"{API}/auth/login", json={"email": "new@example.com", "password": PASSWORD}).status_code in (401, 403)
    assert client.post(f"{API}/users/{r.json()['id']}/activate", headers=admin_h).status_code == 200
    login(client, "new@example.com", PASSWORD)


def test_duplicate_registration_conflict(client, analyst):
    r = client.post(f"{API}/auth/register", json={"email": analyst["email"], "full_name": "Dup Person",
                                                  "password": PASSWORD})
    assert r.status_code == 409


def test_weak_password_rejected_with_validation_envelope(client):
    r = client.post(f"{API}/auth/register", json={"email": "w@example.com", "full_name": "Weak One",
                                                  "password": "weakpass"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"


def test_password_reset_flow(client, analyst):
    r = client.post(f"{API}/auth/password-reset/request", json={"email": analyst["email"]})
    assert r.status_code == 200
    token = r.json()["reset_token"]
    assert token  # EXPOSE_RESET_TOKEN=true in tests
    assert client.post(f"{API}/auth/password-reset/confirm",
                       json={"token": token, "new_password": "N3w!Passw0rd"}).status_code == 200
    login(client, analyst["email"], "N3w!Passw0rd")
    # token is single use
    assert client.post(f"{API}/auth/password-reset/confirm",
                       json={"token": token, "new_password": "An0ther!Pass"}).status_code == 400
    # old sessions were revoked
    assert client.get(f"{API}/auth/me", headers=analyst["headers"]).status_code == 401


def test_reset_request_for_unknown_email_does_not_leak(client):
    r = client.post(f"{API}/auth/password-reset/request", json={"email": "ghost@example.com"})
    assert r.status_code == 200 and not r.json().get("reset_token")


def test_change_password_requires_current_and_revokes_sessions(client, analyst):
    bad = client.post(f"{API}/auth/change-password", headers=analyst["headers"],
                      json={"current_password": "Nope12345", "new_password": "N3w!Passw0rd"})
    assert bad.status_code in (400, 401, 403)
    ok = client.post(f"{API}/auth/change-password", headers=analyst["headers"],
                     json={"current_password": PASSWORD, "new_password": "N3w!Passw0rd"})
    assert ok.status_code == 200
    # the current session stays valid, every other session is revoked
    assert client.get(f"{API}/auth/me", headers=analyst["headers"]).status_code == 200
    assert client.post(f"{API}/auth/login", json={"email": analyst["email"], "password": PASSWORD}).status_code == 401
    other = login(client, analyst["email"], "N3w!Passw0rd")
    assert client.post(f"{API}/auth/change-password", headers=auth(other["access_token"]),
                       json={"current_password": "N3w!Passw0rd", "new_password": "Th1rd!Passw0rd"}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=analyst["headers"]).status_code == 401


def test_deactivated_user_loses_access_immediately(client, admin_h, analyst):
    assert client.post(f"{API}/users/{analyst['id']}/deactivate", headers=admin_h, json={}).status_code == 200
    assert client.get(f"{API}/auth/me", headers=analyst["headers"]).status_code == 401
    assert client.post(f"{API}/auth/login", json={"email": analyst["email"], "password": PASSWORD}).status_code in (401, 403)


def test_failed_login_is_audited(client, admin_h, analyst):
    client.post(f"{API}/auth/login", json={"email": analyst["email"], "password": "Wrong1234x"})
    logs = client.get(f"{API}/audit-logs", headers=admin_h, params={"action": "auth.login_failed"}).json()
    assert logs["total"] >= 1
