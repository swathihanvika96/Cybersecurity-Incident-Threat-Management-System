"""Test fixtures: in-memory SQLite, fast bcrypt, one fresh seeded database per test."""
import os

# Must be set before the application (and its settings / engine) is imported.
os.environ.update(
    ENVIRONMENT="testing",
    DATABASE_URL="sqlite:///:memory:",
    BCRYPT_ROUNDS="4",
    SECRET_KEY="test-secret-key-test-secret-key-test-secret-key",
    FIRST_SUPERADMIN_EMAIL="admin@example.com",
    FIRST_SUPERADMIN_PASSWORD="Admin@12345",
    EXPOSE_RESET_TOKEN="true",
    AUTO_CREATE_TABLES="false",
    SEED_ON_STARTUP="false",
    ENABLE_BACKGROUND_WORKERS="false",
    LOG_JSON="false",
    LOG_LEVEL="WARNING",
    REDIS_URL="",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db.base import Base  # noqa: E402
from app.db.init_db import seed_all  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402

PASSWORD = "Str0ng!Passw0rd"
ADMIN = ("admin@example.com", "Admin@12345")
API = "/api/v1"


@pytest.fixture(autouse=True)
def database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_all(db)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def client():
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def login(client: TestClient, email: str, password: str) -> dict:
    r = client.post(f"{API}/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_h(client):
    return auth(login(client, *ADMIN)["access_token"])


@pytest.fixture
def roles(client, admin_h) -> dict[str, int]:
    r = client.get(f"{API}/roles", headers=admin_h)
    assert r.status_code == 200, r.text
    body = r.json()
    items = body["items"] if isinstance(body, dict) else body
    return {role["name"]: role["id"] for role in items}


@pytest.fixture
def make_user(client, admin_h, roles):
    counter = {"n": 0}

    def _make(role: str, **extra) -> dict:
        counter["n"] += 1
        email = f"{role}{counter['n']}@example.com"
        payload = {"email": email, "full_name": f"{role.title()} {counter['n']}", "password": PASSWORD,
                   "role_id": roles[role], **extra}
        r = client.post(f"{API}/users", json=payload, headers=admin_h)
        assert r.status_code == 201, r.text
        user = r.json()
        user["headers"] = auth(login(client, email, PASSWORD)["access_token"])
        user["password"] = PASSWORD
        return user

    return _make


@pytest.fixture
def manager(make_user):
    return make_user("security_manager")


@pytest.fixture
def manager2(make_user):
    return make_user("security_manager")


@pytest.fixture
def analyst(make_user):
    return make_user("security_analyst")


@pytest.fixture
def analyst2(make_user):
    return make_user("security_analyst")


@pytest.fixture
def it_admin(make_user):
    return make_user("it_administrator")


@pytest.fixture
def auditor(make_user):
    return make_user("auditor")


@pytest.fixture
def org(client, admin_h) -> dict:
    r = client.post(f"{API}/organizations", json={"name": "Acme Corp", "industry": "Finance"}, headers=admin_h)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def department(client, admin_h, org) -> dict:
    r = client.post(f"{API}/departments", json={"organization_id": org["id"], "name": "Engineering"},
                    headers=admin_h)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.fixture
def make_asset(client, it_admin, org, department):
    def _make(name="web-01", criticality="high", **extra) -> dict:
        payload = {"name": name, "asset_type": "server", "criticality": criticality, "organization_id": org["id"],
                   "department_id": department["id"], "hostname": f"{name}.acme.test", "ip_address": "10.0.0.5",
                   **extra}
        r = client.post(f"{API}/assets", json=payload, headers=it_admin["headers"])
        assert r.status_code == 201, r.text
        return r.json()

    return _make


@pytest.fixture
def asset(make_asset):
    return make_asset()


@pytest.fixture
def make_alert(client, manager):
    def _make(asset_id, title="Multiple failed logins", severity="high", category="unauthorized_access",
              source="SIEM", headers=None, **extra) -> dict:
        r = client.post(f"{API}/alerts", json={"title": title, "severity": severity, "category": category,
                                               "source": source, "asset_id": asset_id, **extra},
                        headers=headers or manager["headers"])
        assert r.status_code == 201, r.text
        return r.json()

    return _make
