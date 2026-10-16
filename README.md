# Security Incident, Alert & Vulnerability Management System

FastAPI backend for managing security alerts, incidents, vulnerabilities, risk, remediation, investigations,
response playbooks, SLAs, audit logs, notifications, dashboards and reports.

* **Stack:** Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, JWT, bcrypt, Pytest, Docker, optional Redis.
* **Databases:** PostgreSQL (docker-compose default), MySQL, SQLite (local dev / tests).
* **Swagger UI:** `/docs` · **ReDoc:** `/redoc` · **OpenAPI:** `/openapi.json` (a verified copy is in `docs/openapi.json`).

## Quick start (local)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env                  # defaults use SQLite
alembic upgrade head                  # create the schema
uvicorn app.main:app --reload         # roles, permissions, SLA policies and the first admin are seeded on startup
```

Open <http://localhost:8000/docs>, click **Authorize** and log in with `admin@example.com` / `Admin@12345`
(change these via `FIRST_SUPERADMIN_EMAIL` / `FIRST_SUPERADMIN_PASSWORD`; production refuses the default values).

### Docker

```bash
docker compose up --build             # api + postgres + redis; migrations run before the API starts
curl localhost:8000/health/ready
```

> The Docker/PostgreSQL/MySQL/Redis paths were written to the standard configuration but **could not be executed in the
> environment this project was built in**; everything else (migrations on SQLite, the API, all tests) was run.

### Tests

```bash
pytest                                # 224 tests, in-memory SQLite, ~30 s
```

Unit tests cover the risk formula, SLA state machine, alert clustering/fingerprints, JWT/password handling and CSV
safety. Integration tests cover every module with positive and negative cases (permissions, validation, state
transitions, four-eyes rules, sensitive-incident access, audit immutability) plus the full demo flow in
`tests/integration/test_end_to_end_flow.py`.

### Verify the running API end to end

```bash
python scripts/demo_flow.py           # the mandatory 16-step demo over HTTP (records docs/demo_run.json)
python scripts/verify_swagger.py      # validates /openapi.json and checks real responses against it
```

`docs/SWAGGER_VERIFICATION.md` is the output of the last run: spec validity, Swagger/ReDoc reachability, OAuth2
"Authorize" flow, every operation (method, path, auth, status codes) and real sample responses.

## Architecture

```
router (app/api/v1/<module>)  ->  service (business rules, commit)  ->  repository (queries)  ->  SQLAlchemy models
         Pydantic schemas (request/response)         core (config, security, permissions, exceptions)
```

* One router package per module, mirrored by `services/`, `repositories/`, `schemas/`, `models/`.
* Errors share one envelope: `{"success": false, "error": {"code", "message", "details"}, "request_id"}`.
* Lists are paginated (`?page=&size=`) and return `{items, total, page, size, pages}`; all list endpoints support
  filters and whitelisted sorting.
* Timestamps are stored as naive UTC and serialized as ISO-8601 UTC.
* Request bodies reject unknown fields (mass-assignment protection).
* **Swagger examples:** every request body ships a realistic example (e.g. name `Swathi`, phone `9876543210`) defined in
  `app/schemas/examples.py`; "Try it out" is pre-filled with it. A unit test keeps every example valid for its model.
  IDs in the examples (1, 2, 3...) assume the objects created earlier in the demo flow.
* Users have an optional `phone` (7-15 digits, optional leading `+`; spaces/dashes are stripped); organizations have `contact_phone`.

## Security model

* **Auth:** JWT access + refresh tokens. Each token carries a session id; logout, deactivation and password change
  revoke sessions. Refresh tokens rotate and **reuse of an old one revokes all of the user's sessions**.
  Passwords are bcrypt-hashed; login failures are indistinguishable for unknown e-mail vs wrong password and are audited.
* **Password reset** uses a single-use, hashed, expiring token. The "e-mail" is simulated: the token is returned in the
  response only when `EXPOSE_RESET_TOKEN=true` (development).
* **RBAC:** permissions are stored in the database and granted per role; every endpoint declares what it needs.
* **Privilege escalation guard:** nobody can grant a role containing permissions they do not hold; only a super admin
  can grant `super_admin`.
* **Sensitive incidents** are visible only to holders of `incident:sensitive`, the assignee and the creator - in lists,
  search, SLA views, investigations and playbook executions.
* **Four-eyes approvals:** incident closure, remediation approval and sensitive playbook steps must be approved by a
  different user from the requester/submitter/performer.
* **Audit log is append-only:** the API has no write endpoints for it (PUT/PATCH/DELETE return 405) and the ORM raises on
  any UPDATE/DELETE of an audit row. Evidence access, report exports and failed logins are audited.
* **Simulated actions only:** playbook steps record a *simulated* result; nothing touches a real system.
* **CSV export** neutralises spreadsheet formula injection.

### Roles

| Capability | Super Admin | Security Manager | Security Analyst | IT Administrator | Auditor |
|---|:-:|:-:|:-:|:-:|:-:|
| Users / roles administration | ✔ | read | – | users | read |
| Organizations, departments, assets | ✔ | read | read | ✔ manage | read |
| Alerts | ✔ | read/write | read/write | read | read |
| Incidents (create/update) | ✔ | ✔ | ✔ | read | read |
| Assign any analyst / approve closure | ✔ | ✔ | claim own only / – | – | – |
| Sensitive incidents | ✔ | ✔ | assignee/creator only | – | – |
| Vulnerabilities | ✔ | read/write | read/write | read | read |
| Risk calculate / accept risk | ✔ | ✔ | read | read | read |
| Remediation work / approve | ✔ | ✔ / ✔ | work / – | work / – | read |
| Investigations / evidence | ✔ | ✔ | ✔ | – | investigations read, **no evidence** |
| Playbooks manage / execute / approve | ✔ | ✔ | execute | execute | – |
| SLA read / manage | ✔ | ✔ | read | – | read |
| Audit logs | ✔ | ✔ | – | – | ✔ |
| Dashboard / reports / CSV export | ✔ | ✔ | dashboard + reports | dashboard | ✔ + export |

The authoritative list is `app/core/constants.py` (`ROLE_PERMISSIONS`); `GET /api/v1/roles/{id}` shows it live.

## Business rules

### Alert duplicate detection
Fingerprint = SHA-256 of `asset | category | source | normalised title` (case/whitespace-insensitive). An alert whose
fingerprint matches a non-duplicate alert detected within `DUPLICATE_ALERT_WINDOW_MINUTES` (60) is stored with
`is_duplicate=true` and `duplicate_of_id`; the original's `occurrence_count` is incremented and its severity raised if the
repeat is more severe.

### Alert correlation
Alerts of the **same asset and category** where each is detected within `window_minutes` (120) of the previous one form a
chain; chains of at least `min_alerts` (3) become a correlation group (`POST /correlations/auto`, preview with
`GET /correlations/repeated-alerts`). Groups can also be created and edited manually; history is recorded.

### Incident rules
* Statuses: `new → assigned → investigating ⇄ containment → resolved → closed`. Closing requires a resolution and
  approval (`closure/request` → `closure/approve|reject`); rejection re-opens to `investigating`.
* Severity defaults to the highest linked-alert severity; an SLA is attached at creation.
* **Duplicate incidents:** an *open* incident for the same asset and category created within
  `DUPLICATE_INCIDENT_WINDOW_HOURS` (24) is rejected with `409 duplicate_incident` unless `allow_duplicate=true`
  (then linked as a possible duplicate). An alert can belong to only one incident.

### Risk engine (formula `v1`)
```
impact         = criticality_weight × severity_weight / 16 × 70      weights: low 1, medium 2, high 3, critical 4
exploitability = cvss_score / 10 × 30
risk_score     = round(impact + exploitability, 2)                   range 0–100
level          = critical ≥ 75 · high ≥ 50 · medium ≥ 25 · low
asset risk     = highest current score among the asset's open (not accepted/mitigated) vulnerabilities
```
Worked example: critical database (4) + high vulnerability (3), CVSS 8.1 → 4×3/16×70 + 8.1/10×30 = 52.5 + 24.3 = **76.8 (critical)**.
Scores are recalculated when an asset's criticality, a vulnerability's CVSS/severity, a mapping, a remediation approval or a
risk acceptance changes; a new assessment row is written only when the score changes, so history stays meaningful.
`GET /risks/formula` returns the same description from the running system. Severity from CVSS follows the v3 bands
(9.0 critical, 7.0 high, 4.0 medium); default remediation deadlines are 7/30/90/180 days.

### SLA
Deadlines are measured from incident creation:

| Severity | Acknowledge (first assignment) | Start investigation | Resolve |
|---|---|---|---|
| critical | 15 min | 60 min | 4 h |
| high | 30 min | 2 h | 8 h |
| medium | 2 h | 8 h | 24 h |
| low | 8 h | 24 h | 72 h |
| informational | 24 h | 72 h | 168 h |

Policies are editable (`PUT /slas/policies/{severity}`). Status: `on_track`, `at_risk` (last 25 % of a window left),
`breached` (a deadline passed or was met late), `met`. Escalation level = number of breached phases
(`escalated` → `critical_escalation`); managers are notified. Manual escalation is available. A severity change
re-applies the policy.

### Remediation
`open → in_progress → pending_approval → approved | rejected → (rework) in_progress`; `cancelled` is terminal. Submitting
requires evidence; approval must come from someone other than the submitter and marks the vulnerability mitigated for that
asset. Deadline monitoring raises "due soon"/"overdue" notifications.

### Notifications and workers
Notifications are queued and delivered by a worker (simulated in-app delivery; the `_deliver` hook is where e-mail/webhook
would plug in). Set `ENABLE_BACKGROUND_WORKERS=true` to run the SLA monitor, remediation-deadline/risk-acceptance expiry
and delivery loops in a background thread, or run `python -m app.workers.runner` in one dedicated process. Each worker
also exposes `run_once()`, and managers can trigger delivery/SLA evaluation through the API.

### Dashboard and reports
All numbers are computed from live database rows (optionally cached in Redis for `DASHBOARD_CACHE_TTL_SECONDS`).
Reports: `daily-incident-summary`, `weekly-security-summary`, `vulnerability-analysis`, `asset-risk`,
`analyst-performance` (managers only), `sla-compliance`, `remediation-status`, `incident-resolution-trends`; each can be
exported as CSV (`/reports/{type}/export`, requires `report:export`, audited).

## API overview (`/api/v1`)

| Area | Prefix |
|---|---|
| Authentication | `/auth` (login, token, refresh, logout, me, register, password-reset, change-password) |
| Users, roles | `/users`, `/roles` |
| Organizations, departments, teams, assets | `/organizations`, `/departments`, `/teams`, `/assets` |
| Alerts, correlation | `/alerts`, `/correlations` |
| Incidents, search | `/incidents`, `/search` |
| Vulnerabilities, risk | `/vulnerabilities`, `/risks` |
| Remediation | `/remediation/tasks` |
| Investigations (notes, evidence) | `/investigations` |
| Playbooks, executions, tasks | `/playbooks` |
| SLA | `/slas` |
| Audit, notifications | `/audit-logs`, `/notifications` |
| Dashboard, reports | `/dashboard`, `/reports` |
| Health | `/health`, `/health/ready` (outside `/api/v1`) |

`docs/SWAGGER_VERIFICATION.md` lists every operation.

## Mandatory demo flow
Admin Login → Register Assets → Create Alerts → Correlate → Create Incident → Assign Analyst → Identify Vulnerabilities →
Calculate Risk → Create Remediation Task → Complete Investigation → Track SLA → Resolve Incident → Generate Notifications →
View Dashboard → Export Reports → Verify Audit Logs. Run it with `python scripts/demo_flow.py` or see
`tests/integration/test_end_to_end_flow.py`.

## Configuration
See `.env.example` for every setting (database URL, token lifetimes, rule windows, workers, Redis). With
`ENVIRONMENT=production` the app refuses to start with the default secret key/admin password or with
`EXPOSE_RESET_TOKEN=true`.

## Notes and deviations from the supplied structure
* Added an `app/api/v1/search` router (advanced search), `app/repositories/base.py`, `app/api/deps.py`, `scripts/` and
  `docs/` beyond the provided tree; everything else follows it.
* Migrations: `0001` initial schema, `0002` phone fields; `alembic check` reports no drift on SQLite. In development the app
  applies pending migrations at startup; in production run `alembic upgrade head` (the Dockerfile does).
* Not implemented (out of scope): real e-mail delivery, real enforcement of playbook actions (intentionally simulated),
  file upload for evidence (only references and SHA-256 are stored).
