# Swagger / OpenAPI verification

Verified against the live server at `http://127.0.0.1:8011` (OpenAPI 3.1.0, API version 1.0.0).

## Checks

| Result | Check | Detail |
|---|---|---|
| PASS | OpenAPI document validates against the specification | OpenAPI 3.1.0 |
| PASS | Swagger UI served at /docs |  |
| PASS | ReDoc served at /redoc |  |
| PASS | 'Authorize' button: OAuth2 password flow declared | {'scopes': {}, 'tokenUrl': '/api/v1/auth/token'} |
| PASS | Token endpoint accepts the Swagger form login |  |
| PASS | Every operation has a summary | 167 operations |
| PASS | Every operation documents a 2xx response |  |
| PASS | Every non-public operation declares security |  |
| PASS | Protected operations document 401/403/404/409 error envelopes |  |
| PASS | All tags are described | [] |
| PASS | Every JSON request body has a Swagger example |  |
| PASS | Real responses conform to documented schemas | 47 validated, 0 mismatches |

## Surface: 167 operations / 135 paths / 203 schemas

### Authentication

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| POST | `/api/v1/auth/change-password` | Change own password | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/login` | Log in (JSON) | public | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/logout` | Log out and invalidate the tokens | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/auth/me` | Current user | Bearer | 200 | 400,401,403,404,409 |
| POST | `/api/v1/auth/password-reset/confirm` | Set a new password with a reset token | public | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/password-reset/request` | Request a password reset | public | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/refresh` | Rotate tokens with a refresh token | public | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/register` | Register an account | public | 201 | 400,401,403,404,409,422 |
| POST | `/api/v1/auth/token` | Log in (OAuth2 form, used by Swagger 'Authorize') | public | 200 | 400,401,403,404,409,422 |

### Users

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/users` | List users | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/users` | Create a user | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/users/{user_id}` | Get a user | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/users/{user_id}` | Update a user | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/users/{user_id}/activate` | Activate an account | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/users/{user_id}/deactivate` | Deactivate an account | Bearer | 200 | 400,401,403,404,409,422 |
| PUT | `/api/v1/users/{user_id}/role` | Assign a role | Bearer | 200 | 400,401,403,404,409,422 |

### Roles & Permissions

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/roles` | List roles with their permissions | Bearer | 200 | 400,401,403,404,409 |
| POST | `/api/v1/roles` | Create a custom role | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/roles/permissions` | List every permission in the system | Bearer | 200 | 400,401,403,404,409 |
| DELETE | `/api/v1/roles/{role_id}` | Delete a custom role | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/roles/{role_id}` | Get a role | Bearer | 200 | 400,401,403,404,409,422 |
| PUT | `/api/v1/roles/{role_id}/permissions` | Replace a role's permission set | Bearer | 200 | 400,401,403,404,409,422 |

### Organizations

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/organizations` | List organizations | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/organizations` | Register an organization | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/organizations/{organization_id}` | Get an organization | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/organizations/{organization_id}` | Update an organization | Bearer | 200 | 400,401,403,404,409,422 |

### Departments

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/departments` | List departments | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/departments` | Register a department | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/departments/{department_id}` | Get a department | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/departments/{department_id}` | Update a department | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/departments/{department_id}/assets` | View assets by department | Bearer | 200 | 400,401,403,404,409,422 |

### Security Teams

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/teams` | List teams | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/teams` | Create a security team | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/teams/{team_id}` | Get a team with its members | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/teams/{team_id}` | Update a team | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/teams/{team_id}/members` | Assign an analyst to the team | Bearer | 200 | 400,401,403,404,409,422 |
| DELETE | `/api/v1/teams/{team_id}/members/{user_id}` | Remove a member from the team | Bearer | 200 | 400,401,403,404,409,422 |

### Assets

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/assets` | Search and filter assets | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/assets` | Register an asset (server, endpoint, application or database) | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/assets/{asset_id}` | Get an asset | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/assets/{asset_id}` | Update an asset | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/assets/{asset_id}/history` | Asset change history | Bearer | 200 | 400,401,403,404,409,422 |
| PUT | `/api/v1/assets/{asset_id}/owner` | Assign (or clear) the asset owner | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/assets/{asset_id}/status` | Change the asset status | Bearer | 200 | 400,401,403,404,409,422 |

### Security Alerts

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/alerts` | Search, filter, sort and paginate alerts | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/alerts` | Create a security alert | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/alerts/{alert_id}` | Get an alert | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/alerts/{alert_id}` | Update an alert | Bearer | 200 | 400,401,403,404,409,422 |
| PUT | `/api/v1/alerts/{alert_id}/assignee` | Assign (or un-assign) an alert | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/alerts/{alert_id}/status` | Change the alert status | Bearer | 200 | 400,401,403,404,409,422 |

### Alert Correlation

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/correlations` | List correlation groups | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/correlations` | Group related alerts manually | Bearer | 201 | 400,401,403,404,409,422 |
| POST | `/api/v1/correlations/auto` | Group repeated alerts automatically | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/correlations/repeated-alerts` | Identify repeated alerts affecting the same asset | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/correlations/{correlation_id}` | Get a correlation group | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/correlations/{correlation_id}/alerts` | Add alerts to a correlation | Bearer | 200 | 400,401,403,404,409,422 |
| DELETE | `/api/v1/correlations/{correlation_id}/alerts/{alert_id}` | Remove an alert from a correlation | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/correlations/{correlation_id}/history` | Correlation history | Bearer | 200 | 400,401,403,404,409,422 |

### Incidents

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/incidents` | List incidents | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents` | Create an incident (from alerts, a correlation group, or manually) | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/incidents/{incident_id}` | Get an incident with its linked alerts | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/incidents/{incident_id}` | Update an incident | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/alerts` | Link more alerts to the incident | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/assign` | Assign a responsible analyst | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/incidents/{incident_id}/assignments` | Assignment history | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/closure/approve` | Approve closure | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/closure/reject` | Reject closure | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/closure/request` | Request closure approval | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/incidents/{incident_id}/history` | Incident history | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/incidents/{incident_id}/notes` | Investigation notes | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/notes` | Add an investigation note | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/incidents/{incident_id}/related` | Related incidents | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/related` | Mark another incident as related | Bearer | 201 | 400,401,403,404,409,422 |
| POST | `/api/v1/incidents/{incident_id}/resolve` | Resolve an incident | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/incidents/{incident_id}/status` | Change the incident status | Bearer | 200 | 400,401,403,404,409,422 |

### Search

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/search` | Search incidents and alerts together | Bearer | 200 | 400,401,403,404,409,422 |

### Vulnerabilities

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/vulnerabilities` | Search and filter vulnerabilities | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/vulnerabilities` | Record a vulnerability (optionally mapped to affected assets) | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/vulnerabilities/{vulnerability_id}` | Get a vulnerability | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/vulnerabilities/{vulnerability_id}` | Update a vulnerability | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/vulnerabilities/{vulnerability_id}/assets` | Affected assets | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/vulnerabilities/{vulnerability_id}/assets` | Map the vulnerability to affected assets | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/vulnerabilities/{vulnerability_id}/history` | Vulnerability history | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/vulnerabilities/{vulnerability_id}/status` | Change the status | Bearer | 200 | 400,401,403,404,409,422 |

### Risk Assessment

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/risks/acceptances` | Risk acceptances | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/risks/acceptances` | Formally accept the risk of a vulnerability on an asset | Bearer | 201 | 400,401,403,404,409,422 |
| POST | `/api/v1/risks/acceptances/{acceptance_id}/revoke` | Revoke a risk acceptance | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/risks/assessments` | Risk assessments | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/risks/assets/{asset_id}` | Risk summary of one asset | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/risks/calculate` | Calculate / re-calculate risk scores | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/risks/formula` | The documented risk-scoring formula | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/risks/high-risk-assets` | Highest-risk assets | Bearer | 200 | 400,401,403,404,409,422 |

### Remediation

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/remediation/tasks` | Search and filter remediation tasks | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks` | Create a remediation task for a vulnerability | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/remediation/tasks/{task_id}` | Get a remediation task | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/remediation/tasks/{task_id}` | Update a remediation task | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/remediation/tasks/{task_id}/approvals` | Approval decisions | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/approve` | Approve the remediation | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/cancel` | Cancel the task | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/remediation/tasks/{task_id}/evidence` | Task evidence | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/evidence` | Attach evidence of the fix | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/remediation/tasks/{task_id}/history` | Task history | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/reject` | Reject the remediation | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/start` | Start work on the task | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/remediation/tasks/{task_id}/submit` | Submit the fix for approval | Bearer | 200 | 400,401,403,404,409,422 |

### Investigations

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/investigations` | List investigations | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations` | Open an investigation | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/investigations/{investigation_id}` | Get an investigation | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/investigations/{investigation_id}` | Update an investigation | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/close` | Close a completed investigation | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/complete` | Complete the investigation with a summary of findings | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/investigations/{investigation_id}/evidence` | List evidence (access is audited) | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/evidence` | Register evidence | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/investigations/{investigation_id}/evidence/{evidence_id}` | Get one piece of evidence (access is audited) | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/links` | Link incidents, alerts and assets | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/investigations/{investigation_id}/notes` | Investigation notes and events | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/notes` | Add an investigation note | Bearer | 201 | 400,401,403,404,409,422 |
| PUT | `/api/v1/investigations/{investigation_id}/owner` | Change the owner | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/investigations/{investigation_id}/start` | Start the investigation | Bearer | 200 | 400,401,403,404,409,422 |

### Response Playbooks

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/playbooks` | List playbooks | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks` | Create a playbook | Bearer | 201 | 400,401,403,404,409,422 |
| GET | `/api/v1/playbooks/executions` | List playbook executions | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/playbooks/executions/{execution_id}` | Get an execution | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/executions/{execution_id}/cancel` | Cancel a running execution | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/playbooks/executions/{execution_id}/history` | Execution history | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/playbooks/tasks/mine` | My playbook tasks | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/tasks/{task_id}/approve` | Approve a sensitive step | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/tasks/{task_id}/assign` | Assign a task to an analyst | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/tasks/{task_id}/complete` | Complete a task (the action is simulated) | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/tasks/{task_id}/reject` | Reject a sensitive step | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/tasks/{task_id}/start` | Start a task | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/playbooks/{playbook_id}` | Get a playbook | Bearer | 200 | 400,401,403,404,409,422 |
| PATCH | `/api/v1/playbooks/{playbook_id}` | Update a playbook | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/playbooks/{playbook_id}/execute` | Run a playbook against an incident (simulated) | Bearer | 201 | 400,401,403,404,409,422 |
| PUT | `/api/v1/playbooks/{playbook_id}/steps` | Replace the playbook steps | Bearer | 200 | 400,401,403,404,409,422 |

### SLA Management

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/slas/approaching` | Incidents approaching a deadline | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/slas/breached` | Incidents that breached an SLA | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/slas/escalated` | Escalated incidents | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/slas/evaluate` | Evaluate all open incidents now | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/slas/incidents/{incident_id}` | SLA of an incident | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/slas/incidents/{incident_id}/escalate` | Escalate manually | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/slas/incidents/{incident_id}/history` | SLA history | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/slas/policies` | SLA policy per severity | Bearer | 200 | 400,401,403,404,409 |
| PUT | `/api/v1/slas/policies/{severity}` | Update an SLA policy | Bearer | 200 | 400,401,403,404,409,422 |

### Audit Logs

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/audit-logs` | Search the audit trail (newest first) | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/audit-logs/{audit_log_id}` | Get one audit entry | Bearer | 200 | 400,401,403,404,409,422 |

### Notifications

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/notifications` | My notifications (newest first) | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/notifications/process` | Deliver queued notifications now | Bearer | 200 | 400,401,403,404,409 |
| POST | `/api/v1/notifications/read-all` | Mark all my notifications as read | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/notifications/unread-count` | Number of unread notifications | Bearer | 200 | 400,401,403,404,409 |
| POST | `/api/v1/notifications/{notification_id}/read` | Mark as read | Bearer | 200 | 400,401,403,404,409,422 |
| POST | `/api/v1/notifications/{notification_id}/unread` | Mark as unread | Bearer | 200 | 400,401,403,404,409,422 |

### Dashboard

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/dashboard` | Full dashboard summary | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/dashboard/alerts` | Alert counters | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/analyst-workload` | Workload per analyst | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/high-risk-assets` | High-risk assets | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/dashboard/incident-trend` | Incidents created/resolved per day | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/dashboard/incidents` | Incident counters | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/remediation` | Overdue remediation | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/response-times` | Average response / resolution times | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/sla` | SLA compliance | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/dashboard/vulnerabilities` | Vulnerability counters | Bearer | 200 | 400,401,403,404,409 |

### Reports

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/api/v1/reports` | Available reports | Bearer | 200 | 400,401,403,404,409 |
| GET | `/api/v1/reports/{report_type}` | Generate a report | Bearer | 200 | 400,401,403,404,409,422 |
| GET | `/api/v1/reports/{report_type}/export` | Export a report as CSV | Bearer | 200 | 400,401,403,404,409,422 |

### Health

| Method | Path | Summary | Auth | Success | Errors |
|---|---|---|---|---|---|
| GET | `/health` | Liveness probe | public | 200 |  |
| GET | `/health/ready` | Readiness probe (checks the database) | public | 200 | 503 |

## Request body examples shown in Swagger (Try it out)

**POST `/api/v1/alerts`** - Create a security alert

```json
{
  "asset_id": 1,
  "category": "unauthorized_access",
  "description": "52 failed attempts in 4 minutes",
  "detected_at": "2026-10-14T09:30:00Z",
  "severity": "high",
  "source": "SIEM",
  "title": "Multiple failed SSH logins from 203.0.113.50"
}
```

**PATCH `/api/v1/alerts/{alert_id}`** - Update an alert

```json
{
  "description": "Attempts increased to 310 in 10 minutes",
  "severity": "critical"
}
```

**PUT `/api/v1/alerts/{alert_id}/assignee`** - Assign (or un-assign) an alert

```json
{
  "assigned_to_id": 3
}
```

**PATCH `/api/v1/alerts/{alert_id}/status`** - Change the alert status

```json
{
  "comment": "Looking into it",
  "status": "acknowledged"
}
```

**POST `/api/v1/assets`** - Register an asset (server, endpoint, application or database)

```json
{
  "asset_type": "database",
  "criticality": "critical",
  "department_id": 1,
  "description": "Primary customer database",
  "hostname": "db-prod-01.acme.example.com",
  "ip_address": "10.0.1.15",
  "location": "Mumbai DC-2, Rack 14",
  "name": "db-prod-01",
  "organization_id": 1,
  "owner_id": 2,
  "status": "active"
}
```

**PATCH `/api/v1/assets/{asset_id}`** - Update an asset

```json
{
  "criticality": "high",
  "description": "Primary customer database",
  "location": "Hyderabad DC-1"
}
```

**PUT `/api/v1/assets/{asset_id}/owner`** - Assign (or clear) the asset owner

```json
{
  "owner_id": 2
}
```

**PATCH `/api/v1/assets/{asset_id}/status`** - Change the asset status

```json
{
  "reason": "Quarterly patch window",
  "status": "under_maintenance"
}
```

**POST `/api/v1/auth/change-password`** - Change own password

```json
{
  "current_password": "Swathi@12345",
  "new_password": "Swathi@67890"
}
```

**POST `/api/v1/auth/login`** - Log in (JSON)

```json
{
  "email": "admin@example.com",
  "password": "Admin@12345"
}
```

**POST `/api/v1/auth/password-reset/confirm`** - Set a new password with a reset token

```json
{
  "new_password": "Swathi@67890",
  "token": "<token from /auth/password-reset/request>"
}
```

**POST `/api/v1/auth/password-reset/request`** - Request a password reset

```json
{
  "email": "swathi@example.com"
}
```

**POST `/api/v1/auth/refresh`** - Rotate tokens with a refresh token

```json
{
  "refresh_token": "<refresh_token returned by /auth/login>"
}
```

**POST `/api/v1/auth/register`** - Register an account

```json
{
  "email": "swathi@example.com",
  "full_name": "Swathi",
  "password": "Swathi@12345",
  "phone": "9876543210"
}
```

**POST `/api/v1/correlations`** - Group related alerts manually

```json
{
  "alert_ids": [
    1,
    2,
    3
  ],
  "name": "Brute force campaign on db-prod-01"
}
```

**POST `/api/v1/correlations/{correlation_id}/alerts`** - Add alerts to a correlation

```json
{
  "alert_ids": [
    4,
    5
  ]
}
```

**POST `/api/v1/departments`** - Register a department

```json
{
  "description": "Owns production infrastructure",
  "name": "Platform Engineering",
  "organization_id": 1
}
```

**PATCH `/api/v1/departments/{department_id}`** - Update a department

```json
{
  "description": "Owns production infrastructure and CI/CD"
}
```

**POST `/api/v1/incidents`** - Create an incident (from alerts, a correlation group, or manually)

```json
{
  "alert_ids": [
    1,
    2,
    3
  ],
  "allow_duplicate": false,
  "description": "Repeated failed logins followed by a success",
  "is_sensitive": false,
  "title": "Credential attack on db-prod-01"
}
```

**PATCH `/api/v1/incidents/{incident_id}`** - Update an incident

```json
{
  "description": "Confirmed successful login from the attacking IP",
  "severity": "critical"
}
```

**POST `/api/v1/incidents/{incident_id}/alerts`** - Link more alerts to the incident

```json
{
  "alert_ids": [
    6
  ]
}
```

**POST `/api/v1/incidents/{incident_id}/assign`** - Assign a responsible analyst

```json
{
  "assigned_to_id": 3,
  "comment": "You own this one"
}
```

**POST `/api/v1/incidents/{incident_id}/closure/reject`** - Reject closure

```json
{
  "comment": "Verified by a second reviewer"
}
```

**POST `/api/v1/incidents/{incident_id}/notes`** - Add an investigation note

```json
{
  "content": "Source IP blocked at the firewall (simulated)."
}
```

**POST `/api/v1/incidents/{incident_id}/related`** - Mark another incident as related

```json
{
  "reason": "Same source IP",
  "related_incident_id": 2,
  "relation_type": "related"
}
```

**POST `/api/v1/incidents/{incident_id}/resolve`** - Resolve an incident

```json
{
  "resolution_details": "Blocked the source range, forced password reset and enabled MFA.",
  "resolution_summary": "Attack blocked and credentials rotated",
  "root_cause": "Weak password on a service account"
}
```

**PATCH `/api/v1/incidents/{incident_id}/status`** - Change the incident status

```json
{
  "comment": "Starting log review",
  "status": "investigating"
}
```

**POST `/api/v1/investigations`** - Open an investigation

```json
{
  "alert_ids": [
    1,
    2,
    3
  ],
  "asset_ids": [
    1
  ],
  "description": "Determine scope and impact",
  "incident_ids": [
    1
  ],
  "owner_id": 3,
  "title": "db-prod-01 credential attack"
}
```

**PATCH `/api/v1/investigations/{investigation_id}`** - Update an investigation

```json
{
  "description": "Scope: database tier and the bastion host"
}
```

**POST `/api/v1/investigations/{investigation_id}/complete`** - Complete the investigation with a summary of findings

```json
{
  "summary": "Credential stuffing from one botnet range; no data accessed."
}
```

**POST `/api/v1/investigations/{investigation_id}/evidence`** - Register evidence

```json
{
  "description": "auth.log, 14 Oct 09:00-09:30 UTC",
  "evidence_type": "log",
  "reference": "s3://evidence-vault/INV-2026-000001/auth.log",
  "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "title": "Auth log extract"
}
```

**POST `/api/v1/investigations/{investigation_id}/links`** - Link incidents, alerts and assets

```json
{
  "alert_ids": [],
  "asset_ids": [
    2
  ],
  "incident_ids": [
    2
  ]
}
```

**POST `/api/v1/investigations/{investigation_id}/notes`** - Add an investigation note

```json
{
  "content": "Source IP blocked at the firewall (simulated)."
}
```

**PUT `/api/v1/investigations/{investigation_id}/owner`** - Change the owner

```json
{
  "owner_id": 2
}
```

**POST `/api/v1/organizations`** - Register an organization

```json
{
  "contact_email": "security@acme.example.com",
  "contact_phone": "9876543210",
  "description": "Global payments company",
  "industry": "Finance",
  "name": "Acme Corporation"
}
```

**PATCH `/api/v1/organizations/{organization_id}`** - Update an organization

```json
{
  "contact_phone": "9876543210",
  "industry": "Banking"
}
```

**POST `/api/v1/playbooks`** - Create a playbook

```json
{
  "description": "Standard response to brute-force attacks",
  "incident_category": "unauthorized_access",
  "name": "Credential attack response",
  "steps": [
    {
      "simulated_action": "collect_logs",
      "step_type": "investigation",
      "title": "Collect authentication logs"
    },
    {
      "is_sensitive": true,
      "simulated_action": "block_ip_range",
      "step_type": "containment",
      "title": "Block source IP range"
    },
    {
      "simulated_action": "reset_passwords",
      "step_type": "recovery",
      "title": "Force password reset"
    }
  ]
}
```

**POST `/api/v1/playbooks/executions/{execution_id}/cancel`** - Cancel a running execution

```json
{
  "reason": "False alarm"
}
```

**POST `/api/v1/playbooks/tasks/{task_id}/assign`** - Assign a task to an analyst

```json
{
  "assigned_to_id": 3
}
```

**POST `/api/v1/playbooks/tasks/{task_id}/reject`** - Reject a sensitive step

```json
{
  "comment": "Containment verified"
}
```

**PATCH `/api/v1/playbooks/{playbook_id}`** - Update a playbook

```json
{
  "description": "Updated after the Q3 review",
  "is_active": true
}
```

**POST `/api/v1/playbooks/{playbook_id}/execute`** - Run a playbook against an incident (simulated)

```json
{
  "assignments": [
    {
      "step_order": 1,
      "user_id": 3
    }
  ],
  "incident_id": 1
}
```

**PUT `/api/v1/playbooks/{playbook_id}/steps`** - Replace the playbook steps

```json
{
  "steps": [
    {
      "step_type": "investigation",
      "title": "Collect authentication logs"
    },
    {
      "step_type": "recovery",
      "title": "Restore service"
    }
  ]
}
```

**POST `/api/v1/remediation/tasks`** - Create a remediation task for a vulnerability

```json
{
  "asset_id": 1,
  "assigned_to_id": 3,
  "description": "Apply vendor patch and restart sshd in the maintenance window",
  "due_date": "2026-10-21T18:30:00Z",
  "priority": "high",
  "title": "Upgrade OpenSSH on db-prod-01",
  "vulnerability_id": 1
}
```

**PATCH `/api/v1/remediation/tasks/{task_id}`** - Update a remediation task

```json
{
  "due_date": "2026-10-18T18:30:00Z",
  "priority": "urgent"
}
```

**POST `/api/v1/remediation/tasks/{task_id}/cancel`** - Cancel the task

```json
{
  "reason": "Asset decommissioned"
}
```

**POST `/api/v1/remediation/tasks/{task_id}/evidence`** - Attach evidence of the fix

```json
{
  "description": "Upgraded to OpenSSH 9.8p1; scan shows the CVE closed",
  "reference_type": "patch",
  "reference_url": "https://tickets.example.com/CHG-1042"
}
```

**POST `/api/v1/remediation/tasks/{task_id}/reject`** - Reject the remediation

```json
{
  "comments": "Evidence verified against the follow-up scan"
}
```

**POST `/api/v1/risks/acceptances`** - Formally accept the risk of a vulnerability on an asset

```json
{
  "asset_id": 2,
  "expires_at": "2027-03-31T18:30:00Z",
  "justification": "Legacy host behind a jump server; patch scheduled for Q1",
  "vulnerability_id": 1
}
```

**POST `/api/v1/risks/acceptances/{acceptance_id}/revoke`** - Revoke a risk acceptance

```json
{
  "reason": "Host is now internet-facing"
}
```

**POST `/api/v1/roles`** - Create a custom role

```json
{
  "description": "Hunts for threats; read-only on incidents",
  "name": "threat_hunter",
  "permissions": [
    "alert:read",
    "incident:read",
    "vulnerability:read"
  ]
}
```

**PUT `/api/v1/roles/{role_id}/permissions`** - Replace a role's permission set

```json
{
  "permissions": [
    "alert:read",
    "alert:write",
    "incident:read"
  ]
}
```

**POST `/api/v1/slas/incidents/{incident_id}/escalate`** - Escalate manually

```json
{
  "reason": "Customer-facing impact confirmed"
}
```

**PUT `/api/v1/slas/policies/{severity}`** - Update an SLA policy

```json
{
  "ack_minutes": 15,
  "investigation_minutes": 60,
  "resolution_minutes": 240
}
```

**POST `/api/v1/teams`** - Create a security team

```json
{
  "description": "Detection and response",
  "manager_id": 2,
  "name": "Blue Team",
  "team_type": "security"
}
```

**PATCH `/api/v1/teams/{team_id}`** - Update a team

```json
{
  "description": "24x7 detection and response",
  "is_active": true
}
```

**POST `/api/v1/teams/{team_id}/members`** - Assign an analyst to the team

```json
{
  "member_role": "analyst",
  "user_id": 3
}
```

**POST `/api/v1/users`** - Create a user

```json
{
  "department_id": 1,
  "email": "swathi@example.com",
  "full_name": "Swathi",
  "is_active": true,
  "organization_id": 1,
  "password": "Swathi@12345",
  "phone": "9876543210",
  "role_id": 3
}
```

**PATCH `/api/v1/users/{user_id}`** - Update a user

```json
{
  "department_id": 1,
  "full_name": "Swathi Hanvika",
  "phone": "9876543210"
}
```

**PUT `/api/v1/users/{user_id}/role`** - Assign a role

```json
{
  "role_id": 3
}
```

**POST `/api/v1/vulnerabilities`** - Record a vulnerability (optionally mapped to affected assets)

```json
{
  "asset_ids": [
    1
  ],
  "cve_id": "CVE-2024-6387",
  "cvss_score": 8.1,
  "description": "Race condition in sshd signal handler",
  "recommendation": "Upgrade OpenSSH to 9.8p1 or later",
  "title": "OpenSSH remote code execution (regreSSHion)"
}
```

**PATCH `/api/v1/vulnerabilities/{vulnerability_id}`** - Update a vulnerability

```json
{
  "cvss_score": 9.0,
  "recommendation": "Upgrade OpenSSH to 9.8p1 and restart sshd"
}
```

**POST `/api/v1/vulnerabilities/{vulnerability_id}/assets`** - Map the vulnerability to affected assets

```json
{
  "asset_ids": [
    1,
    2
  ],
  "notes": "Found by the weekly authenticated scan"
}
```

**PATCH `/api/v1/vulnerabilities/{vulnerability_id}/status`** - Change the status

```json
{
  "comment": "Confirmed on db-prod-01",
  "status": "under_review"
}
```

## Real sample responses (from the live demo run)

**POST /auth/login** -> `200`

```json
{
  "access_token": "<redacted>",
  "refresh_token": "<redacted>",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**POST /alerts** -> `201`

```json
{
  "id": 1,
  "reference": "ALR-2026-000001",
  "title": "Brute force attempt #0",
  "description": null,
  "source": "SIEM",
  "category": "unauthorized_access",
  "severity": "high",
  "status": "new",
  "asset": {
    "id": 1,
    "name": "db-955005",
    "asset_type": "database",
    "criticality": "critical"
  },
  "assigned_to": null,
  "detected_at": "2026-10-14T04:26:48.647337Z",
  "is_duplicate": false,
  "duplicate_of_id": null,
  "occurrence_count": 1,
  "correlation_id": null,
  "created_at": "2026-10-14T05:16:48.677943Z",
  "updated_at": "2026-10-14T05:16:48.679963Z"
}
```

**POST /incidents** -> `201`

```json
{
  "id": 1,
  "reference": "INC-2026-000001",
  "title": "Credential attack on db-955005",
  "description": null,
  "category": "unauthorized_access",
  "severity": "critical",
  "status": "new",
  "is_sensitive": false,
  "asset": {
    "id": 1,
    "name": "db-955005",
    "asset_type": "database",
    "criticality": "critical"
  },
  "correlation_id": 1,
  "assigned_to": null,
  "created_by_id": 4,
  "resolution_summary": null,
  "resolution_details": null,
  "root_cause": null,
  "resolved_at": null,
  "closed_at": null,
  "closure_requested_by_id": null,
  "closure_requested_at": null,
  "closure_approved_by_id": null,
  "closure_note": null,
  "sla": {
    "incident_id": 1,
    "severity": "critical",
    "ack_deadline": "2026-10-14T05:31:48.871387Z",
    "investigation_deadline": "2026-10-14T06:16:48.871387Z",
    "resolution_deadline": "2026-10-14T09:16:48.871387Z",
    "acknowledged_at": null,
    "investigation_started_at": null,
    "resolved_at": null,
    "response_time_minutes": null,
    "resolution_time_minutes": null,
    "ack_breached": false,
    "investigation_breached": false,
    "resolution_breached": false,
    "sla_status": "on_track",
    "escalation_status": "none",
    "escalation_level": 0,
    "escalated_at": null,
    "escalation_reason": null,
    "minutes_to_resolution_deadline": 240.0
  },
  "created_at": "2026-10-14T05:16:48.871387Z",
  "updated_at": "2026-10-14T05:16:48.876651Z",
  "alerts": [
    {
      "id": 1,
      "reference": "ALR-2026-000001",
      "title": "Brute force attempt #0",
      "severity": "high",
      "status": "in_progress",
      "detected_at": "2026-10-14T04:26:48.647337Z"
    },
    {
      "id": 2,
      "reference": "ALR-2026-000002",
      "title": "Brute force attempt #1",
      "severity": "high",
     
  ... (truncated)
```

**GET /risks/assets/1** -> `200`

```json
{
  "asset": {
    "id": 1,
    "name": "db-955005",
    "asset_type": "database",
    "criticality": "critical"
  },
  "risk_score": 76.8,
  "risk_level": "critical",
  "open_vulnerabilities": 1,
  "accepted_vulnerabilities": 0
}
```

**GET /slas/incidents/1** -> `200`

```json
{
  "incident_id": 1,
  "severity": "critical",
  "ack_deadline": "2026-10-14T05:31:48.871387Z",
  "investigation_deadline": "2026-10-14T06:16:48.871387Z",
  "resolution_deadline": "2026-10-14T09:16:48.871387Z",
  "acknowledged_at": "2026-10-14T05:16:48.919081Z",
  "investigation_started_at": "2026-10-14T05:16:49.278749Z",
  "resolved_at": null,
  "response_time_minutes": 0.0,
  "resolution_time_minutes": null,
  "ack_breached": false,
  "investigation_breached": false,
  "resolution_breached": false,
  "sla_status": "on_track",
  "escalation_status": "none",
  "escalation_level": 0,
  "escalated_at": null,
  "escalation_reason": null,
  "minutes_to_resolution_deadline": 240.0
}
```

**GET /dashboard** -> `200`

```json
{
  "generated_at": "2026-10-14T05:16:49.480302Z",
  "incidents": {
    "total": 1,
    "open": 0,
    "resolved": 1,
    "by_status": {
      "closed": 1
    },
    "by_severity": {
      "critical": 1
    }
  },
  "alerts": {
    "total": 3,
    "critical_total": 1,
    "critical_open": 0,
    "by_severity": {
      "critical": 1,
      "high": 2
    }
  },
  "vulnerabilities": {
    "total": 1,
    "unresolved": 1,
    "by_severity": {
      "high": 1
    },
    "by_status": {
      "in_remediation": 1
    }
  },
  "high_risk_assets": [
    {
      "asset": {
        "id": 2,
        "name": "web-955005",
        "asset_type": "server",
        "criticality": "high"
      },
      "risk_score": 63.67,
      "risk_level": "high",
      "open_vulnerabilities": 1
    }
  ],
  "response_times": {
    "average_response_minutes": 0.0,
    "average_resolution_minutes": 0.01,
    "incidents_measured": 1
  },
  "sla": {
    "tracked": 1,
    "compliant": 1,
    "breached": 0,
    "in_progress": 0,
    "compliance_percent": 100.0
  },
  "remediation": {
    "overdue": 0,
    "total_unfinished": 0
  },
  "analyst_workload": [
    {
      "user_id": 6,
      "full_name": "security_analyst 1",
      "open_incidents": 0,
      "open_alerts": 0,
      "open_remediation_tasks": 0,
      "open_playbook_tasks": 0,
      "total_open": 0
    }
  ],
  "incident_trend": [
    {
      "date": "2026-09-15",
      "created": 0,
      "resolved": 0
    },
    {
      "date": "2026-09-16",
      "created": 0,
      "resolved": 0
    },
    {
      "date": "2026-09-17",
      "created": 0,
      "resolved": 0
    },
    {
      "date": "2026-09-18",
      "created": 0,
      "resolved": 0
    },
    {
      "date": "2026-09-19",
      "created": 0,
      "resolved": 0
    },
    {
      "date":
  ... (truncated)
```

**GET /audit-logs** -> `200`

```json
{
  "items": [
    {
      "id": 37,
      "user_id": 4,
      "action": "report.export",
      "entity_type": "report",
      "entity_id": null,
      "previous_value": null,
      "new_value": {
        "report": "sla-compliance",
        "rows": 1,
        "parameters": {}
      },
      "ip_address": "127.0.0.1",
      "timestamp": "2026-10-14T05:16:49.563856Z"
    },
    {
      "id": 36,
      "user_id": 5,
      "action": "incident.closure_approve",
      "entity_type": "incident",
      "entity_id": 1,
      "previous_value": {
        "status": "resolved"
      },
      "new_value": {
        "status": "closed",
        "comment": null
      },
      "ip_address": "127.0.0.1",
      "timestamp": "2026-10-14T05:16:49.405147Z"
    },
    {
      "id": 35,
      "user_id": 4,
      "action": "incident.closure_request",
      "entity_type": "incident",
      "entity_id": 1,
      "previous_value": null,
      "new_value": {
        "comment": null
      },
      "ip_address": "127.0.0.1",
      "timestamp": "2026-10-14T05:16:49.383653Z"
    },
    {
      "id": 34,
      "user_id": 6,
      "action": "incident.resolve",
      "entity_type": "incident",
      "entity_id": 1,
      "previous_value": {
        "status": "investigating"
      },
      "new_value": {
        "status": "resolved",
        "resolution_summary": "Attack blocked"
      },
      "ip_address": "127.0.0.1",
      "timestamp": "2026-10-14T05:16:49.365083Z"
    },
    {
      "id": 33,
      "user_id": 6,
      "action": "incident.status_change",
      "entity_type": "incident",
      "entity_id": 1,
      "previous_value": {
        "status": "assigned"
      },
      "new_value": {
        "status": "investigating",
        "comment": null
      },
      "ip_address": "127.0.0.1",
      "times
  ... (truncated)
```
