"""Realistic example payloads shown in Swagger UI ("Try it out") for every request body.

They are attached to the models centrally (see `apply_examples`) so schema files stay uncluttered. A unit test
validates every example against its model, so an example can never drift out of sync with the schema.
IDs (1, 2, 3 ...) assume the objects created earlier in the demo flow.
"""
import importlib
import pkgutil

from pydantic import BaseModel

import app.schemas as _schemas_pkg
from app.schemas.common import RequestModel

SAMPLE_USER = {"full_name": "Swathi", "email": "swathi@example.com", "phone": "9876543210"}
STRONG_PASSWORD = "Swathi@12345"

EXAMPLES: dict[str, dict] = {
    # ------------------------------------------------------------------ authentication
    "RegisterRequest": {**SAMPLE_USER, "password": STRONG_PASSWORD},
    "LoginRequest": {"email": "admin@example.com", "password": "Admin@12345"},
    "RefreshRequest": {"refresh_token": "<refresh_token returned by /auth/login>"},
    "LogoutRequest": {"all_sessions": False},
    "PasswordResetRequest": {"email": "swathi@example.com"},
    "PasswordResetConfirm": {"token": "<token from /auth/password-reset/request>", "new_password": "Swathi@67890"},
    "PasswordChange": {"current_password": STRONG_PASSWORD, "new_password": "Swathi@67890"},
    # ------------------------------------------------------------------ users, roles, organisation
    "UserCreate": {**SAMPLE_USER, "password": STRONG_PASSWORD, "role_id": 3, "organization_id": 1,
                   "department_id": 1, "is_active": True},
    "UserUpdate": {"full_name": "Swathi Hanvika", "phone": "9876543210", "department_id": 1},
    "StatusChange": {"reason": "Left the security team"},
    "RoleAssign": {"role_id": 3},
    "RoleCreate": {"name": "threat_hunter", "description": "Hunts for threats; read-only on incidents",
                   "permissions": ["alert:read", "incident:read", "vulnerability:read"]},
    "RolePermissionsUpdate": {"permissions": ["alert:read", "alert:write", "incident:read"]},
    "OrganizationCreate": {"name": "Acme Corporation", "description": "Global payments company",
                           "industry": "Finance", "contact_email": "security@acme.example.com",
                           "contact_phone": "9876543210"},
    "OrganizationUpdate": {"industry": "Banking", "contact_phone": "9876543210"},
    "DepartmentCreate": {"organization_id": 1, "name": "Platform Engineering",
                         "description": "Owns production infrastructure"},
    "DepartmentUpdate": {"description": "Owns production infrastructure and CI/CD"},
    "TeamCreate": {"name": "Blue Team", "description": "Detection and response", "team_type": "security",
                   "manager_id": 2},
    "TeamUpdate": {"description": "24x7 detection and response", "is_active": True},
    "TeamMemberAdd": {"user_id": 3, "member_role": "analyst"},
    # ------------------------------------------------------------------ assets
    "AssetCreate": {"name": "db-prod-01", "asset_type": "database", "criticality": "critical", "status": "active",
                    "hostname": "db-prod-01.acme.example.com", "ip_address": "10.0.1.15",
                    "location": "Mumbai DC-2, Rack 14", "description": "Primary customer database",
                    "organization_id": 1, "department_id": 1, "owner_id": 2},
    "AssetUpdate": {"criticality": "high", "location": "Hyderabad DC-1", "description": "Primary customer database"},
    "AssetStatusUpdate": {"status": "under_maintenance", "reason": "Quarterly patch window"},
    "AssetOwnerAssign": {"owner_id": 2},
    # ------------------------------------------------------------------ alerts and correlation
    "AlertCreate": {"title": "Multiple failed SSH logins from 203.0.113.50", "description": "52 failed attempts in 4 minutes",
                    "source": "SIEM", "category": "unauthorized_access", "severity": "high", "asset_id": 1,
                    "detected_at": "2026-10-14T09:30:00Z"},
    "AlertUpdate": {"severity": "critical", "description": "Attempts increased to 310 in 10 minutes"},
    "AlertStatusUpdate": {"status": "acknowledged", "comment": "Looking into it"},
    "AlertAssign": {"assigned_to_id": 3},
    "CorrelationCreate": {"name": "Brute force campaign on db-prod-01", "alert_ids": [1, 2, 3]},
    "CorrelationAddAlerts": {"alert_ids": [4, 5]},
    "AutoCorrelateRequest": {"window_minutes": 120, "min_alerts": 3, "lookback_hours": 168},
    # ------------------------------------------------------------------ incidents
    "IncidentCreate": {"title": "Credential attack on db-prod-01", "description": "Repeated failed logins followed by a success",
                       "alert_ids": [1, 2, 3], "is_sensitive": False, "allow_duplicate": False},
    "IncidentUpdate": {"severity": "critical", "description": "Confirmed successful login from the attacking IP"},
    "IncidentStatusUpdate": {"status": "investigating", "comment": "Starting log review"},
    "IncidentAssign": {"assigned_to_id": 3, "comment": "You own this one"},
    "IncidentResolve": {"resolution_summary": "Attack blocked and credentials rotated",
                        "resolution_details": "Blocked the source range, forced password reset and enabled MFA.",
                        "root_cause": "Weak password on a service account"},
    "ClosureRequest": {"comment": "Root cause fixed and verified"},
    "ClosureDecision": {"comment": "Verified by a second reviewer"},
    "IncidentLinkAlerts": {"alert_ids": [6]},
    "IncidentRelationCreate": {"related_incident_id": 2, "relation_type": "related", "reason": "Same source IP"},
    "NoteCreate": {"content": "Source IP blocked at the firewall (simulated)."},
    # ------------------------------------------------------------------ vulnerabilities, risk
    "VulnerabilityCreate": {"title": "OpenSSH remote code execution (regreSSHion)", "description": "Race condition in sshd signal handler",
                            "cve_id": "CVE-2024-6387", "cvss_score": 8.1, "recommendation": "Upgrade OpenSSH to 9.8p1 or later",
                            "asset_ids": [1]},
    "VulnerabilityUpdate": {"cvss_score": 9.0, "recommendation": "Upgrade OpenSSH to 9.8p1 and restart sshd"},
    "VulnerabilityStatusUpdate": {"status": "under_review", "comment": "Confirmed on db-prod-01"},
    "MapAssets": {"asset_ids": [1, 2], "notes": "Found by the weekly authenticated scan"},
    "RiskCalculateRequest": {"asset_id": 1},
    "RiskAcceptanceCreate": {"asset_id": 2, "vulnerability_id": 1,
                             "justification": "Legacy host behind a jump server; patch scheduled for Q1",
                             "expires_at": "2027-03-31T18:30:00Z"},
    "RiskAcceptanceRevoke": {"reason": "Host is now internet-facing"},
    # ------------------------------------------------------------------ remediation
    "RemediationCreate": {"vulnerability_id": 1, "asset_id": 1, "title": "Upgrade OpenSSH on db-prod-01",
                          "description": "Apply vendor patch and restart sshd in the maintenance window",
                          "assigned_to_id": 3, "priority": "high", "due_date": "2026-10-21T18:30:00Z"},
    "RemediationUpdate": {"priority": "urgent", "due_date": "2026-10-18T18:30:00Z"},
    "RemediationEvidenceCreate": {"description": "Upgraded to OpenSSH 9.8p1; scan shows the CVE closed",
                                  "reference_type": "patch", "reference_url": "https://tickets.example.com/CHG-1042"},
    "CommentBody": {"comment": "Starting the change now"},
    "DecisionBody": {"comments": "Evidence verified against the follow-up scan"},
    "CancelBody": {"reason": "Asset decommissioned"},
    # ------------------------------------------------------------------ investigations
    "InvestigationCreate": {"title": "db-prod-01 credential attack", "description": "Determine scope and impact",
                            "owner_id": 3, "incident_ids": [1], "alert_ids": [1, 2, 3], "asset_ids": [1]},
    "InvestigationUpdate": {"description": "Scope: database tier and the bastion host"},
    "InvestigationLink": {"incident_ids": [2], "alert_ids": [], "asset_ids": [2]},
    "OwnerChange": {"owner_id": 2},
    "InvestigationComplete": {"summary": "Credential stuffing from one botnet range; no data accessed."},
    "EvidenceCreate": {"title": "Auth log extract", "evidence_type": "log", "description": "auth.log, 14 Oct 09:00-09:30 UTC",
                       "reference": "s3://evidence-vault/INV-2026-000001/auth.log",
                       "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
    # ------------------------------------------------------------------ playbooks
    "PlaybookStepIn": {"title": "Isolate host", "description": "Cut the host off the network", "step_type": "containment",
                       "is_sensitive": True, "simulated_action": "isolate_host"},
    "PlaybookCreate": {"name": "Credential attack response", "description": "Standard response to brute-force attacks",
                       "incident_category": "unauthorized_access",
                       "steps": [
                           {"title": "Collect authentication logs", "step_type": "investigation", "simulated_action": "collect_logs"},
                           {"title": "Block source IP range", "step_type": "containment", "is_sensitive": True,
                            "simulated_action": "block_ip_range"},
                           {"title": "Force password reset", "step_type": "recovery", "simulated_action": "reset_passwords"},
                       ]},
    "PlaybookUpdate": {"description": "Updated after the Q3 review", "is_active": True},
    "PlaybookStepsReplace": {"steps": [{"title": "Collect authentication logs", "step_type": "investigation"},
                                        {"title": "Restore service", "step_type": "recovery"}]},
    "StepAssignment": {"step_order": 1, "user_id": 3},
    "PlaybookExecute": {"incident_id": 1, "assignments": [{"step_order": 1, "user_id": 3}]},
    "TaskAssign": {"assigned_to_id": 3},
    "TaskComplete": {"notes": "Logs collected and attached to the investigation"},
    "TaskReview": {"comment": "Containment verified"},
    "ExecutionCancel": {"reason": "False alarm"},
    # ------------------------------------------------------------------ SLA
    "SLAPolicyUpdate": {"ack_minutes": 15, "investigation_minutes": 60, "resolution_minutes": 240},
    "EscalateRequest": {"reason": "Customer-facing impact confirmed"},
}


def _request_models() -> dict[str, type[BaseModel]]:
    found: dict[str, type[BaseModel]] = {}
    for info in pkgutil.iter_modules(_schemas_pkg.__path__):
        if info.name == "examples":
            continue
        module = importlib.import_module(f"app.schemas.{info.name}")
        for name, obj in vars(module).items():
            if (isinstance(obj, type) and issubclass(obj, RequestModel) and obj is not RequestModel
                    and not name.startswith("_") and obj.__module__ == module.__name__):
                found[name] = obj
    return found


def apply_examples() -> None:
    models = _request_models()
    for name, example in EXAMPLES.items():
        model = models[name]  # KeyError here means an example refers to a model that no longer exists
        extra = dict(model.model_config.get("json_schema_extra") or {})
        extra["examples"] = [example]
        model.model_config["json_schema_extra"] = extra
        model.model_rebuild(force=True)
