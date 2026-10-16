"""Enumerations, permission catalogue, role matrix and business-rule tables."""
from enum import StrEnum


# --------------------------------------------------------------------------- roles
class RoleName(StrEnum):
    SUPER_ADMIN = "super_admin"
    SECURITY_MANAGER = "security_manager"
    SECURITY_ANALYST = "security_analyst"
    IT_ADMINISTRATOR = "it_administrator"
    AUDITOR = "auditor"


# --------------------------------------------------------------------------- assets
class AssetType(StrEnum):
    SERVER = "server"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    DATABASE = "database"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


ASSET_CRITICALITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNDER_MAINTENANCE = "under_maintenance"
    DECOMMISSIONED = "decommissioned"


# --------------------------------------------------------------------------- alerts / incidents
class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class SecurityCategory(StrEnum):
    MALWARE = "malware"
    PHISHING = "phishing"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DENIAL_OF_SERVICE = "denial_of_service"
    POLICY_VIOLATION = "policy_violation"
    VULNERABILITY_EXPLOIT = "vulnerability_exploit"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    OTHER = "other"


class AlertStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


ALERT_ACTIVE_STATUSES = (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS)

ALERT_TRANSITIONS: dict[str, set[str]] = {
    "new": {"acknowledged", "in_progress", "false_positive"},
    "acknowledged": {"in_progress", "resolved", "false_positive"},
    "in_progress": {"resolved", "false_positive"},
    "resolved": {"in_progress"},
    "false_positive": {"new"},
}


class IncidentStatus(StrEnum):
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    RESOLVED = "resolved"
    CLOSED = "closed"


INCIDENT_OPEN_STATUSES = ("new", "assigned", "investigating", "containment")
INCIDENT_DONE_STATUSES = ("resolved", "closed")

# Status moves allowed through PATCH /incidents/{id}/status.
# "resolved" is reached via POST /resolve (needs resolution details) and "closed" only via closure approval.
INCIDENT_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "new": set(),  # must be assigned first
    "assigned": {"investigating"},
    "investigating": {"containment"},
    "containment": {"investigating"},
    "resolved": {"investigating"},  # re-open
    "closed": set(),
}
INCIDENT_RESOLVABLE_FROM = {"investigating", "containment"}


class CorrelationRule(StrEnum):
    SAME_ASSET_CATEGORY = "same_asset_category"
    MANUAL = "manual"


# --------------------------------------------------------------------------- vulnerabilities / risk
class VulnerabilitySeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VulnerabilityStatus(StrEnum):
    OPEN = "open"
    UNDER_REVIEW = "under_review"
    IN_REMEDIATION = "in_remediation"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


VULN_TRANSITIONS: dict[str, set[str]] = {
    "open": {"under_review", "in_remediation", "closed"},
    "under_review": {"open", "in_remediation", "closed"},
    "in_remediation": {"under_review", "mitigated"},
    "mitigated": {"in_remediation", "closed"},
    "accepted_risk": {"closed"},  # entered only through risk acceptance; left via revoke/expiry
    "closed": {"open"},
}
VULN_UNRESOLVED_STATUSES = ("open", "under_review", "in_remediation")

# default remediation deadline (days) when none is supplied
VULN_DEFAULT_DEADLINE_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}


class AssetVulnStatus(StrEnum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"
    CLOSED = "closed"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AcceptanceStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


# Risk scoring formula (version 1) - documented in README and GET /risks/formula
#   score = (criticality_weight * severity_weight) / 16 * 70  +  (cvss / 10) * 30      (0..100)
RISK_FORMULA_VERSION = "v1"
CRITICALITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
VULN_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
RISK_LEVEL_BANDS = [(75.0, "critical"), (50.0, "high"), (25.0, "medium"), (0.0, "low")]


# --------------------------------------------------------------------------- remediation
class Priority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class RemediationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


REMEDIATION_TRANSITIONS: dict[str, set[str]] = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"pending_approval", "cancelled"},
    "pending_approval": {"approved", "rejected"},
    "rejected": {"in_progress", "cancelled"},
    "approved": set(),
    "cancelled": set(),
}
REMEDIATION_UNFINISHED = ("open", "in_progress", "pending_approval", "rejected")


class ApprovalDecision(StrEnum):
    APPROVED = "approved"
    REJECTED = "rejected"


# --------------------------------------------------------------------------- investigations / playbooks
class InvestigationStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CLOSED = "closed"


class EvidenceType(StrEnum):
    LOG = "log"
    FILE = "file"
    SCREENSHOT = "screenshot"
    NETWORK_CAPTURE = "network_capture"
    MEMORY_DUMP = "memory_dump"
    REPORT = "report"
    OTHER = "other"


class PlaybookStepType(StrEnum):
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    RECOVERY = "recovery"


class PlaybookExecutionStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class PlaybookTaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    REJECTED = "rejected"


# --------------------------------------------------------------------------- SLA
class SLAStatus(StrEnum):
    ON_TRACK = "on_track"
    AT_RISK = "at_risk"
    BREACHED = "breached"
    MET = "met"


class EscalationStatus(StrEnum):
    NONE = "none"
    ESCALATED = "escalated"
    CRITICAL_ESCALATION = "critical_escalation"


# severity -> (acknowledgment, investigation start, resolution) in minutes
SLA_DEFAULT_POLICIES = {
    "critical": (15, 60, 240),
    "high": (30, 120, 480),
    "medium": (120, 480, 1440),
    "low": (480, 1440, 4320),
    "informational": (1440, 4320, 10080),
}


# --------------------------------------------------------------------------- notifications
class NotificationType(StrEnum):
    CRITICAL_INCIDENT = "critical_incident"
    INCIDENT_ASSIGNED = "incident_assigned"
    SLA_BREACH = "sla_breach"
    HIGH_RISK_VULNERABILITY = "high_risk_vulnerability"
    REMEDIATION_DEADLINE = "remediation_deadline"
    PENDING_APPROVAL = "pending_approval"
    INCIDENT_RESOLVED = "incident_resolved"
    RISK_ACCEPTANCE_EXPIRED = "risk_acceptance_expired"
    REMEDIATION_ASSIGNED = "remediation_assigned"
    REMEDIATION_DECISION = "remediation_decision"
    PLAYBOOK_TASK_ASSIGNED = "playbook_task_assigned"


class NotificationStatus(StrEnum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    FAILED = "failed"


# --------------------------------------------------------------------------- permissions
class P:
    """Permission names. Stored in the `permissions` table; granted to roles through `role_permissions`."""

    USER_READ = "user:read"
    USER_MANAGE = "user:manage"
    ROLE_MANAGE = "role:manage"
    ORG_READ = "organization:read"
    ORG_MANAGE = "organization:manage"
    ASSET_READ = "asset:read"
    ASSET_MANAGE = "asset:manage"
    TEAM_MANAGE = "team:manage"
    ALERT_READ = "alert:read"
    ALERT_WRITE = "alert:write"
    INCIDENT_READ = "incident:read"
    INCIDENT_WRITE = "incident:write"
    INCIDENT_ASSIGN = "incident:assign"
    INCIDENT_APPROVE_CLOSURE = "incident:approve_closure"
    INCIDENT_SENSITIVE = "incident:sensitive"
    VULN_READ = "vulnerability:read"
    VULN_WRITE = "vulnerability:write"
    RISK_READ = "risk:read"
    RISK_WRITE = "risk:write"
    RISK_ACCEPT = "risk:accept"
    REMEDIATION_READ = "remediation:read"
    REMEDIATION_WRITE = "remediation:write"
    REMEDIATION_APPROVE = "remediation:approve"
    INVESTIGATION_READ = "investigation:read"
    INVESTIGATION_WRITE = "investigation:write"
    EVIDENCE_READ = "evidence:read"
    PLAYBOOK_MANAGE = "playbook:manage"
    PLAYBOOK_EXECUTE = "playbook:execute"
    PLAYBOOK_APPROVE = "playbook:approve"
    SLA_READ = "sla:read"
    SLA_MANAGE = "sla:manage"
    AUDIT_READ = "audit:read"
    NOTIFICATION_MANAGE = "notification:manage"
    DASHBOARD_READ = "dashboard:read"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"
    REPORT_ANALYST = "report:analyst_performance"


ALL_PERMISSIONS: list[str] = [v for k, v in vars(P).items() if not k.startswith("_")]

_SECURITY_MANAGER = [
    P.USER_READ, P.ORG_READ, P.ASSET_READ, P.TEAM_MANAGE,
    P.ALERT_READ, P.ALERT_WRITE,
    P.INCIDENT_READ, P.INCIDENT_WRITE, P.INCIDENT_ASSIGN, P.INCIDENT_APPROVE_CLOSURE, P.INCIDENT_SENSITIVE,
    P.VULN_READ, P.VULN_WRITE, P.RISK_READ, P.RISK_WRITE, P.RISK_ACCEPT,
    P.REMEDIATION_READ, P.REMEDIATION_WRITE, P.REMEDIATION_APPROVE,
    P.INVESTIGATION_READ, P.INVESTIGATION_WRITE, P.EVIDENCE_READ,
    P.PLAYBOOK_MANAGE, P.PLAYBOOK_EXECUTE, P.PLAYBOOK_APPROVE,
    P.SLA_READ, P.SLA_MANAGE, P.AUDIT_READ, P.NOTIFICATION_MANAGE, P.DASHBOARD_READ,
    P.REPORT_READ, P.REPORT_EXPORT, P.REPORT_ANALYST,
]
_SECURITY_ANALYST = [
    P.ORG_READ, P.ASSET_READ, P.ALERT_READ, P.ALERT_WRITE, P.INCIDENT_READ, P.INCIDENT_WRITE,
    P.VULN_READ, P.VULN_WRITE, P.RISK_READ, P.REMEDIATION_READ, P.REMEDIATION_WRITE,
    P.INVESTIGATION_READ, P.INVESTIGATION_WRITE, P.EVIDENCE_READ, P.PLAYBOOK_EXECUTE,
    P.SLA_READ, P.DASHBOARD_READ, P.REPORT_READ,
]
_IT_ADMINISTRATOR = [
    P.USER_READ, P.USER_MANAGE, P.ORG_READ, P.ORG_MANAGE, P.ASSET_READ, P.ASSET_MANAGE,
    P.ALERT_READ, P.INCIDENT_READ, P.VULN_READ, P.RISK_READ,
    P.REMEDIATION_READ, P.REMEDIATION_WRITE, P.PLAYBOOK_EXECUTE, P.DASHBOARD_READ,
]
_AUDITOR = [
    P.USER_READ, P.ORG_READ, P.ASSET_READ, P.ALERT_READ, P.INCIDENT_READ, P.VULN_READ, P.RISK_READ,
    P.REMEDIATION_READ, P.INVESTIGATION_READ, P.SLA_READ, P.AUDIT_READ, P.DASHBOARD_READ,
    P.REPORT_READ, P.REPORT_EXPORT,
]

ROLE_PERMISSIONS: dict[str, list[str]] = {
    RoleName.SUPER_ADMIN: ALL_PERMISSIONS,
    RoleName.SECURITY_MANAGER: _SECURITY_MANAGER,
    RoleName.SECURITY_ANALYST: _SECURITY_ANALYST,
    RoleName.IT_ADMINISTRATOR: _IT_ADMINISTRATOR,
    RoleName.AUDITOR: _AUDITOR,
}

ROLE_DESCRIPTIONS = {
    RoleName.SUPER_ADMIN: "Full access to every function, including user and role administration.",
    RoleName.SECURITY_MANAGER: "Runs the security team: assigns incidents, approves closure/remediation, accepts risk.",
    RoleName.SECURITY_ANALYST: "Triages alerts, investigates incidents and works remediation/playbook tasks.",
    RoleName.IT_ADMINISTRATOR: "Maintains organizations, assets and user accounts; executes remediation work.",
    RoleName.AUDITOR: "Read-only access to records, audit logs and reports (no sensitive incident evidence).",
}
