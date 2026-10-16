"""Import every model so SQLAlchemy metadata (and Alembic autogenerate) sees all tables."""
from app.models.alert_correlation import AlertCorrelation, CorrelationHistory
from app.models.asset import Asset
from app.models.asset_history import AssetHistory
from app.models.asset_vulnerability import AssetVulnerability
from app.models.audit_log import AuditLog
from app.models.department import Department
from app.models.incident import Incident, IncidentRelation
from app.models.incident_alert import IncidentAlert
from app.models.incident_assignment import IncidentAssignment
from app.models.incident_history import IncidentHistory
from app.models.incident_sla import IncidentSLA, SLAPolicy
from app.models.investigation import (
    Investigation,
    InvestigationAlert,
    InvestigationAsset,
    InvestigationIncident,
)
from app.models.investigation_evidence import InvestigationEvidence
from app.models.investigation_note import InvestigationNote
from app.models.notification import Notification
from app.models.organization import Organization
from app.models.password_reset_token import PasswordResetToken
from app.models.permission import Permission, role_permissions
from app.models.playbook_execution import PlaybookExecution, PlaybookHistory
from app.models.playbook_step import PlaybookStep
from app.models.playbook_task import PlaybookTask
from app.models.refresh_token import RefreshToken
from app.models.remediation_approval import RemediationApproval
from app.models.remediation_evidence import RemediationEvidence
from app.models.remediation_history import RemediationHistory
from app.models.remediation_task import RemediationTask
from app.models.report_export import ReportExport
from app.models.response_playbook import ResponsePlaybook
from app.models.risk_acceptance import RiskAcceptance
from app.models.risk_assessment import RiskAssessment
from app.models.role import Role
from app.models.security_alert import SecurityAlert
from app.models.security_team import SecurityTeam
from app.models.sla_history import SLAHistory
from app.models.team_member import TeamMember
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.vulnerability_history import VulnerabilityHistory

__all__ = [name for name in dir() if not name.startswith("_")]
