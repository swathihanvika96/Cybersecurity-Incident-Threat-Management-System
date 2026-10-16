"""Aggregates every versioned router."""
from fastapi import APIRouter

from app.api.v1.alerts.router import router as alerts
from app.api.v1.assets.router import router as assets
from app.api.v1.audit_logs.router import router as audit_logs
from app.api.v1.auth.router import router as auth
from app.api.v1.correlations.router import router as correlations
from app.api.v1.dashboard.router import router as dashboard
from app.api.v1.departments.router import router as departments
from app.api.v1.incidents.router import router as incidents
from app.api.v1.investigations.router import router as investigations
from app.api.v1.notifications.router import router as notifications
from app.api.v1.organizations.router import router as organizations
from app.api.v1.playbooks.router import router as playbooks
from app.api.v1.remediation.router import router as remediation
from app.api.v1.reports.router import router as reports
from app.api.v1.risks.router import router as risks
from app.api.v1.roles.router import router as roles
from app.api.v1.search.router import router as search
from app.api.v1.slas.router import router as slas
from app.api.v1.teams.router import router as teams
from app.api.v1.users.router import router as users
from app.api.v1.vulnerabilities.router import router as vulnerabilities

api_router = APIRouter()
for _router in (auth, users, roles, organizations, departments, teams, assets, alerts, correlations, incidents,
                search, vulnerabilities, risks, remediation, investigations, playbooks, slas, audit_logs,
                notifications, dashboard, reports):
    api_router.include_router(_router)
