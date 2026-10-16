"""Runs the mandatory end-to-end demo against a RUNNING server and records the real responses.

    python scripts/demo_flow.py --base-url http://127.0.0.1:8000 --email admin@example.com --password 'Admin@12345' \
        --out docs/demo_run.json
"""
import argparse
import json
import sys
import time
from datetime import datetime, timedelta, timezone

import httpx

PASSWORD = "Demo!Passw0rd1"


class Demo:
    def __init__(self, base: str):
        self.http = httpx.Client(base_url=base.rstrip("/") + "/api/v1", timeout=30)
        self.log: list[dict] = []
        self.step_no = 0

    def call(self, method, path, token=None, expect=(200, 201), **kw):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = self.http.request(method, path, headers=headers, **kw)
        ok = r.status_code in (expect if isinstance(expect, tuple) else (expect,))
        try:
            body = r.json()
        except ValueError:
            body = r.text[:500]
        self.log.append({"step": self.step_no, "request": f"{method} {path}", "status": r.status_code, "ok": ok,
                         "response": body})
        if not ok:
            print(f"   FAILED {method} {path} -> {r.status_code}: {body}")
            raise SystemExit(1)
        return body

    def step(self, title):
        self.step_no += 1
        print(f"{self.step_no:>2}. {title}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--email", default="admin@example.com")
    ap.add_argument("--password", default="Admin@12345")
    ap.add_argument("--out", default="docs/demo_run.json")
    args = ap.parse_args()
    d = Demo(args.base_url)
    run = str(int(time.time()))[-6:]  # makes the script re-runnable against the same database

    d.step("Admin login")
    admin = d.call("POST", "/auth/login", json={"email": args.email, "password": args.password})["access_token"]
    roles = {r["name"]: r["id"] for r in d.call("GET", "/roles", admin)}

    def user(role, n):
        email = f"{role}.{run}.{n}@example.com"
        u = d.call("POST", "/users", admin, json={"email": email, "full_name": f"{role} {n}", "phone": "9876543210", "password": PASSWORD,
                                                  "role_id": roles[role]})
        tok = d.call("POST", "/auth/login", json={"email": email, "password": PASSWORD})["access_token"]
        return {"id": u["id"], "token": tok}

    it, mgr, mgr2, ana = user("it_administrator", 1), user("security_manager", 1), user("security_manager", 2), user("security_analyst", 1)

    d.step("Register assets")
    org = d.call("POST", "/organizations", it["token"], json={"name": f"Demo Corp {run}", "industry": "Finance", "contact_phone": "9876543210"})
    dep = d.call("POST", "/departments", it["token"], json={"organization_id": org["id"], "name": f"Platform {run}"})
    db_asset = d.call("POST", "/assets", it["token"], json={"name": f"db-{run}", "asset_type": "database", "criticality": "critical",
                                                          "organization_id": org["id"], "department_id": dep["id"], "ip_address": "10.1.0.10"})
    web_asset = d.call("POST", "/assets", it["token"], json={"name": f"web-{run}", "asset_type": "server", "criticality": "high",
                                                           "organization_id": org["id"], "department_id": dep["id"], "ip_address": "10.1.0.20"})

    d.step("Create security alerts (one duplicate on purpose)")
    base = datetime.now(timezone.utc) - timedelta(minutes=50)
    alert_ids = []
    for i, sev in enumerate(("high", "high", "critical")):
        a = d.call("POST", "/alerts", mgr["token"], json={
            "title": f"Brute force attempt #{i}", "source": "SIEM", "category": "unauthorized_access", "severity": sev,
            "asset_id": db_asset["id"], "detected_at": (base + timedelta(minutes=15 * i)).isoformat()})
        alert_ids.append(a["id"])
    dup = d.call("POST", "/alerts", mgr["token"], json={"title": "Brute force attempt #0", "source": "SIEM",
                                                        "category": "unauthorized_access", "severity": "high", "asset_id": db_asset["id"]})
    assert dup["is_duplicate"] and dup["duplicate_of_id"] == alert_ids[0]

    d.step("Correlate alerts")
    d.call("GET", "/correlations/repeated-alerts", mgr["token"])
    d.call("POST", "/correlations/auto", mgr["token"])
    corr = d.call("GET", "/correlations", mgr["token"], params={"asset_id": db_asset["id"]})["items"][0]

    d.step("Create incident from the correlation")
    inc = d.call("POST", "/incidents", mgr["token"], json={"title": f"Credential attack on db-{run}", "correlation_id": corr["id"]})

    d.step("Assign analyst")
    d.call("POST", f"/incidents/{inc['id']}/assign", mgr["token"], json={"assigned_to_id": ana["id"]})

    d.step("Identify vulnerabilities")
    vuln = d.call("POST", "/vulnerabilities", mgr["token"], json={
        "title": "OpenSSH regreSSHion", "cve_id": f"CVE-2024-{run[:4].rjust(4, '0')}", "cvss_score": 8.1,
        "asset_ids": [db_asset["id"], web_asset["id"]], "recommendation": "Upgrade OpenSSH"})

    d.step("Calculate risk")
    d.call("GET", "/risks/formula", mgr["token"])
    d.call("POST", "/risks/calculate", mgr["token"], json={"asset_id": db_asset["id"]})
    risk = d.call("GET", f"/risks/assets/{db_asset['id']}", mgr["token"])
    d.call("GET", "/risks/high-risk-assets", mgr["token"])

    d.step("Create remediation task, work it, approve it (four-eyes)")
    task = d.call("POST", "/remediation/tasks", mgr["token"], json={
        "vulnerability_id": vuln["id"], "asset_id": db_asset["id"], "title": "Patch OpenSSH", "assigned_to_id": ana["id"],
        "priority": "high", "due_date": (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()})
    d.call("POST", f"/remediation/tasks/{task['id']}/start", ana["token"])
    d.call("POST", f"/remediation/tasks/{task['id']}/evidence", ana["token"], json={"description": "Upgraded to 9.8p1", "reference_type": "patch"})
    d.call("POST", f"/remediation/tasks/{task['id']}/submit", ana["token"])
    d.call("POST", f"/remediation/tasks/{task['id']}/approve", mgr2["token"], json={"comments": "Verified"})

    d.step("Complete investigation")
    inv = d.call("POST", "/investigations", ana["token"], json={"title": "Credential attack investigation",
                                                                "incident_ids": [inc["id"]], "asset_ids": [db_asset["id"]]})
    d.call("POST", f"/investigations/{inv['id']}/notes", ana["token"], json={"content": "Source range blocked (simulated)"})
    d.call("POST", f"/investigations/{inv['id']}/evidence", ana["token"], json={"title": "Auth log extract", "evidence_type": "log",
                                                                               "reference": "s3://evidence/auth.log"})
    d.call("POST", f"/investigations/{inv['id']}/complete", ana["token"], json={"summary": "Credential stuffing from one botnet range; no compromise."})

    d.step("Track SLA")
    d.call("PATCH", f"/incidents/{inc['id']}/status", ana["token"], json={"status": "investigating"})
    sla = d.call("GET", f"/slas/incidents/{inc['id']}", mgr["token"])

    d.step("Resolve incident and close it with approval")
    d.call("POST", f"/incidents/{inc['id']}/resolve", ana["token"], json={"resolution_summary": "Attack blocked",
                                                                         "resolution_details": "Blocked range, enforced MFA, patched OpenSSH."})
    d.call("POST", f"/incidents/{inc['id']}/closure/request", mgr["token"])
    d.call("POST", f"/incidents/{inc['id']}/closure/approve", mgr["token"], expect=403)  # cannot approve own request
    closed = d.call("POST", f"/incidents/{inc['id']}/closure/approve", mgr2["token"])

    d.step("Generate notifications")
    d.call("POST", "/notifications/process", mgr["token"])
    notes = d.call("GET", "/notifications", ana["token"])

    d.step("View dashboard")
    dash = d.call("GET", "/dashboard", mgr["token"])

    d.step("Export reports")
    d.call("GET", "/reports/vulnerability-analysis", mgr["token"])
    csv_resp = d.http.get("/reports/sla-compliance/export", headers={"Authorization": f"Bearer {mgr['token']}"})
    assert csv_resp.status_code == 200 and csv_resp.headers["content-type"].startswith("text/csv")
    d.log.append({"step": d.step_no, "request": "GET /reports/sla-compliance/export", "status": 200, "ok": True,
                  "response": csv_resp.text[:600]})

    d.step("Verify audit logs")
    audit = d.call("GET", "/audit-logs", admin, params={"size": 100})
    actions = {e["action"] for e in audit["items"]}
    for needed in ("auth.login", "incident.create", "vulnerability.create", "remediation.approve", "report.export"):
        assert needed in actions, f"missing audit action {needed}"
    d.call("DELETE", f"/audit-logs/{audit['items'][0]['id']}", admin, expect=405)  # protected from modification

    summary = {"closed_status": closed["status"], "db_asset_risk_score_before_remediation": risk["risk_score"],
               "sla_status": sla["sla_status"], "notifications_for_analyst": notes["total"],
               "dashboard_incidents": dash["incidents"], "audit_entries_seen": audit["total"]}
    print("\nDEMO COMPLETED:", json.dumps(summary, indent=2, default=str))
    with open(args.out, "w") as fh:
        json.dump({"summary": summary, "calls": d.log}, fh, indent=2, default=str)
    print(f"{len(d.log)} calls recorded in {args.out}")


if __name__ == "__main__":
    sys.exit(main())
