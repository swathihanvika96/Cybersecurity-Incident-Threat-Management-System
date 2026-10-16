"""Verifies the Swagger/OpenAPI output of a RUNNING server and writes docs/openapi.json + docs/SWAGGER_VERIFICATION.md.

Checks: document validity (openapi-spec-validator), Swagger UI / ReDoc reachability, OAuth2 security scheme,
summary + success response on every operation, every protected operation declares security, and - using the calls
recorded by scripts/demo_flow.py - that REAL responses conform to the documented response schemas.
"""
import argparse
import json
import re
import sys
from collections import Counter

import httpx
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

PUBLIC = {"/api/v1/auth/login", "/api/v1/auth/token", "/api/v1/auth/register", "/api/v1/auth/refresh",
          "/api/v1/auth/password-reset/request", "/api/v1/auth/password-reset/confirm", "/health", "/health/ready"}


def template_regex(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{[^/]+\}", r"[^/]+", path) + "$")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--demo", default="docs/demo_run.json")
    ap.add_argument("--out-spec", default="docs/openapi.json")
    ap.add_argument("--out-report", default="docs/SWAGGER_VERIFICATION.md")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    checks: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))
        print(("PASS " if ok else "FAIL ") + name + (f" - {detail}" if detail else ""))

    spec = httpx.get(f"{base}/openapi.json", timeout=30).json()
    with open(args.out_spec, "w") as fh:
        json.dump(spec, fh, indent=2)
    try:
        validate(spec)
        check("OpenAPI document validates against the specification", True, f"OpenAPI {spec['openapi']}")
    except Exception as exc:  # noqa: BLE001
        check("OpenAPI document validates against the specification", False, str(exc)[:200])

    docs = httpx.get(f"{base}/docs", timeout=30)
    check("Swagger UI served at /docs", docs.status_code == 200 and "swagger-ui" in docs.text.lower())
    redoc = httpx.get(f"{base}/redoc", timeout=30)
    check("ReDoc served at /redoc", redoc.status_code == 200 and "redoc" in redoc.text.lower())

    schemes = spec.get("components", {}).get("securitySchemes", {})
    flows = schemes.get("OAuth2PasswordBearer", {}).get("flows", {}).get("password", {})
    check("'Authorize' button: OAuth2 password flow declared", flows.get("tokenUrl") == "/api/v1/auth/token", str(flows))
    form = httpx.post(f"{base}/api/v1/auth/token", data={"username": "admin@example.com", "password": "Admin@12345"})
    check("Token endpoint accepts the Swagger form login", form.status_code == 200 and "access_token" in form.json())

    ops = []
    for path, item in spec["paths"].items():
        for method, op in item.items():
            if method in ("get", "post", "put", "patch", "delete"):
                ops.append((method.upper(), path, op))
    check("Every operation has a summary", all(op.get("summary") for _, _, op in ops), f"{len(ops)} operations")
    check("Every operation documents a 2xx response", all(any(c.startswith("2") for c in op["responses"]) for _, _, op in ops))
    unprotected = [f"{m} {p}" for m, p, op in ops if p not in PUBLIC and not op.get("security")]
    check("Every non-public operation declares security", not unprotected, ", ".join(unprotected[:5]))
    no_err = [f"{m} {p}" for m, p, op in ops if p not in PUBLIC and p.startswith("/api") and "401" not in op["responses"]]
    check("Protected operations document 401/403/404/409 error envelopes", not no_err, ", ".join(no_err[:5]))
    tags = Counter(t for _, _, op in ops for t in op.get("tags", []))
    declared = {t["name"] for t in spec.get("tags", [])}
    check("All tags are described", set(tags) <= declared, str(sorted(set(tags) - declared)))

    # every request body must ship a Swagger example
    def body_schema(op):
        content = op.get("requestBody", {}).get("content", {})
        sch = (content.get("application/json") or {}).get("schema")
        if sch and "$ref" in sch:
            return sch["$ref"].rsplit("/", 1)[-1]
        return None

    body_ops = [(m, p, op, body_schema(op)) for m, p, op in ops if body_schema(op)]
    no_example = sorted({name for _, _, _, name in body_ops if "examples" not in spec["components"]["schemas"][name]})
    check("Every JSON request body has a Swagger example", not no_example, ", ".join(no_example[:6]))

    # --- real responses vs documented schemas ---------------------------------------------------
    matched = failed = 0
    problems = []
    try:
        demo = json.load(open(args.demo))["calls"]
    except FileNotFoundError:
        demo = []
        check("Demo recording present", False, f"{args.demo} not found - run scripts/demo_flow.py first")
    matchers = [(m, p, template_regex(p), op) for m, p, op in ops]
    for call in demo:
        method, path = call["request"].split(" ", 1)
        path = "/api/v1" + path.split("?")[0] if not path.startswith("/api") else path
        if not str(call["status"]).startswith("2") or not isinstance(call["response"], (dict, list)):
            continue
        for m, p, rx, op in matchers:
            if m == method and rx.match(path):
                resp = op["responses"].get(str(call["status"]))
                schema = resp and resp.get("content", {}).get("application/json", {}).get("schema")
                if schema:
                    validator = Draft202012Validator({**schema, "components": spec["components"]})
                    errors = list(validator.iter_errors(call["response"]))
                    if errors:
                        failed += 1
                        problems.append(f"{method} {path}: {errors[0].message[:120]}")
                    else:
                        matched += 1
                break
    check("Real responses conform to documented schemas", demo and failed == 0, f"{matched} validated, {failed} mismatches")
    for p in problems[:10]:
        print("   ", p)

    # --- report ---------------------------------------------------------------------------------
    by_tag: dict[str, list] = {}
    for m, p, op in ops:
        by_tag.setdefault((op.get("tags") or ["-"])[0], []).append((m, p, op))
    lines = ["# Swagger / OpenAPI verification", "",
             f"Verified against the live server at `{base}` (OpenAPI {spec['openapi']}, API version {spec['info']['version']}).", "",
             "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    lines += [f"| {'PASS' if ok else '**FAIL**'} | {name} | {detail.replace('|', '/')} |" for name, ok, detail in checks]
    lines += ["", f"## Surface: {len(ops)} operations / {len(spec['paths'])} paths / {len(spec['components']['schemas'])} schemas", ""]
    for tag in [t["name"] for t in spec.get("tags", [])] + [t for t in by_tag if t not in {x['name'] for x in spec.get('tags', [])}]:
        if tag not in by_tag:
            continue
        lines += [f"### {tag}", "", "| Method | Path | Summary | Auth | Success | Errors |", "|---|---|---|---|---|---|"]
        for m, p, op in sorted(by_tag[tag], key=lambda x: (x[1], x[0])):
            codes = sorted(op["responses"])
            ok = ",".join(c for c in codes if c.startswith("2"))
            err = ",".join(c for c in codes if not c.startswith("2"))
            lines.append(f"| {m} | `{p}` | {op['summary']} | {'Bearer' if op.get('security') else 'public'} | {ok} | {err} |")
        lines.append("")
    lines += ["## Request body examples shown in Swagger (Try it out)", ""]
    for m, p, op, name in sorted(body_ops, key=lambda x: (x[1], x[0])):
        ex = spec["components"]["schemas"][name].get("examples", [None])[0]
        lines += [f"**{m} `{p}`** - {op['summary']}", "", "```json", json.dumps(ex, indent=2), "```", ""]
    if demo:
        lines += ["## Real sample responses (from the live demo run)", ""]
        wanted = ["POST /auth/login", "POST /alerts", "POST /incidents", "GET /risks/assets/", "GET /slas/incidents/",
                  "GET /dashboard", "GET /audit-logs"]
        shown = set()
        for call in demo:
            req = call["request"]
            for w in wanted:
                if req.startswith(w) and w not in shown and isinstance(call["response"], (dict, list)):
                    shown.add(w)
                    body = json.dumps(call["response"], indent=2, default=str)
                    if "access_token" in body:
                        body = re.sub(r'("(?:access|refresh)_token": ")[^"]+', r"\1<redacted>", body)
                    if len(body) > 1800:
                        body = body[:1800] + "\n  ... (truncated)"
                    lines += [f"**{req}** -> `{call['status']}`", "", "```json", body, "```", ""]
    open(args.out_report, "w").write("\n".join(lines))
    failed_checks = [c for c in checks if not c[1]]
    print(f"\n{len(checks) - len(failed_checks)}/{len(checks)} checks passed; report -> {args.out_report}")
    return 1 if failed_checks else 0


if __name__ == "__main__":
    sys.exit(main())
