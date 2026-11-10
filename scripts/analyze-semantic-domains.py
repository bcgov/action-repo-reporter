#!/usr/bin/env python3
"""Deep semantic domain analyzers for authorization, logging, and token hygiene.

Performs static AST/pattern analysis on controllers, routes, views, loggers,
and authentication modules to detect:
1. Unprotected mutating routes in NestJS, Express, and Django (AUTHZ)
2. Sensitive credential and client error logging leaks (DATA)
3. Non-constant-time token comparisons and hardcoded fallback secrets (AUTH / CRYPTO)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any


def _is_ignored(path: pathlib.Path) -> bool:
    ignored_parts = {
        "node_modules", "dist", "build", ".git", ".next", ".nuxt",
        "coverage", "__pycache__", "venv", ".venv", "tests", "test",
        "spec", "e2e", "migrations", ".pytest_cache",
    }
    return any(p in ignored_parts or p.startswith(".") for p in path.parts)


def _safe_read_lines(file_path: pathlib.Path) -> list[str]:
    try:
        return file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def analyze_authz_nestjs(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect unprotected mutating endpoints in NestJS controllers."""
    findings = []
    ts_files = [p for p in repo_dir.rglob("*.controller.ts") if not _is_ignored(p)]
    # Also check generic .ts files containing @Controller
    all_ts = [p for p in repo_dir.rglob("*.ts") if not _is_ignored(p) and p not in ts_files]
    for p in all_ts:
        lines = _safe_read_lines(p)
        if any("@Controller" in ln for ln in lines):
            ts_files.append(p)

    for path in sorted(ts_files):
        lines = _safe_read_lines(path)
        rel_path = str(path.relative_to(repo_dir))
        
        has_class_controller = False
        class_has_guard = False
        class_line = 0

        # Scan class-level decorators
        for idx, line in enumerate(lines, 1):
            if "@Controller" in line:
                has_class_controller = True
                # Check preceding lines for @UseGuards or @Roles
                start = max(0, idx - 10)
                for prev in lines[start:idx]:
                    if "@UseGuards" in prev or "@Roles" in prev:
                        class_has_guard = True
            if has_class_controller and re.search(r"\bclass\s+\w+", line):
                class_line = idx
                break

        if not has_class_controller:
            continue

        # If class has guard, endpoints inherit protection unless explicitly overridden
        if class_has_guard:
            continue

        # Look for mutating methods without route-level guard
        mutating_verbs = ("@Post", "@Put", "@Delete", "@Patch")
        for idx, line in enumerate(lines, 1):
            matched_verb = next((v for v in mutating_verbs if v in line), None)
            if not matched_verb:
                continue

            # Check if public auth endpoint (e.g. login, token, callback, refresh, webhook)
            lower_line = line.lower()
            if any(term in lower_line for term in ("login", "token", "callback", "refresh", "webhook", "public", "auth/")):
                continue

            # Check preceding 8 lines for method-level @UseGuards, @Roles, or @Public
            method_guarded = False
            start = max(0, idx - 8)
            for prev in lines[start:idx]:
                if any(k in prev for k in ("@UseGuards", "@Roles", "@Public", "@Auth")):
                    method_guarded = True
                    break

            if not method_guarded:
                snippet = line.strip()
                if idx < len(lines):
                    snippet += f"\n{lines[idx].strip()}"
                findings.append({
                    "severity": "High",
                    "title": f"Unprotected mutating endpoint in NestJS controller ({matched_verb.lstrip('@')})",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": snippet[:200],
                    }],
                    "impact": "Unauthenticated or unprivileged callers can execute state-changing actions without token verification or role checks, resulting in broken access control.",
                    "recommendation": "Decorate the controller or method with `@UseGuards(JwtAuthGuard)` and appropriate role authorization decorators.",
                    "domain": "AUTHZ",
                    "source": "semantic-analyzer",
                    "cwes": [284, 862],
                    "owasp": "A01 Broken Access Control",
                })
    return findings


def analyze_authz_express(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect unprotected mutating routes in Express route handlers."""
    findings = []
    route_files = [
        p for p in repo_dir.rglob("*")
        if p.suffix in (".js", ".ts")
        and not _is_ignored(p)
        and (
            "route" in p.name.lower()
            or "router" in p.name.lower()
            or "server" in p.name.lower()
            or "app" in p.name.lower()
        )
    ]

    mutating_re = re.compile(
        r"\b(?:router|app)\.(post|put|delete|patch)\s*\(\s*(['\"][^'\"]+['\"])\s*,",
        re.I,
    )

    auth_terms = (
        "auth", "authenticate", "jwt", "verify", "guard", "protect",
        "isloggedin", "session", "requireauth", "checkrole", "passport",
    )

    public_terms = ("login", "token", "auth", "callback", "public", "health", "webhook", "register")

    for path in sorted(route_files):
        lines = _safe_read_lines(path)
        rel_path = str(path.relative_to(repo_dir))
        for idx, line in enumerate(lines, 1):
            m = mutating_re.search(line)
            if not m:
                continue
            verb = m.group(1).upper()
            route_str = m.group(2).strip("'\"")

            # Skip public auth routes
            if any(term in route_str.lower() for term in public_terms):
                continue

            # Check full statement across lines if needed
            statement = line
            cur = idx
            while cur < len(lines) and ")" not in statement and cur < idx + 5:
                statement += " " + lines[cur].strip()
                cur += 1

            # Check if any middleware matching auth patterns is included
            has_auth_middleware = any(term in statement.lower() for term in auth_terms)
            if not has_auth_middleware:
                findings.append({
                    "severity": "High",
                    "title": f"Unauthenticated mutating route in Express ({verb} {route_str})",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                    }],
                    "impact": "Route handler processes mutating requests without prior authentication middleware, permitting unauthorized data modification.",
                    "recommendation": "Insert authentication and authorization middleware (e.g. `passport.authenticate` or `verifyToken`) before the route handler.",
                    "domain": "AUTHZ",
                    "source": "semantic-analyzer",
                    "cwes": [284, 862],
                    "owasp": "A01 Broken Access Control",
                })
    return findings


def analyze_authz_django(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect unprotected mutating views in Django applications."""
    findings = []
    py_files = [
        p for p in repo_dir.rglob("*.py")
        if not _is_ignored(p)
        and ("views" in p.name.lower() or "viewsets" in p.name.lower() or "api" in p.name.lower())
    ]

    login_decorators = ("@login_required", "@permission_required", "@user_passes_test", "@staff_member_required")
    drf_auth = ("IsAuthenticated", "IsAdminUser", "permission_classes")

    for path in sorted(py_files):
        lines = _safe_read_lines(path)
        rel_path = str(path.relative_to(repo_dir))

        # 1. Check Function-Based Views with mutating verbs
        for idx, line in enumerate(lines, 1):
            if re.match(r"^\s*def\s+([a-zA-Z0-9_]+)\s*\(\s*request\b", line):
                fn_name = re.match(r"^\s*def\s+([a-zA-Z0-9_]+)", line).group(1)
                if any(term in fn_name.lower() for term in ("login", "logout", "token", "auth", "health", "public")):
                    continue

                # Check preceding 6 lines for auth decorator
                start = max(0, idx - 7)
                preceding = " ".join(lines[start:idx - 1])
                has_dec = any(dec in preceding for dec in login_decorators) or any(a in preceding for a in drf_auth)

                # Check if body handles POST/PUT/DELETE
                body = " ".join(lines[idx:min(len(lines), idx + 20)])
                mutating = bool(re.search(r"request\.method\s*in\s*\[?['\"](?:POST|PUT|DELETE|PATCH)", body, re.I))

                if mutating and not has_dec:
                    findings.append({
                        "severity": "High",
                        "title": f"Unprotected mutating Django view function: {fn_name}",
                        "evidence": [{
                            "file": rel_path,
                            "line": idx,
                            "snippet": line.strip()[:200],
                        }],
                        "impact": "View executes database mutations without enforcing user authentication or permission checks, exposing endpoints to unauthenticated callers.",
                        "recommendation": "Decorate the view with `@login_required` or apply DRF permission classes requiring authentication.",
                        "domain": "AUTHZ",
                        "source": "semantic-analyzer",
                        "cwes": [284, 862],
                        "owasp": "A01 Broken Access Control",
                    })

        # 2. Check Class-Based Views / DRF ViewSets
        for idx, line in enumerate(lines, 1):
            m = re.match(r"^\s*class\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\):", line)
            if not m:
                continue
            cls_name = m.group(1)
            bases = m.group(2)
            if not any(b in bases for b in ("View", "APIView", "ViewSet", "ModelViewSet")):
                continue

            # Check if class has mutating methods
            class_body = " ".join(lines[idx:min(len(lines), idx + 40)])
            has_mutating_method = bool(re.search(r"\bdef\s+(?:post|put|delete|patch|create|update|destroy)\s*\(", class_body))
            if not has_mutating_method:
                continue

            has_auth_mixin = any(m in bases for m in ("LoginRequiredMixin", "PermissionRequiredMixin"))
            has_permission_classes = "permission_classes" in class_body and not "AllowAny" in class_body

            if not has_auth_mixin and not has_permission_classes:
                findings.append({
                    "severity": "High",
                    "title": f"Django class-based view lacking authentication or permission classes: {cls_name}",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                    }],
                    "impact": "State-changing class-based view does not enforce authentication mixins or permission classes, allowing unauthenticated API invocation.",
                    "recommendation": "Add `LoginRequiredMixin` or declare `permission_classes = [IsAuthenticated]` on the view.",
                    "domain": "AUTHZ",
                    "source": "semantic-analyzer",
                    "cwes": [284, 862],
                    "owasp": "A01 Broken Access Control",
                })

    return findings


def analyze_sensitive_logging(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect raw HTTP client error object logging and direct token logging."""
    findings = []
    code_files = [
        p for p in repo_dir.rglob("*")
        if p.suffix in (".ts", ".js", ".py") and not _is_ignored(p)
    ]

    raw_err_re = re.compile(
        r"\b(?:logger|console)\.(?:error|warn|debug|info)\s*\(\s*(?:err|error|axiosError|e)\s*[,)]"
    )

    token_log_re = re.compile(
        r"\b(?:logger|console)\.(?:log|info|debug|warn|error)\s*\([^)]*\b(token|jwt|accessToken|refreshToken|bearer|req\.headers(?:\.authorization)?|client_secret)\b",
        re.I,
    )

    for path in sorted(code_files):
        lines = _safe_read_lines(path)
        rel_path = str(path.relative_to(repo_dir))
        content = "\n".join(lines)

        # 1. Raw error object logging in files using HTTP clients (axios/fetch/requests)
        has_http_client = bool(re.search(r"\b(?:axios|fetch|request|urllib|httpx)\b", content, re.I))
        if has_http_client:
            for idx, line in enumerate(lines, 1):
                if raw_err_re.search(line):
                    # Check if error message is extracted or whole object passed
                    if not any(prop in line for prop in (".message", ".code", ".status", ".stack")):
                        findings.append({
                            "severity": "Medium",
                            "title": "Raw HTTP client error object passed directly to logger",
                            "evidence": [{
                                "file": rel_path,
                                "line": idx,
                                "snippet": line.strip()[:200],
                            }],
                            "impact": "Serializing raw HTTP client error objects directly to logs exposes full request configurations, which frequently contain Authorization headers and Bearer tokens.",
                            "recommendation": "Log only `error.message` or `error.code` rather than serializing the entire HTTP error object.",
                            "domain": "DATA",
                            "source": "semantic-analyzer",
                            "cwes": [532],
                            "owasp": "A09 Security Logging and Monitoring Failures",
                        })

        # 2. Direct token / authorization header logging
        for idx, line in enumerate(lines, 1):
            m = token_log_re.search(line)
            if m:
                # Filter out obvious false positives like token.id or token.length or test tokens
                matched_kw = m.group(1)
                if any(fp in line.lower() for fp in ("token.length", "token.id", "token.type", "totallength", "token count")):
                    continue
                findings.append({
                    "severity": "High",
                    "title": f"Potential credential or authorization token disclosure in logger call ({matched_kw})",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                    }],
                    "impact": "Writing tokens, credentials, or raw authorization headers to logs leaks sensitive authentication secrets to log storage and monitoring pipelines.",
                    "recommendation": "Redact authorization tokens and sensitive credential headers prior to emitting log records.",
                    "domain": "DATA",
                    "source": "semantic-analyzer",
                    "cwes": [532],
                    "owasp": "A09 Security Logging and Monitoring Failures",
                })

    return findings


def analyze_token_crypto_hygiene(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect non-constant-time token comparisons and hardcoded fallback secrets."""
    findings = []
    code_files = [
        p for p in repo_dir.rglob("*")
        if p.suffix in (".ts", ".js", ".py") and not _is_ignored(p)
    ]

    timing_re = re.compile(
        r"\b(token|signature|hmac|expectedHash|calculatedHash)\s*===?\s*(?!\s*(?:null|undefined|''|\"\"|None|\d+))\b([a-zA-Z0-9_.]+)",
        re.I,
    )

    fallback_secret_re = re.compile(
        r"\b(?:process\.env\.(?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)|os\.environ\.get\(['\"](?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)['\"]\))\s*(?:\|\||\?\?|,)\s*(['\"][^'\"]{3,}['\"])",
        re.I,
    )

    for path in sorted(code_files):
        lines = _safe_read_lines(path)
        rel_path = str(path.relative_to(repo_dir))

        for idx, line in enumerate(lines, 1):
            # Timing attack check
            m_time = timing_re.search(line)
            if m_time and not any(safe in line for safe in ("timingSafeEqual", "compare_digest", "typeof")):
                findings.append({
                    "severity": "Medium",
                    "title": "Non-constant-time comparison for authentication token or cryptographic hash",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                    }],
                    "impact": "Standard equality comparison terminates early on first byte mismatch, leaking secret timing differences to attackers via side-channel analysis.",
                    "recommendation": "Use `crypto.timingSafeEqual()` in Node.js or `hmac.compare_digest()` in Python for constant-time comparison.",
                    "domain": "CRYPTO",
                    "source": "semantic-analyzer",
                    "cwes": [208, 327],
                    "owasp": "A02 Cryptographic Failures",
                })

            # Hardcoded fallback secret check
            m_sec = fallback_secret_re.search(line)
            if m_sec:
                secret_val = m_sec.group(1)
                findings.append({
                    "severity": "High",
                    "title": "Hardcoded fallback secret for cryptographic token signing",
                    "evidence": [{
                        "file": rel_path,
                        "line": idx,
                        "snippet": line.strip()[:200],
                    }],
                    "impact": "If the environment secret is missing or unset, the application silently signs or validates tokens using an insecure default key.",
                    "recommendation": "Fail closed at application startup if required authentication secrets are omitted from the environment.",
                    "domain": "AUTH",
                    "source": "semantic-analyzer",
                    "cwes": [798, 321],
                    "owasp": "A07 Identification and Authentication Failures",
                })

    return findings


def analyze_semantic_domains(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Run all semantic analyzers across repo tree and return findings list."""
    findings: list[dict[str, Any]] = []
    findings.extend(analyze_authz_nestjs(repo_dir))
    findings.extend(analyze_authz_express(repo_dir))
    findings.extend(analyze_authz_django(repo_dir))
    findings.extend(analyze_sensitive_logging(repo_dir))
    findings.extend(analyze_token_crypto_hygiene(repo_dir))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_dir", nargs="?", default="target", help="Path to repository root (default: target)")
    args = parser.parse_args()
    results = analyze_semantic_domains(pathlib.Path(args.repo_dir))
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
