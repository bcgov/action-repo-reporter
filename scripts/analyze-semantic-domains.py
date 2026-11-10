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
import ast
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


def _safe_read_lines(file_path: pathlib.Path, repo_root: pathlib.Path | None = None) -> list[str]:
    try:
        if file_path.is_symlink() or not file_path.is_file():
            return []
        if repo_root is not None:
            resolved = file_path.resolve()
            root_resolved = repo_root.resolve()
            if not resolved.is_relative_to(root_resolved):
                return []
        if file_path.stat().st_size > 2 * 1024 * 1024:
            return []
        return file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _is_route_public(route_str: str) -> bool:
    """Check if route path contains dedicated public/auth segments rather than resource substrings."""
    segments = {s.lower() for s in re.split(r"[/._-]", route_str.strip("/")) if s}
    public_segments = {
        "login", "logout", "token", "auth", "callback", "public",
        "health", "healthz", "webhook", "register", "signup",
    }
    return bool(segments & public_segments)


def analyze_authz_nestjs(repo_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Detect unprotected mutating endpoints in NestJS controllers."""
    findings = []
    ts_files = [p for p in repo_dir.rglob("*.controller.ts") if not _is_ignored(p)]
    all_ts = [p for p in repo_dir.rglob("*.ts") if not _is_ignored(p) and p not in ts_files]
    for p in all_ts:
        lines = _safe_read_lines(p, repo_dir)
        if any("@Controller" in ln for ln in lines):
            ts_files.append(p)

    mutating_verbs = ("@Post", "@Put", "@Delete", "@Patch")
    guard_terms = ("@UseGuards", "@Roles", "@Public", "@Auth")

    for path in sorted(ts_files):
        lines = _safe_read_lines(path, repo_dir)
        rel_path = str(path.relative_to(repo_dir))

        in_class = False
        class_has_guard = False
        class_dec_block: list[str] = []
        method_dec_block: list[str] = []

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()

            # Collect decorator lines
            if stripped.startswith("@"):
                if not in_class:
                    class_dec_block.append(stripped)
                else:
                    method_dec_block.append(stripped)
                continue

            # Class declaration
            m_cls = re.search(r"\bclass\s+(\w+)", line)
            if m_cls and not in_class:
                has_ctrl = any("@Controller" in d for d in class_dec_block)
                if has_ctrl:
                    in_class = True
                    class_has_guard = any(
                        any(term in d for term in ("@UseGuards", "@Roles", "@Auth"))
                        for d in class_dec_block
                    )
                class_dec_block.clear()
                continue

            if not in_class:
                if not stripped.startswith("//") and not stripped.startswith("/*"):
                    class_dec_block.clear()
                continue

            # Method signature: matches `async? methodName(...)`
            m_method = re.search(
                r"(?:public\s+|private\s+|protected\s+)?(?:async\s+)?([a-zA-Z0-9_]+)\s*\([^)]*\)",
                line,
            )
            if m_method and method_dec_block:
                verb = next(
                    (v for v in mutating_verbs if any(v in d for d in method_dec_block)),
                    None,
                )
                if verb and not class_has_guard:
                    # Check if method decorators include guard
                    method_guarded = any(
                        any(term in d for term in guard_terms)
                        for d in method_dec_block
                    )
                    # Check if any route decorator argument is public
                    verb_line = next(d for d in method_dec_block if verb in d)
                    m_route = re.search(r"['\"]([^'\"]+)['\"]", verb_line)
                    route_path = m_route.group(1) if m_route else ""

                    if not method_guarded and not _is_route_public(route_path):
                        snippet = f"{verb_line}\n{line.strip()}"
                        findings.append({
                            "severity": "High",
                            "title": f"Unprotected mutating endpoint in NestJS controller ({verb.lstrip('@')})",
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
                method_dec_block.clear()
                continue

            # Statement boundary: clear method decorator block if non-decorator code intervenes
            if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
                if not any(stripped.startswith(k) for k in ("public", "private", "protected", "async")):
                    method_dec_block.clear()

            # Class closed
            if in_class and stripped == "}":
                in_class = False
                class_has_guard = False
                method_dec_block.clear()

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
        r"\b(router|app)\.(post|put|delete|patch)\s*\(\s*(['\"][^'\"]+['\"])\s*,(.*)",
        re.I,
    )
    middleware_auth_re = re.compile(
        r"\b(?:auth|authenticate|jwt|verify(?:Token)?|guard|requireAuth|checkRole|isLoggedIn|passport\.authenticate)\b",
        re.I,
    )
    router_use_re = re.compile(
        r"\b(router|app)\.use\s*\((.*)\)",
        re.I,
    )

    for path in sorted(route_files):
        lines = _safe_read_lines(path, repo_dir)
        rel_path = str(path.relative_to(repo_dir))

        router_guarded: set[str] = set()

        for idx, line in enumerate(lines, 1):
            # Check for router-level middleware registrations: router.use(requireAuth)
            m_use = router_use_re.search(line)
            if m_use:
                obj_name = m_use.group(1).lower()
                use_args = m_use.group(2)
                if middleware_auth_re.search(use_args):
                    router_guarded.add(obj_name)

            m = mutating_re.search(line)
            if not m:
                continue

            obj = m.group(1).lower()
            verb = m.group(2).upper()
            route_str = m.group(3).strip("'\"")
            rest_of_line = m.group(4)

            # If the router or app has file-level auth middleware preceding this route, route is protected
            if obj in router_guarded:
                continue

            # Skip public auth routes by segment match
            if _is_route_public(route_str):
                continue

            # Accumulate multi-line route definition if closing paren is on later line
            statement = rest_of_line
            cur = idx
            while cur < len(lines) and ")" not in statement and cur < idx + 5:
                statement += " " + lines[cur].strip()
                cur += 1

            # Extract arguments between the path and the terminal handler
            # Split statement up to closing paren
            call_body = statement.split(")", 1)[0]
            args = [a.strip() for a in call_body.split(",") if a.strip()]

            # If args has <= 1 entry, only the terminal handler was passed (no middleware)
            # If args has > 1 entries, middlewares are args[:-1]
            has_auth_middleware = False
            if len(args) > 1:
                middleware_args = args[:-1]
                has_auth_middleware = any(middleware_auth_re.search(arg) for arg in middleware_args)

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
    """Detect unprotected mutating views in Django applications using AST parsing."""
    findings = []
    py_files = [
        p for p in repo_dir.rglob("*.py")
        if not _is_ignored(p)
        and ("views" in p.name.lower() or "viewsets" in p.name.lower() or "api" in p.name.lower())
    ]

    for path in sorted(py_files):
        lines = _safe_read_lines(path, repo_dir)
        rel_path = str(path.relative_to(repo_dir))
        content = "\n".join(lines)
        if not content.strip():
            continue

        try:
            tree = ast.parse(content, filename=str(path))
        except SyntaxError:
            continue

        for node in tree.body:
            # 1. Function-Based Views
            if isinstance(node, ast.FunctionDef):
                has_request_arg = any(arg.arg == "request" for arg in node.args.args)
                if not has_request_arg:
                    continue

                if _is_route_public(node.name):
                    continue

                is_protected = False
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Name) and dec.id in (
                        "login_required", "permission_required", "staff_member_required",
                    ):
                        is_protected = True
                    elif isinstance(dec, ast.Call):
                        fn_name = ""
                        if isinstance(dec.func, ast.Name):
                            fn_name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            fn_name = dec.func.attr
                        if fn_name in ("login_required", "permission_required", "staff_member_required"):
                            is_protected = True
                        elif fn_name == "permission_classes" and dec.args:
                            if isinstance(dec.args[0], (ast.List, ast.Tuple)):
                                classes = [
                                    elt.id for elt in dec.args[0].elts
                                    if isinstance(elt, ast.Name)
                                ]
                                if (
                                    any(c in ("IsAuthenticated", "IsAdminUser") for c in classes)
                                    and "AllowAny" not in classes
                                ):
                                    is_protected = True

                # Check if function body contains mutation checks or mutations
                mutating = False
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Compare):
                        src = ast.unparse(sub)
                        if "request.method" in src and any(v in src for v in ("POST", "PUT", "DELETE", "PATCH")):
                            mutating = True
                            break

                if mutating and not is_protected:
                    line_no = node.lineno
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else f"def {node.name}(request):"
                    findings.append({
                        "severity": "High",
                        "title": f"Unprotected mutating Django view function: {node.name}",
                        "evidence": [{
                            "file": rel_path,
                            "line": line_no,
                            "snippet": snippet[:200],
                        }],
                        "impact": "View executes database mutations without enforcing user authentication or permission checks, exposing endpoints to unauthenticated callers.",
                        "recommendation": "Decorate the view with `@login_required` or apply DRF permission classes requiring authentication.",
                        "domain": "AUTHZ",
                        "source": "semantic-analyzer",
                        "cwes": [284, 862],
                        "owasp": "A01 Broken Access Control",
                    })

            # 2. Class-Based Views / DRF ViewSets
            elif isinstance(node, ast.ClassDef):
                base_names = []
                for b in node.bases:
                    if isinstance(b, ast.Name):
                        base_names.append(b.id)
                    elif isinstance(b, ast.Attribute):
                        base_names.append(b.attr)

                if not any(b in ("View", "APIView", "ViewSet", "ModelViewSet") for b in base_names):
                    continue

                has_auth_mixin = any(
                    m in ("LoginRequiredMixin", "PermissionRequiredMixin") for m in base_names
                )

                # Inspect class body exclusively for mutating methods and permission_classes
                has_mutating_method = any(
                    isinstance(sub, ast.FunctionDef)
                    and sub.name in ("post", "put", "delete", "patch", "create", "update", "destroy")
                    for sub in node.body
                )
                if not has_mutating_method:
                    continue

                perm_classes: list[str] = []
                has_perm_attr = False
                for sub in node.body:
                    if isinstance(sub, ast.Assign):
                        for tgt in sub.targets:
                            if isinstance(tgt, ast.Name) and tgt.id == "permission_classes":
                                has_perm_attr = True
                                if isinstance(sub.value, (ast.List, ast.Tuple)):
                                    perm_classes = [
                                        elt.id for elt in sub.value.elts
                                        if isinstance(elt, ast.Name)
                                    ]

                is_protected = has_auth_mixin or (
                    has_perm_attr
                    and len(perm_classes) > 0
                    and "AllowAny" not in perm_classes
                    and any(c in ("IsAuthenticated", "IsAdminUser") for c in perm_classes)
                )

                if not is_protected:
                    line_no = node.lineno
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else f"class {node.name}:"
                    findings.append({
                        "severity": "High",
                        "title": f"Django class-based view lacking authentication or permission classes: {node.name}",
                        "evidence": [{
                            "file": rel_path,
                            "line": line_no,
                            "snippet": snippet[:200],
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

    # Matches bare error object arguments passed to logger (e.g. logger.error(err) or logger.error(err, context))
    raw_err_re = re.compile(
        r"\b(?:logger|console)\.(?:error|warn|debug|info)\s*\((?:[^)]*,\s*)?\b(err|error|axiosError|e)\b(?!\s*[:.\[])(?:\s*[,)])",
        re.I,
    )
    raw_axios_err_re = re.compile(
        r"\b(?:logger|console)\.(?:error|warn|debug|info)\s*\((?:[^)]*,\s*)?\b(?:axiosError|httpError|(?:err|error|e)\.(?:config|request|response|headers))\b",
        re.I,
    )

    logger_call_re = re.compile(
        r"\b(?:logger|console)\.(?:log|info|debug|warn|error)\s*\((.*)\)",
        re.I,
    )

    for path in sorted(code_files):
        lines = _safe_read_lines(path, repo_dir)
        rel_path = str(path.relative_to(repo_dir))
        content = "\n".join(lines)

        # 1. Raw HTTP client error object logging
        # Only flag if the error explicitly accesses HTTP client properties or appears in an immediate HTTP catch block
        has_http_client = bool(re.search(r"\b(?:axios|fetch|request|urllib|httpx)\b", content, re.I))
        if has_http_client:
            for idx, line in enumerate(lines, 1):
                is_match = bool(raw_axios_err_re.search(line))
                if not is_match and raw_err_re.search(line):
                    chunk = "\n".join(lines[max(0, idx - 7):idx])
                    if re.search(r"\b(?:axios\.|fetch\(|https?\.request|http\.get|http\.post)\b", chunk, re.I):
                        is_match = True
                if is_match:
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

        # 2. Direct token / authorization header logging (excluding static string literals)
        for idx, line in enumerate(lines, 1):
            m_call = logger_call_re.search(line)
            if not m_call:
                continue

            arg_content = m_call.group(1).strip()
            is_leak = False
            matched_kw = ""

            # Check interpolation in template literals or f-strings
            m_tmpl = re.search(
                r'[`"].*?\$\{[^}]*\b(token|jwt|accessToken|refreshToken|bearer|client_secret)\b[^}]*\}.*?[`"]',
                arg_content,
                re.I,
            )
            if m_tmpl:
                is_leak = True
                matched_kw = m_tmpl.group(1)

            m_fstr = re.search(
                r'f[\'"].*?\{[^}]*\b(token|jwt|accessToken|refreshToken|bearer|client_secret)\b[^}]*\}.*?[\'"]',
                arg_content,
                re.I,
            )
            if m_fstr:
                is_leak = True
                matched_kw = m_fstr.group(1)

            # Check for header authorization expression
            if not is_leak and re.search(
                r"\breq\.headers(?:\.authorization|\[[\"']authorization[\"']\])",
                arg_content,
                re.I,
            ):
                is_leak = True
                matched_kw = "req.headers.authorization"

            # Check for token variables outside static string literals
            if not is_leak:
                # Strip ordinary non-interpolated string literals
                stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', arg_content)
                stripped = re.sub(r"'(?:[^'\\]|\\.)*'", "''", stripped)
                m_var = re.search(
                    r"\b(token|jwt|accessToken|refreshToken|bearer|client_secret)\b(?!\s*[:.\[])",
                    stripped,
                    re.I,
                )
                if m_var:
                    # Filter out non-sensitive metric names like tokenCount or totalLength
                    var_name = m_var.group(1)
                    if not any(fp in line.lower() for fp in ("token.length", "token.id", "tokencount")):
                        is_leak = True
                        matched_kw = var_name

            if is_leak:
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

    fallback_secret_patterns = [
        # Python: os.environ.get('SECRET_KEY', 'default') inside call
        re.compile(
            r"os\.environ\.get\(\s*['\"](?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)['\"]\s*,\s*['\"][^'\"]{3,}['\"]\s*\)",
            re.I,
        ),
        # Python: os.environ.get('SECRET_KEY') or 'default'
        re.compile(
            r"(?:os\.environ\.get\(\s*['\"](?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)['\"][^)]*\)|os\.environ\[\s*['\"](?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)['\"]\s*\])\s*or\s*['\"][^'\"]{3,}['\"]",
            re.I,
        ),
        # JavaScript / TypeScript: process.env.SECRET || 'default' or ?? 'default'
        re.compile(
            r"process\.env\.(?:JWT_SECRET|SECRET_KEY|TOKEN_SECRET)\s*(?:\|\||\?\?)\s*['\"][^'\"]{3,}['\"]",
            re.I,
        ),
    ]

    for path in sorted(code_files):
        lines = _safe_read_lines(path, repo_dir)
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
            if any(p.search(line) for p in fallback_secret_patterns):
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
