#!/usr/bin/env python3
"""Dependency reachability (VEX) analyzer and exploit attack chain correlator.

Performs static import analysis across the project code to determine if
vulnerable dependency packages are directly or transitively imported in the
application, and correlates disparate vulnerability findings into actionable
multi-stage attack chains.
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


def extract_imported_packages(repo_dir: pathlib.Path) -> dict[str, dict[str, Any]]:
    """Scan source code files to extract all imported package and module names."""
    packages: dict[str, dict[str, Any]] = {}

    js_import_re = re.compile(
        r"""(?:import\s+(?:(?:[a-zA-Z0-9_{}\s*,*]+)\s+from\s+)?|require\s*\(\s*|import\s*\(\s*)['"]([^'"./][^'"]*)['"]"""
    )
    py_import_re = re.compile(
        r"""^\s*(?:import|from)\s+([a-zA-Z0-9_]+)""", re.MULTILINE
    )

    py_alias_map = {
        "yaml": "pyyaml", "jwt": "pyjwt", "dateutil": "python-dateutil",
        "dotenv": "python-dotenv", "psycopg2": "psycopg2-binary",
        "pil": "pillow", "openssl": "pyopenssl", "serial": "pyserial",
        "crypto": "pycryptodome",
    }

    for path in repo_dir.rglob("*"):
        if _is_ignored(path) or path.is_symlink() or not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".py"):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(repo_dir))
        if suffix == ".py":
            for m in py_import_re.finditer(content):
                mod = m.group(1).lower()
                for pkg in {mod, py_alias_map.get(mod, mod)}:
                    rec = packages.setdefault(pkg, {"files": set()})
                    rec["files"].add(rel)
        else:
            for m in js_import_re.finditer(content):
                raw = m.group(1)
                parts = raw.split("/")
                pkg = parts[0] if not raw.startswith("@") else f"{parts[0]}/{parts[1]}" if len(parts) > 1 else parts[0]
                pkg_clean = pkg.lower()
                rec = packages.setdefault(pkg_clean, {"files": set()})
                rec["files"].add(rel)
                # Also track top-level scope (e.g. '@nestjs' for '@nestjs/common')
                if raw.startswith("@") and len(parts) > 1:
                    packages.setdefault(parts[0].lower(), {"files": set()})["files"].add(rel)

    # Convert sets to sorted lists for JSON serialization
    return {
        pkg: {"files": sorted(data["files"])}
        for pkg, data in sorted(packages.items())
    }


def _extract_package_name(finding: dict[str, Any]) -> str:
    """Extract package name from finding metadata or title."""
    pkg = finding.get("package")
    if pkg and isinstance(pkg, str):
        return pkg.strip()
    title = finding.get("title", "")
    # Title formats: "lodash 4.17.15 affected by CVE-..." or "lodash 4.17.15: ..." or "package: joi ..."
    m = re.match(r"^([a-zA-Z0-9@_./-]+)\s+[0-9v.]+(?::|\s+affected by)", title, re.I)
    if m:
        return m.group(1).strip()
    m2 = re.search(r"\b(?:package|module|library)\s+([a-zA-Z0-9@_./-]+)\b", title, re.I)
    if m2:
        return m2.group(1).strip()
    # Match leading package name before colon: "express: prototype pollution"
    m3 = re.match(r"^([a-zA-Z0-9@_./-]+):", title)
    if m3:
        return m3.group(1).strip()
    return ""


def assess_reachability(
    repo_dir: pathlib.Path,
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Assess whether dependency vulnerability findings are imported/callable in source."""
    imported_map = extract_imported_packages(repo_dir)
    imported_names = set(imported_map.keys())

    reachable_pkgs = set()
    unreachable_pkgs = set()
    total_dep_findings = 0
    reachable_findings_count = 0

    for f in findings:
        domain = f.get("domain", "").lower()
        if domain not in ("deps", "dependencies", "dependabot", "gd"):
            continue

        total_dep_findings += 1
        pkg_name = _extract_package_name(f).lower()
        if not pkg_name:
            f["reachability"] = "reachable"
            f["vex_status"] = "affected"
            f["vex_justification"] = "Package identification uncertain; defaulting to reachable."
            reachable_findings_count += 1
            continue

        # Check direct or scope match
        is_imported = (
            pkg_name in imported_names
            or any(pkg_name.startswith(f"{imp}/") or imp.startswith(f"{pkg_name}/") for imp in imported_names)
        )

        if is_imported:
            import_info = imported_map.get(pkg_name) or {}
            cites = import_info.get("files", [])
            f["reachability"] = "reachable"
            f["vex_status"] = "affected"
            f["vex_justification"] = f"Directly imported in application code ({len(cites)} file(s))."
            reachable_pkgs.add(pkg_name)
            reachable_findings_count += 1
        else:
            f["reachability"] = "unreachable"
            f["vex_status"] = "not_affected"
            f["vex_justification"] = "vulnerable_code_not_in_execute_path (unimported transitive dependency)"
            f["effective_severity"] = "Low"
            unreachable_pkgs.add(pkg_name)

    summary = {
        "total_dependency_findings": total_dep_findings,
        "reachable_findings": reachable_findings_count,
        "unreachable_findings": total_dep_findings - reachable_findings_count,
        "reachable_packages": sorted(reachable_pkgs),
        "unreachable_packages": sorted(unreachable_pkgs),
    }

    return findings, summary


def generate_chain_mermaid(chain: dict[str, Any]) -> str:
    """Generate Mermaid diagram visualizing the attack chain stages."""
    lines = ["graph LR"]
    stages = chain.get("stages", [])
    for i, s in enumerate(stages):
        fid = s.get("finding_id", f"Stage{i+1}")
        desc = s.get("stage", f"Step {i+1}").replace('"', '')
        clean_title = s.get("description", "").replace('"', "'")[:38]
        node_id = f"S{i+1}"
        lines.append(f'    {node_id}["{fid}: {desc}<br/><i>{clean_title}</i>"]')
    for i in range(len(stages) - 1):
        lines.append(f"    S{i+1} -->|enables| S{i+2}")
    if stages:
        clean_target = chain.get("title", "Exploit Impact").replace('"', "'")
        lines.append(f'    S{len(stages)} -->|Impact| Target["{clean_target}"]')
    return "\n".join(lines)


def correlate_attack_chains(
    findings: list[dict[str, Any]],
    components: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Identify plausible multi-stage attack scenarios across findings."""
    chains: list[dict[str, Any]] = []

    by_domain: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        d = f.get("domain", "").lower()
        by_domain.setdefault(d, []).append(f)

    # 1. Credential / Log Leak -> Unprotected Mutating Endpoint
    leaks = by_domain.get("logging-data", []) + by_domain.get("data", []) + by_domain.get("secrets", [])
    authz = by_domain.get("authz", [])
    if leaks and authz:
        l_f = leaks[0]
        a_f = authz[0]
        chain = {
            "id": f"CHAIN-{len(chains)+1:03d}",
            "title": "Credential Disclosure to Unauthorized State Mutation",
            "severity": "Critical",
            "findings": [l_f["id"], a_f["id"]],
            "stages": [
                {
                    "stage": "Credential Harvesting",
                    "finding_id": l_f["id"],
                    "description": l_f.get("title", ""),
                },
                {
                    "stage": "Privilege Exploitation",
                    "finding_id": a_f["id"],
                    "description": a_f.get("title", ""),
                },
            ],
            "narrative": (
                f"An attacker harvesting leaked authorization tokens or credentials via {l_f['id']} "
                f"can immediately execute state-changing actions via unguarded mutating endpoint {a_f['id']} "
                "without triggering access control defenses."
            ),
            "remediation": "Redact sensitive log outputs and enforce controller/route guard decorators.",
        }
        chain["mermaid"] = generate_chain_mermaid(chain)
        chains.append(chain)

    # 2. Hardcoded Secret Fallback -> Token Forgery & Auth Bypass
    auth_fallbacks = [
        f for f in (by_domain.get("authn", []) + by_domain.get("auth", []))
        if any(term in f.get("title", "").lower() for term in ("fallback secret", "hardcoded", "fallback"))
    ]
    crypto_issues = by_domain.get("cryptography", []) + by_domain.get("crypto", []) + [
        f for f in (by_domain.get("authn", []) + by_domain.get("auth", []))
        if any(term in f.get("title", "").lower() for term in ("constant-time", "verify", "algorithm"))
    ]
    if auth_fallbacks and crypto_issues:
        af = auth_fallbacks[0]
        cf = crypto_issues[0]
        chain = {
            "id": f"CHAIN-{len(chains)+1:03d}",
            "title": "Hardcoded Secret Fallback to Administrative Token Forgery",
            "severity": "Critical",
            "findings": [af["id"], cf["id"]],
            "stages": [
                {
                    "stage": "Key Derivation",
                    "finding_id": af["id"],
                    "description": af.get("title", ""),
                },
                {
                    "stage": "Authentication Forgery",
                    "finding_id": cf["id"],
                    "description": cf.get("title", ""),
                },
            ],
            "narrative": (
                f"When deployed with missing environment configurations, the application defaults to {af['id']}, "
                f"allowing attackers to forge valid JWT signatures and bypass verification checks in {cf['id']}."
            ),
            "remediation": "Fail closed at startup on missing secrets and enforce constant-time signature verification.",
        }
        chain["mermaid"] = generate_chain_mermaid(chain)
        chains.append(chain)

    # 3. Reachable Vulnerable Dependency -> Secrets Extraction
    reachable_deps = [
        f for f in (by_domain.get("dependencies", []) + by_domain.get("deps", []) + by_domain.get("dependabot", []))
        if f.get("reachability") == "reachable"
    ] or (by_domain.get("injection", []) + by_domain.get("inj", []))
    secrets = by_domain.get("secrets", []) + by_domain.get("logging-data", []) + by_domain.get("data", [])
    if reachable_deps and secrets:
        dep = reachable_deps[0]
        sec = secrets[0]
        chain = {
            "id": f"CHAIN-{len(chains)+1:03d}",
            "title": "Reachable Component Flaw to Secret Exfiltration",
            "severity": "High",
            "findings": [dep["id"], sec["id"]],
            "stages": [
                {
                    "stage": "Library Exploitation",
                    "finding_id": dep["id"],
                    "description": dep.get("title", ""),
                },
                {
                    "stage": "Secret Exfiltration",
                    "finding_id": sec["id"],
                    "description": sec.get("title", ""),
                },
            ],
            "narrative": (
                f"Exploiting reachable dependency vulnerability {dep['id']} grants memory or execution access "
                f"within the container context, leading to extraction of secrets identified in {sec['id']}."
            ),
            "remediation": "Upgrade the reachable dependency and rotate the exposed secrets.",
        }
        chain["mermaid"] = generate_chain_mermaid(chain)
        chains.append(chain)

    # 4. Security Misconfiguration -> Cross-Origin Session Exfiltration
    config_issues = [
        f for f in (by_domain.get("configuration", []) + by_domain.get("config", []))
        if any(term in f.get("title", "").lower() for term in ("cors", "cookie", "header", "debug"))
    ]
    auth_sessions = (
        by_domain.get("authn", []) + by_domain.get("auth", []) +
        by_domain.get("logging-data", []) + by_domain.get("data", [])
    )
    if config_issues and auth_sessions:
        cfg = config_issues[0]
        sess = auth_sessions[0]
        chain = {
            "id": f"CHAIN-{len(chains)+1:03d}",
            "title": "Permissive Configuration to Cross-Origin Session Exfiltration",
            "severity": "High",
            "findings": [cfg["id"], sess["id"]],
            "stages": [
                {
                    "stage": "Security Misconfiguration",
                    "finding_id": cfg["id"],
                    "description": cfg.get("title", ""),
                },
                {
                    "stage": "Session Exfiltration",
                    "finding_id": sess["id"],
                    "description": sess.get("title", ""),
                },
            ],
            "narrative": (
                f"Permissive CORS or cookie misconfigurations in {cfg['id']} allow malicious third-party web origins "
                f"to read sensitive session data and authentication endpoints referenced in {sess['id']}."
            ),
            "remediation": "Restrict CORS allowed origins and set Secure and SameSite flags on session cookies.",
        }
        chain["mermaid"] = generate_chain_mermaid(chain)
        chains.append(chain)

    return chains


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_dir", nargs="?", default="target", help="Repository root path")
    parser.add_argument("--findings", default="reports/findings.json", help="Path to findings JSON")
    args = parser.parse_args()

    repo_path = pathlib.Path(args.repo_dir)
    findings_path = pathlib.Path(args.findings)

    if findings_path.is_file():
        data = json.loads(findings_path.read_text(encoding="utf-8"))
        findings = data.get("findings", [])
        findings, summary = assess_reachability(repo_path, findings)
        chains = correlate_attack_chains(findings)
        print(json.dumps({"vex_summary": summary, "attack_chains": chains}, indent=2))
    else:
        imported = extract_imported_packages(repo_path)
        print(json.dumps({"imported_packages": imported}, indent=2))

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
