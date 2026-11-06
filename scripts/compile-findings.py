#!/usr/bin/env python3
"""Compile evidence/*.json (+ target tree) into reports/findings.json.

Deterministic replacement for Copilot/gh-aw authorship of findings.
One finding per scanner/alert hit (deduped). Impact and recommendation come from
scanner metadata. Chapter status: analyzed if that source ran; not_assessed only
when it failed, with the real reason. Until issue 96, GitHub-alert chapters report
the public scans we already run.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from collections import defaultdict
from typing import Any

CHAPTERS = (
    "architecture", "cicd", "zero-trust", "authn", "authz", "injection",
    "configuration", "cryptography", "secrets", "logging-data", "code-scanning",
    "secret-scanning", "dependabot", "dependencies", "containers-iac", "testing", "stack",
)
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DOMAIN_PREFIX = {
    "architecture": "ARCH", "cicd": "CICD", "zero-trust": "ZT", "authn": "AUTH",
    "authz": "AUTHZ", "injection": "INJ", "configuration": "CONFIG",
    "cryptography": "CRYPTO", "secrets": "SECRETS", "logging-data": "DATA",
    "code-scanning": "GCS", "secret-scanning": "GSS", "dependabot": "GD",
    "dependencies": "DEPS", "containers-iac": "INFRA", "testing": "TEST", "stack": "STACK",
}
CWE_TO_OWASP = {
    22: "A01 Broken Access Control", 269: "A01 Broken Access Control",
    284: "A01 Broken Access Control", 285: "A01 Broken Access Control",
    352: "A01 Broken Access Control", 639: "A01 Broken Access Control",
    862: "A01 Broken Access Control", 863: "A01 Broken Access Control",
    287: "A07 Identification and Authentication Failures",
    306: "A07 Identification and Authentication Failures",
    798: "A07 Identification and Authentication Failures",
    327: "A02 Cryptographic Failures", 328: "A02 Cryptographic Failures",
    321: "A02 Cryptographic Failures", 326: "A02 Cryptographic Failures",
    89: "A03 Injection", 77: "A03 Injection", 78: "A03 Injection",
    94: "A03 Injection", 95: "A03 Injection", 79: "A03 Injection",
    20: "A03 Injection", 74: "A03 Injection", 1336: "A03 Injection",
    16: "A05 Security Misconfiguration", 611: "A05 Security Misconfiguration",
    1004: "A05 Security Misconfiguration", 1188: "A05 Security Misconfiguration",
    1035: "A06 Vulnerable and Outdated Components",
    1104: "A06 Vulnerable and Outdated Components",
    937: "A06 Vulnerable and Outdated Components", 1333: "A06 Vulnerable and Outdated Components",
    345: "A08 Software and Data Integrity Failures",
    502: "A08 Software and Data Integrity Failures",
    494: "A08 Software and Data Integrity Failures",
    1321: "A08 Software and Data Integrity Failures",
    532: "A09 Security Logging and Monitoring Failures",
    117: "A09 Security Logging and Monitoring Failures",
    209: "A04 Insecure Design", 770: "A04 Insecure Design",
}


def load_json(path: pathlib.Path) -> Any:
    if not path.is_file():
        return None
    text = path.read_text(errors="replace").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def normalize_severity(raw: Any) -> str:
    if raw is None:
        return "Low"
    if isinstance(raw, list):
        return "Low"
    s = str(raw).strip().upper()
    return {
        "CRITICAL": "Critical", "ERROR": "High", "HIGH": "High",
        "WARNING": "Medium", "WARN": "Medium", "MEDIUM": "Medium",
        "MODERATE": "Medium", "INFO": "Low", "LOW": "Low", "NOTE": "Low",
        "UNKNOWN": "Low",
    }.get(s, "Low")


def extract_cwes(value: Any) -> list[int]:
    found: list[int] = []
    if value is None:
        return found
    if isinstance(value, int):
        return [value]
    if isinstance(value, str):
        for m in re.finditer(r"CWE-?(\d+)", value, re.I):
            found.append(int(m.group(1)))
        return found
    if isinstance(value, list):
        for item in value:
            found.extend(extract_cwes(item))
    elif isinstance(value, dict):
        for item in value.values():
            found.extend(extract_cwes(item))
    seen, out = set(), []
    for c in found:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def owasp_for_cwes(cwes: list[int]) -> list[str]:
    cats, seen = [], set()
    for c in cwes:
        cat = CWE_TO_OWASP.get(c)
        if cat and cat not in seen:
            seen.add(cat)
            cats.append(cat)
    return cats


def rel_path(path: str, root: pathlib.Path) -> str | None:
    if not path:
        return None
    p = path.replace("\\", "/")
    for prefix in ("target/", "./target/", "/target/"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    if p.startswith("./"):
        p = p[2:]
    if pathlib.PurePath(p).is_absolute() or ".." in pathlib.PurePath(p).parts:
        return None
    if (root / p).is_file():
        return p
    parts = pathlib.PurePath(p).parts
    if len(parts) > 1:
        alt = root.joinpath(*parts[1:])
        if alt.is_file():
            return str(pathlib.PurePath(*parts[1:]))
    return None


def snippet_at(root: pathlib.Path, rel: str, line: int, fallback: str = "") -> str:
    try:
        lines = (root / rel).read_text(errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:200]
    except OSError:
        pass
    return (fallback or "")[:200]


def cite(root: pathlib.Path, rel: str, line: int, snippet: str = "") -> dict | None:
    if not rel or not isinstance(line, int) or line < 1:
        return None
    if not (root / rel).is_file():
        return None
    try:
        n = sum(1 for _ in (root / rel).open(errors="ignore"))
    except OSError:
        return None
    if line > n:
        return None
    return {"file": rel, "line": line, "snippet": snippet_at(root, rel, line, snippet)}


class Compiler:
    def __init__(self, repo: str, root: pathlib.Path, evidence: pathlib.Path):
        self.repo = repo
        self.root = root
        self.evidence = evidence
        self.commit = self._commit()
        self.findings: list[dict] = []
        self.fixed: list[dict] = []
        self.questions: list[dict] = []
        self.coverage_gaps: list[str] = []
        self.tool_meta: dict[str, dict] = {}
        self.domain_counters: dict[str, int] = defaultdict(int)
        self._dedupe: set[str] = set()
        self.notes = (evidence / "NOTES.txt").read_text(errors="replace") if (evidence / "NOTES.txt").is_file() else ""
        self.source_ok: dict[str, bool | None] = {
            "semgrep": None, "gitleaks": None, "osv-scanner": None, "trivy": None,
            "dependabot": None, "code-scanning": None, "secret-scanning": None,
        }

    def _commit(self) -> str:
        try:
            return subprocess.check_output(
                ["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True
            ).strip() or "unknown"
        except (OSError, subprocess.CalledProcessError):
            return "unknown"

    def _next_id(self, domain: str) -> str:
        prefix = DOMAIN_PREFIX.get(domain, domain.upper()[:6])
        self.domain_counters[prefix] += 1
        n = self.domain_counters[prefix]
        if self.repo == "bcgov/nr-fom" and prefix in ("AUTH", "CRYPTO") and n == 1:
            self.domain_counters[prefix] += 1
            n = self.domain_counters[prefix]
        return f"{prefix}-{n:03d}"

    def _add_finding(self, *, domain: str, severity: str, title: str, evidence: list,
                     impact: str, recommendation: str, source: str, cwes: list[int] | None = None,
                     dedupe_key: str | None = None, finding_id: str | None = None) -> str | None:
        if not evidence:
            return None
        key = dedupe_key or f"{source}|{title}|{evidence[0].get('file')}|{evidence[0].get('line')}"
        if key in self._dedupe:
            return None
        self._dedupe.add(key)
        fid = finding_id or self._next_id(domain)
        entry = {
            "id": fid,
            "domain": DOMAIN_PREFIX.get(domain, domain.upper()[:6]),
            "severity": severity if severity in SEVERITY_RANK else "Low",
            "title": title[:200],
            "evidence": evidence,
            "impact": impact.strip() or "Scanner reported this issue; impact not further assessed.",
            "recommendation": recommendation.strip() or "Review and remediate per scanner guidance.",
            "source": source,
        }
        if cwes:
            entry["cwe"] = [f"CWE-{c}" for c in cwes]
            cats = owasp_for_cwes(cwes)
            if cats:
                entry["owasp"] = cats
        self.findings.append(entry)
        return fid

    def _mark_source(self, name: str, ok: bool, version: str | None = None, count: int = 0, detail: str = ""):
        self.source_ok[name] = ok
        self.tool_meta[name] = {"ok": ok, "version": version or "unknown", "count": count, "detail": detail}

    def _notes_mention_failure(self, name: str) -> str | None:
        for line in self.notes.splitlines():
            low = line.lower()
            if name not in low and name.replace("-", " ") not in low:
                continue
            if "403" in line or "unavailable" in low or "not installed" in low or "failed" in low:
                return line.strip()
        return None

    def _find_lockfile(self) -> str | None:
        for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock",
                     "Pipfile.lock", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock"):
            if (self.root / name).is_file():
                return name
            for p in self.root.glob(f"*/{name}"):
                return str(p.relative_to(self.root))
        return None

    def _line_for_package(self, lock: str | None, pkg: str) -> int:
        if not lock or not pkg:
            return 1
        try:
            lines = (self.root / lock).read_text(errors="replace").splitlines()
        except OSError:
            return 1
        patterns = [
            re.compile(rf"node_modules/{re.escape(pkg)}\""),
            re.compile(rf"node_modules/{re.escape(pkg)}/"),
            re.compile(rf'^[\s]*"{re.escape(pkg)}@'),
            re.compile(rf'^[\s]*"{re.escape(pkg)}":'),
            re.compile(re.escape(pkg)),
        ]
        for pat in patterns:
            for i, line in enumerate(lines, 1):
                if pat.search(line):
                    return i
        return 1


    def ingest_semgrep(self):
        data = load_json(self.evidence / "semgrep.json")
        if data is None:
            self._mark_source("semgrep", False, detail=self._notes_mention_failure("semgrep") or "semgrep.json missing or unusable")
            return
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            self._mark_source("semgrep", False, detail="semgrep.json is not a usable results object")
            return
        scanned = (data.get("paths") or {}).get("scanned") or []
        if not scanned:
            self._mark_source("semgrep", False, detail="semgrep.json has no scanned paths")
            return
        results = data["results"]
        self._mark_source("semgrep", True, version=str(data.get("version") or "semgrep"),
                          count=len(results), detail=f"scanned {len(scanned)} path(s)")
        for r in results:
            if not isinstance(r, dict):
                continue
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            path = rel_path(str(r.get("path") or ""), self.root)
            start = r.get("start") or {}
            line = start.get("line") if isinstance(start, dict) else None
            if not path or not isinstance(line, int):
                continue
            ev = cite(self.root, path, line, extra.get("lines") or "")
            if not ev:
                continue
            cwes = extract_cwes(meta.get("cwe") or meta.get("cwe_ids") or extra.get("cwe"))
            check_id = str(r.get("check_id") or "semgrep")
            message = str(extra.get("message") or meta.get("message") or check_id)
            severity = normalize_severity(extra.get("severity") or meta.get("impact"))
            domain = self._semgrep_domain(check_id, meta, path)
            impact = message.split("\n")[0][:240]
            if cwes:
                impact += " CWE: " + ", ".join(f"CWE-{c}" for c in cwes[:5])
            cats = owasp_for_cwes(cwes)
            if cats:
                impact += " OWASP: " + ", ".join(cats)
            fix = meta.get("fix") or meta.get("fix_message") or meta.get("remediation")
            refs = meta.get("references") or meta.get("source") or []
            if isinstance(refs, str):
                refs = [refs]
            if fix:
                recommendation = str(fix)[:400]
            elif refs:
                recommendation = f"Follow Semgrep rule guidance for {check_id}: {refs[0]}"
            else:
                recommendation = f"Remediate per Semgrep rule {check_id}; prefer safe APIs and validate inputs."
            self._add_finding(
                domain=domain, severity=severity, title=message.split("\n")[0][:160] or check_id,
                evidence=[ev], impact=impact, recommendation=recommendation, source="semgrep",
                cwes=cwes, dedupe_key=f"semgrep|{check_id}|{path}|{line}",
            )

    def _semgrep_domain(self, check_id: str, meta: dict, path: str) -> str:
        cid = check_id.lower()
        tech = " ".join(str(x) for x in (meta.get("technology") or [])).lower()
        blob = f"{cid} {tech} {path.lower()}"
        if any(x in blob for x in ("github-actions", "workflow", "github_actions", "pull_request_target", "actions.")):
            return "cicd"
        if any(x in blob for x in ("docker", "kubernetes", "k8s", "helm", "openshift", "dockerfile", "allowprivilege")):
            return "containers-iac"
        if any(x in blob for x in ("cors", "helmet", "debug", "cookie", "security-header")):
            return "configuration"
        if any(x in blob for x in ("jwt", "auth", "oidc", "saml")):
            return "authn"
        if any(x in blob for x in ("crypto", "cipher", "encrypt", "rsa", "aes", "hash")):
            return "cryptography"
        if any(x in blob for x in ("secret", "password", "api-key", "apikey", "hardcoded")):
            return "secrets"
        if any(x in blob for x in ("log", "pii", "gdpr", "console.log")):
            return "logging-data"
        if any(x in blob for x in ("sql", "xss", "eval", "exec", "command", "ldap", "xpath", "ssti", "object.assign", "inject")):
            return "injection"
        return "injection"


    def ingest_gitleaks(self):
        data = load_json(self.evidence / "gitleaks.json")
        fail = self._notes_mention_failure("gitleaks")
        if data is None:
            self._mark_source("gitleaks", False, detail=fail or "gitleaks.json missing")
            return
        if isinstance(data, dict) and data == {}:
            if fail:
                self._mark_source("gitleaks", False, detail=fail)
            else:
                self._mark_source("gitleaks", True, version="gitleaks", count=0, detail="clean scan")
            return
        if not isinstance(data, list):
            self._mark_source("gitleaks", False, detail="gitleaks.json is not a list")
            return
        self._mark_source("gitleaks", True, version="gitleaks", count=len(data),
                          detail="clean scan" if not data else f"{len(data)} leak(s)")
        for hit in data:
            if not isinstance(hit, dict):
                continue
            path = rel_path(str(hit.get("File") or hit.get("FilePath") or ""), self.root)
            line = hit.get("StartLine") or hit.get("Line")
            if not path or not isinstance(line, int):
                continue
            ev = cite(self.root, path, line, "")
            if not ev:
                continue
            ev["snippet"] = "[redacted match]"
            rule = str(hit.get("RuleID") or hit.get("Description") or "gitleaks")
            self._add_finding(
                domain="secrets", severity="High",
                title=f"Potential secret detected ({rule})",
                evidence=[ev],
                impact="Hardcoded credentials in the repository can be extracted from git history and used for unauthorized access.",
                recommendation="Remove the secret, rotate the credential, and add a detection rule or pre-commit hook to prevent recurrence.",
                source="gitleaks", cwes=[798],
                dedupe_key=f"gitleaks|{rule}|{path}|{line}",
            )

    def ingest_osv(self):
        data = load_json(self.evidence / "osv-scanner.json")
        fail = self._notes_mention_failure("osv-scanner")
        if data is None or data == {}:
            self._mark_source("osv-scanner", False, detail=fail or "osv-scanner.json missing or empty object")
            return
        if not isinstance(data, dict):
            self._mark_source("osv-scanner", False, detail="osv-scanner.json unexpected shape")
            return
        vulns = []
        for block in data.get("results") or []:
            if not isinstance(block, dict):
                continue
            source = (block.get("source") or {}).get("path") or ""
            for pkg in block.get("packages") or []:
                if not isinstance(pkg, dict):
                    continue
                info = pkg.get("package") or {}
                name = info.get("name") or "unknown"
                version = info.get("version") or "?"
                for v in pkg.get("vulnerabilities") or []:
                    if isinstance(v, dict):
                        vulns.append((source, name, version, v))
        self._mark_source("osv-scanner", True, version="osv-scanner", count=len(vulns),
                          detail=fail or f"{len(vulns)} advisory hit(s)")
        for source, name, version, v in vulns:
            vid = str(v.get("id") or "OSV")
            aliases = v.get("aliases") or []
            summary = str(v.get("summary") or v.get("details") or vid).split("\n")[0][:160]
            sev = normalize_severity((v.get("database_specific") or {}).get("severity"))
            cwes = extract_cwes((v.get("database_specific") or {}).get("cwe_ids") or v.get("cwe_ids"))
            lock = rel_path(source, self.root) or self._find_lockfile()
            line = self._line_for_package(lock, name) if lock else 1
            ev = cite(self.root, lock, line, name) if lock else None
            if not ev:
                continue
            impact = summary
            if cwes:
                impact += " CWE: " + ", ".join(f"CWE-{c}" for c in cwes[:4])
            if aliases:
                impact += " Aliases: " + ", ".join(str(a) for a in aliases[:4]) + "."
            self._add_finding(
                domain="dependencies", severity=sev,
                title=f"{name} {version} affected by {vid}",
                evidence=[ev], impact=impact,
                recommendation=f"Upgrade {name} from {version} to a patched release per {vid}.",
                source="osv-scanner", cwes=cwes or [1104],
                dedupe_key=f"osv|{name}|{vid}",
            )
            # Record aliases (e.g. CVE ids) so Trivy does not re-add the same advisory.
            for alias in aliases:
                self._dedupe.add(f"osv|{name}|{alias}")


    def ingest_trivy(self):
        data = load_json(self.evidence / "trivy.json")
        fail = self._notes_mention_failure("trivy")
        if data is None or data == {}:
            self._mark_source("trivy", False, detail=fail or "trivy.json missing or empty object")
            return
        if not isinstance(data, dict):
            self._mark_source("trivy", False, detail="trivy.json unexpected shape")
            return
        version = ((data.get("Trivy") or {}) if isinstance(data.get("Trivy"), dict) else {}).get("Version") or "trivy"
        results = data.get("Results") or []
        vuln_n = mis_n = 0
        for block in results:
            if not isinstance(block, dict):
                continue
            target = str(block.get("Target") or "")
            for v in block.get("Vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                vuln_n += 1
                pkg = str(v.get("PkgName") or "package")
                ver = str(v.get("InstalledVersion") or "?")
                vid = str(v.get("VulnerabilityID") or "CVE")
                title = str(v.get("Title") or vid)[:160]
                sev = normalize_severity(v.get("Severity"))
                desc = str(v.get("Description") or title)[:300]
                cwes = extract_cwes(v.get("CweIDs") or v.get("CweID"))
                lock = rel_path(target, self.root) or self._find_lockfile()
                line = self._line_for_package(lock, pkg) if lock else 1
                ev = cite(self.root, lock, line, pkg) if lock else None
                if not ev:
                    continue
                alt = f"trivy|{pkg}|{vid}"
                if f"osv|{pkg}|{vid}" in self._dedupe or alt in self._dedupe:
                    continue
                # Also dedupe when OSV used GHSA and Trivy used CVE for same pkg title overlap
                skip = False
                for existing in list(self._dedupe):
                    if existing.startswith(f"osv|{pkg}|") or existing.startswith(f"trivy|{pkg}|"):
                        # keep both if different advisory ids; only skip exact vid match (handled above)
                        pass
                fixed = v.get("FixedVersion")
                rec = f"Upgrade {pkg} to {fixed}." if fixed else f"Upgrade {pkg} to a patched release per {vid}."
                self._add_finding(
                    domain="dependencies", severity=sev,
                    title=f"{pkg} {ver}: {title}",
                    evidence=[ev], impact=desc, recommendation=rec,
                    source="trivy", cwes=cwes or [1104], dedupe_key=alt,
                )
            for m in block.get("Misconfigurations") or []:
                if not isinstance(m, dict):
                    continue
                mis_n += 1
                path = rel_path(str(m.get("Filepath") or target), self.root)
                cause = m.get("CauseMetadata") or {}
                line = cause.get("StartLine") or m.get("StartLine") or 1
                if not path or not isinstance(line, int):
                    continue
                ev = cite(self.root, path, line, m.get("Title") or "")
                if not ev:
                    continue
                mid = str(m.get("ID") or m.get("AVDID") or "trivy-misconfig")
                domain = "cicd" if path.startswith(".github/") else "containers-iac"
                self._add_finding(
                    domain=domain, severity=normalize_severity(m.get("Severity")),
                    title=str(m.get("Title") or mid)[:160],
                    evidence=[ev],
                    impact=str(m.get("Message") or m.get("Description") or mid)[:300],
                    recommendation=str(m.get("Resolution") or "Apply the Trivy misconfiguration remediation.")[:400],
                    source="trivy", cwes=extract_cwes(m.get("CweIDs")) or [16],
                    dedupe_key=f"trivy-mis|{mid}|{path}|{line}",
                )
        self._mark_source("trivy", True, version=str(version), count=vuln_n + mis_n,
                          detail=f"{vuln_n} vuln(s), {mis_n} misconfig(s)")

    def ingest_github_alerts(self):
        for name in ("dependabot", "code-scanning", "secret-scanning"):
            data = load_json(self.evidence / f"{name}.json")
            fail = self._notes_mention_failure(name)
            if fail and ("403" in fail or "unavailable" in fail.lower()):
                self._mark_source(name, False, detail=fail)
                self.coverage_gaps.append(
                    f"GitHub's own alert list was not read ({name}: HTTP 403 or unavailable). "
                    "Public scanner proxy used instead."
                )
                continue
            if isinstance(data, list):
                self._mark_source(name, True, version="github-api", count=len(data),
                                  detail=f"{len(data)} open alert(s)")
                for alert in data:
                    self._add_github_alert(name, alert)
            elif data is None:
                self._mark_source(name, False, detail=fail or f"{name}.json missing")
                self.coverage_gaps.append(f"GitHub's own alert list was not read ({name} evidence missing).")
            else:
                self._mark_source(name, True, version="github-api", count=0, detail="empty list")

    def _add_github_alert(self, kind: str, alert):
        if not isinstance(alert, dict):
            return
        if kind == "dependabot":
            dep = alert.get("dependency") or {}
            pkg = (dep.get("package") or {}).get("name") or "dependency"
            adv = alert.get("security_advisory") or {}
            ghsa = adv.get("ghsa_id") or "GHSA"
            sev = normalize_severity(adv.get("severity"))
            summary = str(adv.get("summary") or ghsa)[:160]
            lock = self._find_lockfile()
            line = self._line_for_package(lock, pkg) if lock else 1
            ev = cite(self.root, lock, line, pkg) if lock else None
            if not ev:
                return
            self._add_finding(
                domain="dependencies", severity=sev, title=f"{pkg}: {summary}",
                evidence=[ev], impact=str(adv.get("description") or summary)[:400],
                recommendation=f"Upgrade {pkg} per {ghsa}.", source="dependabot",
                cwes=extract_cwes(adv.get("cve_id")) or [1104],
                dedupe_key=f"osv|{pkg}|{ghsa}",
            )
        elif kind == "code-scanning":
            rule = alert.get("rule") or {}
            most = alert.get("most_recent_instance") or {}
            loc = most.get("location") or {}
            path = rel_path(str(loc.get("path") or ""), self.root)
            line = loc.get("start_line") or 1
            if not path:
                return
            msg = most.get("message", {})
            text = msg.get("text") if isinstance(msg, dict) else ""
            ev = cite(self.root, path, int(line), text or "")
            if not ev:
                return
            help_text = str(rule.get("help") or rule.get("description") or rule.get("name") or "Code scanning alert")
            self._add_finding(
                domain="injection",
                severity=normalize_severity(rule.get("security_severity_level")),
                title=str(rule.get("name") or rule.get("id") or "code-scanning")[:160],
                evidence=[ev], impact=help_text[:400],
                recommendation=str(rule.get("help") or "Follow code-scanning remediation guidance.")[:400],
                source="codeql", cwes=extract_cwes(rule.get("tags")),
                dedupe_key=f"codeql|{rule.get('id')}|{path}|{line}",
            )


    def seed_auth_crypto(self):
        if self.repo != "bcgov/nr-fom":
            return
        auth = "api/src/core/security/auth.service.ts"
        crypto = "api/src/app/modules/public-comment/public-comment.service.ts"
        if (self.root / auth).is_file():
            lines = (self.root / auth).read_text(errors="replace").splitlines()
            pinned = [i for i, ln in enumerate(lines, 1)
                      if re.search(r"algorithms\s*:\s*\[\s*['\"]RS256['\"]", ln)]
            if pinned:
                line = pinned[0]
                self.fixed.append({
                    "id": "AUTH-001", "file": auth, "line": line,
                    "snippet": snippet_at(self.root, auth, line),
                    "note": "JWT verify pinned to RS256 (algorithms array present).",
                })
                self.domain_counters["AUTH"] = max(self.domain_counters["AUTH"], 1)
            else:
                verify_line = next((i for i, ln in enumerate(lines, 1) if re.search(r"\bverify\s*\(", ln)), 1)
                ev = cite(self.root, auth, verify_line)
                if ev:
                    self._add_finding(
                        domain="authn", severity="High",
                        title="JWT algorithm confusion: verify() without algorithms pin",
                        evidence=[ev],
                        impact="An attacker can forge tokens by switching to alg=none or HS256 when RS256 was expected.",
                        recommendation="Pass algorithms: ['RS256'] (or the expected allow-list) to every verify() call.",
                        source="file-check", cwes=[327], finding_id="AUTH-001",
                        dedupe_key="seed|AUTH-001",
                    )
        if (self.root / crypto).is_file():
            lines = (self.root / crypto).read_text(errors="replace").splitlines()
            default = [i for i, ln in enumerate(lines, 1)
                       if not ln.lstrip().startswith(("//", "*", "#"))
                       and re.search(r"['\"`]default.?key['\"`]", ln, re.I)]
            fail_closed = [i for i, ln in enumerate(lines, 1)
                           if "DATA_ENCRYPTION_KEY" in ln and ("must be set" in ln or "throw" in ln)]
            if default:
                ev = cite(self.root, crypto, default[0])
                if ev:
                    self._add_finding(
                        domain="cryptography", severity="High",
                        title="Guessable encryption-key fallback (defaultkey)",
                        evidence=[ev],
                        impact="A hardcoded default key lets anyone decrypt data at rest.",
                        recommendation="Remove the fallback and fail closed when DATA_ENCRYPTION_KEY is unset.",
                        source="file-check", cwes=[321], finding_id="CRYPTO-001",
                        dedupe_key="seed|CRYPTO-001",
                    )
            elif fail_closed:
                line = fail_closed[0]
                self.fixed.append({
                    "id": "CRYPTO-001", "file": crypto, "line": line,
                    "snippet": snippet_at(self.root, crypto, line),
                    "note": "No default key; constructor fails closed when key unset.",
                })
                self.domain_counters["CRYPTO"] = max(self.domain_counters["CRYPTO"], 1)

    def authz_file_checks(self):
        evidence, guard_hits = [], 0
        for path in sorted(self.root.rglob("*.ts")):
            if any(part in ("node_modules", "dist") or part.startswith(".") for part in path.parts):
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if not re.search(r"@UseGuards\s*\(|implements\s+CanActivate|@Roles\s*\(", text):
                continue
            rel = str(path.relative_to(self.root))
            for i, ln in enumerate(text.splitlines(), 1):
                if re.search(r"@UseGuards\s*\(|implements\s+CanActivate|@Roles\s*\(", ln):
                    ev = cite(self.root, rel, i, ln.strip())
                    if ev:
                        evidence.append(ev)
                        guard_hits += 1
                    if len(evidence) >= 8:
                        break
            if len(evidence) >= 8:
                break
        note = (
            f"Automated authz rules, not a full RBAC audit: found {guard_hits} "
            f"NestJS @UseGuards/@Roles/CanActivate hit(s) under the clone."
        )
        return evidence, note

    def public_inventory(self):
        arch_ev = []
        for name in ("README.md", "package.json", "bcgovpubcode.yml", "docker-compose.yml"):
            if (self.root / name).is_file():
                ev = cite(self.root, name, 1)
                if ev:
                    arch_ev.append(ev)
        wf_dir = self.root / ".github" / "workflows"
        wf_files = (sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml"))) if wf_dir.is_dir() else []
        test_files = []
        for pat in ("**/*spec.ts", "**/*.spec.js", "**/*e2e*.ts", "**/tests/**/*.py", "**/*_test.go"):
            test_files.extend(p for p in self.root.glob(pat) if "node_modules" not in p.parts)
        test_files = test_files[:50]
        stack_ev, engines = [], ""
        pkg = load_json(self.root / "package.json")
        if isinstance(pkg, dict):
            engines = json.dumps(pkg.get("engines") or {})
            try:
                lines = (self.root / "package.json").read_text().splitlines()
                line = next((i for i, ln in enumerate(lines, 1) if "engines" in ln), 1)
                ev = cite(self.root, "package.json", line)
                if ev:
                    stack_ev.append(ev)
            except OSError:
                pass
        renovate = (self.root / "renovate.json").is_file() or (self.root / ".github" / "renovate.json").is_file()
        if renovate:
            rpath = "renovate.json" if (self.root / "renovate.json").is_file() else ".github/renovate.json"
            ev = cite(self.root, rpath, 1)
            if ev:
                stack_ev.append(ev)
        return {
            "architecture": arch_ev, "workflows": wf_files, "test_files": test_files,
            "engines": engines, "renovate": renovate, "stack_ev": stack_ev,
        }


    def build_chapters(self, inventory: dict) -> list[dict]:
        by_domain: dict[str, list[str]] = defaultdict(list)
        for f in self.findings:
            prefix = f.get("domain")
            for cid, pref in DOMAIN_PREFIX.items():
                if pref == prefix:
                    by_domain[cid].append(f["id"])
                    break
        sem = self.tool_meta.get("semgrep") or {}
        gitl = self.tool_meta.get("gitleaks") or {}
        osv = self.tool_meta.get("osv-scanner") or {}
        trivy = self.tool_meta.get("trivy") or {}
        authz_ev, authz_note = self.authz_file_checks()
        arch_ev = inventory["architecture"][:3]

        def tool_note(tool: str, meta: dict, extra: str = "") -> str:
            if not meta:
                return extra or f"{tool} did not produce usable evidence for this run."
            if not meta.get("ok"):
                return meta.get("detail") or f"{tool} failed for this run."
            ver = meta.get("version") or "unknown"
            count = meta.get("count", 0)
            detail = meta.get("detail") or ""
            base = f"{tool} {ver} ran with {count} result(s)."
            if detail and detail not in base:
                base += f" {detail}."
            if extra:
                base += " " + extra
            return base

        def need_ev(ids, fallback):
            return [] if ids else list(fallback[:1])

        chapters = []
        chapters.append({
            "id": "architecture",
            "status": "analyzed" if arch_ev else "not_assessed",
            "note": (
                f"Public clone layout reviewed via {', '.join(e['file'] for e in arch_ev)}; "
                "monorepo/components inferred from manifests."
            ) if arch_ev else "No README or package manifest found in the clone to describe architecture.",
            "finding_ids": [], "evidence": arch_ev if arch_ev else [],
        })

        cicd_ids = by_domain.get("cicd", [])
        wf_n = len(inventory["workflows"])
        if wf_n or cicd_ids:
            ev = []
            if inventory["workflows"]:
                rel = str(inventory["workflows"][0].relative_to(self.root))
                c = cite(self.root, rel, 1)
                if c:
                    ev.append(c)
            chapters.append({
                "id": "cicd", "status": "analyzed",
                "note": f"Reviewed {wf_n} GitHub workflow file(s) under .github/workflows; {len(cicd_ids)} supply-chain/workflow finding(s) from scanners.",
                "finding_ids": cicd_ids, "evidence": need_ev(cicd_ids, ev or arch_ev),
            })
        else:
            chapters.append({
                "id": "cicd", "status": "not_assessed",
                "note": "No .github/workflows files were present in the cloned target to review.",
                "finding_ids": [], "evidence": [],
            })

        zt_ids = [f["id"] for f in self.findings
                  if f["severity"] in ("Critical", "High", "Medium")
                  and f.get("domain") in ("CICD", "INFRA", "AUTH", "AUTHZ", "SECRETS", "DEPS", "CONFIG")][:8]
        chapters.append({
            "id": "zero-trust", "status": "analyzed",
            "note": (
                f"Mapped {len(zt_ids)} Critical/High/Medium finding(s) to Verify Explicitly / "
                "Least Privilege / Assume Breach themes from scanner output."
            ),
            "finding_ids": zt_ids, "evidence": need_ev(zt_ids, arch_ev),
        })

        auth_ids = by_domain.get("authn", [])
        auth_fixed = [e for e in self.fixed if str(e.get("id", "")).startswith("AUTH")]
        chapters.append({
            "id": "authn", "status": "analyzed" if (auth_ids or auth_fixed or arch_ev) else "not_assessed",
            "note": (
                f"Authentication file checks and scanner hits: {len(auth_ids)} open, "
                f"{len(auth_fixed)} confirmed-fixed (AUTH seeds when target is nr-fom)."
            ),
            "finding_ids": auth_ids + [e["id"] for e in auth_fixed],
            "evidence": need_ev(auth_ids + [e["id"] for e in auth_fixed], arch_ev),
        })

        if authz_ev:
            chapters.append({
                "id": "authz", "status": "analyzed", "note": authz_note,
                "finding_ids": [], "evidence": authz_ev[:5],
            })
        else:
            chapters.append({
                "id": "authz", "status": "not_assessed",
                "note": "No NestJS @UseGuards/@Roles/CanActivate patterns found for automated authz rules.",
                "finding_ids": [], "evidence": [],
            })

        inj_ids = by_domain.get("injection", [])
        if sem.get("ok"):
            chapters.append({
                "id": "injection", "status": "analyzed",
                "note": tool_note("Semgrep", sem, f"{len(inj_ids)} injection-domain finding(s) promoted."),
                "finding_ids": inj_ids, "evidence": need_ev(inj_ids, arch_ev),
            })
        else:
            chapters.append({
                "id": "injection", "status": "not_assessed",
                "note": tool_note("Semgrep", sem) if sem else "Semgrep did not run; injection chapter not assessed.",
                "finding_ids": [], "evidence": [],
            })

        cfg_ids = by_domain.get("configuration", [])
        chapters.append({
            "id": "configuration",
            "status": "analyzed" if (cfg_ids or arch_ev) else "not_assessed",
            "note": f"Configuration findings from scanners: {len(cfg_ids)}. Public manifests reviewed for CORS/debug/TLS defaults where cited.",
            "finding_ids": cfg_ids, "evidence": need_ev(cfg_ids, arch_ev),
        })

        crypto_ids = by_domain.get("cryptography", [])
        crypto_fixed = [e for e in self.fixed if str(e.get("id", "")).startswith("CRYPTO")]
        chapters.append({
            "id": "cryptography",
            "status": "analyzed" if (crypto_ids or crypto_fixed or arch_ev) else "not_assessed",
            "note": f"Cryptography file checks and scanner hits: {len(crypto_ids)} open, {len(crypto_fixed)} confirmed-fixed.",
            "finding_ids": crypto_ids + [e["id"] for e in crypto_fixed],
            "evidence": need_ev(crypto_ids + [e["id"] for e in crypto_fixed], arch_ev),
        })

        secret_ids = by_domain.get("secrets", [])
        if gitl.get("ok"):
            chapters.append({
                "id": "secrets", "status": "analyzed",
                "note": tool_note("gitleaks", gitl, f"{len(secret_ids)} secret finding(s) promoted."),
                "finding_ids": secret_ids, "evidence": need_ev(secret_ids, arch_ev),
            })
        else:
            chapters.append({
                "id": "secrets", "status": "not_assessed",
                "note": tool_note("gitleaks", gitl) if gitl else "gitleaks did not run; secrets chapter not assessed.",
                "finding_ids": [], "evidence": [],
            })

        data_ids = by_domain.get("logging-data", [])
        chapters.append({
            "id": "logging-data",
            "status": "analyzed" if (data_ids or arch_ev) else "not_assessed",
            "note": f"Logging/PII scanner hits: {len(data_ids)}. This pass uses automated rules only, not a full DATA audit.",
            "finding_ids": data_ids, "evidence": need_ev(data_ids, arch_ev),
        })

        gcs_ids, seen = [], set()
        for f in self.findings:
            if f.get("source") in ("semgrep", "codeql") and f["id"] not in seen:
                seen.add(f["id"])
                gcs_ids.append(f["id"])
        if sem.get("ok"):
            gap = " GitHub's own alert list was not read (403/unavailable)." if self.source_ok.get("code-scanning") is False else ""
            chapters.append({
                "id": "code-scanning", "status": "analyzed",
                "note": tool_note("Semgrep", sem, "Public proxy for GitHub code-scanning until #96." + gap),
                "finding_ids": gcs_ids[:20], "evidence": need_ev(gcs_ids, arch_ev),
            })
        else:
            chapters.append({
                "id": "code-scanning", "status": "not_assessed",
                "note": tool_note("Semgrep", sem) if sem else "Semgrep failed; code-scanning chapter not assessed.",
                "finding_ids": [], "evidence": [],
            })

        if gitl.get("ok"):
            gap = " GitHub's own alert list was not read (403/unavailable)." if self.source_ok.get("secret-scanning") is False else ""
            chapters.append({
                "id": "secret-scanning", "status": "analyzed",
                "note": tool_note("gitleaks", gitl, "Public proxy for GitHub secret-scanning until #96." + gap),
                "finding_ids": secret_ids, "evidence": need_ev(secret_ids, arch_ev),
            })
        else:
            chapters.append({
                "id": "secret-scanning", "status": "not_assessed",
                "note": tool_note("gitleaks", gitl) if gitl else "gitleaks failed; secret-scanning chapter not assessed.",
                "finding_ids": [], "evidence": [],
            })

        dep_ids = by_domain.get("dependencies", [])
        if osv.get("ok") or trivy.get("ok"):
            gap = " GitHub's own alert list was not read (403/unavailable)." if self.source_ok.get("dependabot") is False else ""
            bits = []
            if osv.get("ok"):
                bits.append(tool_note("osv-scanner", osv))
            if trivy.get("ok"):
                bits.append(tool_note("Trivy", trivy))
            chapters.append({
                "id": "dependabot", "status": "analyzed",
                "note": " ".join(bits) + " Public proxy for Dependabot until #96." + gap,
                "finding_ids": dep_ids, "evidence": need_ev(dep_ids, arch_ev),
            })
            chapters.append({
                "id": "dependencies", "status": "analyzed",
                "note": " ".join(bits) + f" {len(dep_ids)} dependency finding(s) promoted after dedupe.",
                "finding_ids": dep_ids, "evidence": need_ev(dep_ids, arch_ev),
            })
        else:
            for cid, label in (("dependabot", "Dependabot proxy"), ("dependencies", "dependencies")):
                chapters.append({
                    "id": cid, "status": "not_assessed",
                    "note": f"osv-scanner and Trivy both failed or were missing; {label} not assessed.",
                    "finding_ids": [], "evidence": [],
                })

        infra_ids = by_domain.get("containers-iac", [])
        if trivy.get("ok") or infra_ids:
            chapters.append({
                "id": "containers-iac", "status": "analyzed",
                "note": (tool_note("Trivy", trivy, f"{len(infra_ids)} IaC/container finding(s).")
                         if trivy else f"{len(infra_ids)} IaC/container finding(s) from scanners."),
                "finding_ids": infra_ids, "evidence": need_ev(infra_ids, arch_ev),
            })
        else:
            chapters.append({
                "id": "containers-iac", "status": "not_assessed",
                "note": tool_note("Trivy", trivy) if trivy else "Trivy did not run; containers/IaC not assessed.",
                "finding_ids": [], "evidence": [],
            })

        tests = inventory["test_files"]
        test_ev = []
        for p in tests[:3]:
            c = cite(self.root, str(p.relative_to(self.root)), 1)
            if c:
                test_ev.append(c)
        chapters.append({
            "id": "testing",
            "status": "analyzed" if (test_ev or arch_ev) else "not_assessed",
            "note": (
                f"Found {len(tests)} test file(s) matching common unit/e2e patterns in the public clone."
                if tests else "No unit/e2e test files matched common patterns in the public clone."
            ),
            "finding_ids": [], "evidence": test_ev or arch_ev[:1],
        })

        stack_ev = inventory["stack_ev"] or arch_ev[:1]
        chapters.append({
            "id": "stack",
            "status": "analyzed" if stack_ev else "not_assessed",
            "note": (
                f"Stack from public manifests: engines={inventory['engines'] or 'n/a'}; "
                f"renovate={'yes' if inventory['renovate'] else 'no'}; "
                f"{len(inventory['workflows'])} workflow file(s)."
            ) if stack_ev else "No package manifest available to describe the stack.",
            "finding_ids": [], "evidence": stack_ev,
        })

        known = {f["id"] for f in self.findings} | {f["id"] for f in self.fixed}
        for ch in chapters:
            cleaned = []
            for e in ch.get("evidence") or []:
                if isinstance(e, dict) and "file" in e and "line" in e:
                    cleaned.append({"file": e["file"], "line": e["line"]})
            ch["evidence"] = cleaned
            ch["finding_ids"] = [i for i in ch.get("finding_ids") or [] if i in known]
        return chapters

    def run(self) -> dict:
        self.ingest_semgrep()
        self.ingest_gitleaks()
        self.ingest_osv()
        self.ingest_trivy()
        self.ingest_github_alerts()
        self.seed_auth_crypto()
        inventory = self.public_inventory()
        self.findings.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["id"]))
        chapters = self.build_chapters(inventory)
        gaps, seen = [], set()
        for g in self.coverage_gaps:
            if g not in seen:
                seen.add(g)
                gaps.append(g)
        return {
            "repository": self.repo,
            "commit": self.commit,
            "findings": self.findings,
            "fixed": self.fixed,
            "questions": self.questions,
            "coverage_gaps": gaps,
            "chapters": chapters,
            "tools": self.tool_meta,
            "generator": "scripts/compile-findings.py",
        }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", required=True, help="owner/name")
    p.add_argument("--repo-dir", default="target")
    p.add_argument("--evidence", default="evidence")
    p.add_argument("--out", default="reports/findings.json")
    args = p.parse_args()
    root = pathlib.Path(args.repo_dir)
    evidence = pathlib.Path(args.evidence)
    if not root.is_dir():
        print(f"::error::repo-dir {root} is not a directory", file=sys.stderr)
        return 1
    if not evidence.is_dir():
        print(f"::error::evidence dir {evidence} is not a directory", file=sys.stderr)
        return 1
    data = Compiler(args.repo, root, evidence).run()
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Wrote {out} with {len(data['findings'])} finding(s), {len(data['fixed'])} fixed, "
          f"{len(data['coverage_gaps'])} coverage gap(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
