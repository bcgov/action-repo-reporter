"""Regression tests use temporary repos and scanner stubs; no API calls/dispatch."""
import copy
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("chapters", ROOT / "scripts/validate-chapters.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def render(data):
    text = "# Assessment\n\n## Scope\n| Domain | Status | Findings |\n|---|---|---|\n"
    for c in data["chapters"]:
        text += f"| {c['id']} | {c['status']} | {len(c['finding_ids'])} |\n"
    findings = {f.get("id"): f for f in data.get("findings") or [] if isinstance(f, dict)}
    for c in data["chapters"]:
        text += f"\n## {c['id']}\nStatus: {c['status']}\n{c['note']}\n"
        # Substance beyond note+IDs so the raised chapter gate can pass in unit tests.
        text += "Tooling detail: scripted chapter body includes impact context for citations.\n"
        for fid in c["finding_ids"]:
            f = findings.get(fid) or {}
            text += f"{fid} {f.get('title','')} impact:{f.get('impact','n/a')}\n"
        for e in c["evidence"]:
            if isinstance(e, dict):
                text += f"{e.get('file')}:{e.get('line')}\n"
    return text


class ChapterGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "auth.ts").write_text("verify(token, {algorithms: ['RS256']});\n")
        self.data = {"findings": [], "fixed": [], "chapters": [
            {"id": name, "status": "not_assessed", "note": "Cross repository alert access denied with HTTP 403 for this source.",
             "finding_ids": [], "evidence": []} for name in gate.CHAPTERS]}

    def errors(self, markdown=None):
        return gate.validate(self.data, render(self.data) if markdown is None else markdown, self.root)

    def analyze(self):
        self.data["chapters"][3].update(status="analyzed", note="JWT validation pins accepted algorithms explicitly on the verification call.",
                                       evidence=[{"file": "auth.ts", "line": 1}])

    def test_explicit_not_assessed_with_specific_reason(self):
        self.assertEqual([], self.errors())

    def test_analyzed_with_valid_source(self):
        self.analyze()
        self.assertEqual([], self.errors())

    def test_cited_finding_and_fixed_support_analysis(self):
        for fixed in (False, True):
            with self.subTest(fixed=fixed):
                self.data["findings"] = []
                self.data["fixed"] = []
                entry = {"id": "AUTH-001", "evidence": [{"file": "auth.ts", "line": 1}],
                         "impact": "Algorithm confusion can forge tokens.",
                         "recommendation": "Pin algorithms on verify calls.",
                         "title": "JWT alg pin"}
                if not fixed:
                    entry["severity"] = "High"
                self.data["fixed" if fixed else "findings"] = [entry]
                c = self.data["chapters"][3]
                c.update(status="analyzed", note="The referenced verification finding is supported by the inspected source.", finding_ids=["AUTH-001"])
                self.assertEqual([], self.errors())

    def test_old_shallow_claim_rejected(self):
        for c in self.data["chapters"]:
            c.update(status="analyzed", note="Limited review; scanners clean/quiet except noted.")
        self.assertTrue(any("requires cited" in e for e in self.errors()))
        self.assertTrue(any("placeholder" in e for e in self.errors()))

    def test_plausible_prose_without_evidence_rejected(self):
        self.data["chapters"][4].update(status="analyzed", note="The authorization controls appear sufficient based on a limited manual review.")
        self.assertTrue(any("requires cited" in e for e in self.errors()))

    def test_missing_and_duplicate_chapters_rejected(self):
        self.data["chapters"][-1] = copy.deepcopy(self.data["chapters"][0])
        self.assertTrue(self.errors())
        self.data["chapters"].pop()
        self.assertTrue(self.errors())

    def test_invalid_source_citations_rejected(self):
        self.analyze()
        for ev in ({"file": "missing", "line": 1}, {"file": "auth.ts", "line": 2},
                   {"file": "../escape", "line": 1}, {"file": "/etc/passwd", "line": 1},
                   {"file": "auth.ts", "line": True}, "auth.ts:1"):
            with self.subTest(ev=ev):
                self.data["chapters"][3]["evidence"] = [ev]
                self.assertTrue(any("invalid source" in e for e in self.errors()))

    def test_symlink_escape_rejected(self):
        (self.root / "escape").symlink_to("/etc/passwd")
        self.analyze()
        self.data["chapters"][3]["evidence"] = [{"file": "escape", "line": 1}]
        self.assertTrue(self.errors())

    def test_unknown_or_uncited_finding_rejected(self):
        self.analyze()
        self.data["chapters"][3].update(evidence=[], finding_ids=["AUTH-999"])
        self.assertTrue(self.errors())
        self.data["findings"] = [{"id": "AUTH-999", "severity": "High", "evidence": [{"file": "missing", "line": 1}]}]
        self.assertTrue(self.errors())

    def test_finding_without_severity_cannot_support_analyzed(self):
        self.analyze()
        self.data["chapters"][3].update(evidence=[], finding_ids=["AUTH-001"])
        self.data["findings"] = [{"id": "AUTH-001", "evidence": [{"file": "auth.ts", "line": 1}]}]
        self.assertTrue(self.errors())

    def test_top_level_evidence_only_supports_fixed_not_open_findings(self):
        self.analyze()
        self.data["chapters"][3].update(evidence=[], finding_ids=["AUTH-001"])
        entry = {"id": "AUTH-001", "severity": "High", "file": "auth.ts", "line": 1}
        self.data["findings"] = [entry]
        self.assertTrue(self.errors())
        self.data["findings"] = []
        self.data["fixed"] = [entry]
        self.assertEqual([], self.errors())

    def test_markdown_citations_require_exact_file_and_line(self):
        self.analyze()
        markdown = render(self.data)
        for wrong in ("auth.ts:10", "other/auth.ts:1", "/auth.ts:1", "auth.ts:1oops", "other:auth.ts:1"):
            with self.subTest(citation=wrong):
                self.assertTrue(any("missing source citation" in e for e in self.errors(markdown.replace("auth.ts:1", wrong))))
        for valid in ("`auth.ts:1`", "(auth.ts:1)", "[auth.ts:1](https://example.test/source)"):
            with self.subTest(citation=valid):
                self.assertEqual([], self.errors(markdown.replace("auth.ts:1", valid)))

    def test_markdown_must_match_status_note_cites_and_scope(self):
        self.analyze()
        correct = render(self.data)
        mutations = [correct.replace("Status: analyzed", "Status: not_assessed"),
                     correct.replace("auth.ts:1", ""),
                     correct.replace(self.data["chapters"][3]["note"], "Different conclusion entirely"),
                     correct.replace("| authn | analyzed | 0 |", "| authn | not_assessed | 0 |"),
                     correct + "\n## authn\nStatus: analyzed\n"]
        for markdown in mutations:
            with self.subTest(markdown=markdown):
                self.assertTrue(self.errors(markdown))

    def test_generic_not_assessed_reason_rejected(self):
        self.data["chapters"][0]["note"] = "not assessed"
        self.assertTrue(self.errors())

    def test_cli_fails_loud_without_publishing(self):
        findings = self.root / "findings.json"
        report = self.root / "report.md"
        findings.write_text(json.dumps({"chapters": []}))
        report.write_text("# shallow report")
        result = subprocess.run([sys.executable, str(ROOT / "scripts/validate-chapters.py"), str(findings), str(report),
                                 "--repo-dir", str(self.root)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("::error::Chapter substance gate", result.stderr)


class SemgrepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(sys.executable)
        self.out = self.root / "evidence"
        self.out.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}:/usr/bin:/bin")

    def run_scan(self, content, code=0, stderr=""):
        binary = self.bin / "semgrep"
        binary.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                          f"open(sys.argv[sys.argv.index('-o')+1], 'w').write({content!r})\n"
                          f"print({stderr!r}, file=sys.stderr)\nsys.exit({code})\n")
        binary.chmod(0o755)
        return subprocess.run(["bash", str(ROOT / "scripts/run-semgrep.sh"), str(self.out), "target"],
                              env=self.env, text=True, capture_output=True)

    def test_clean_scan_is_usable(self):
        result = self.run_scan('{"results": [], "paths": {"scanned": ["target/auth.ts"]}}')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], json.loads((self.out / "semgrep.json").read_text())["results"])

    def test_findings_are_usable(self):
        self.assertEqual(0, self.run_scan('{"results": [{"check_id":"rule"}], "paths": {"scanned": ["x"]}}').returncode)

    def test_import_failure_names_error_and_removes_stale_json(self):
        (self.out / "semgrep.json").write_text('{"stale":true}')
        result = self.run_scan('{}', 2, "TypeError: Metaclasses with custom tp_new are not supported.")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("TypeError: Metaclasses", result.stderr)
        self.assertIn("Semgrep runtime/scan failed (exit 2)", result.stderr)
        self.assertFalse((self.out / "semgrep.json").exists())

    def test_invalid_missing_or_zero_scanned_evidence_fails(self):
        for output in ('{}', '', '{broken', '{"results":[]}', '{"results":[],"paths":{"scanned":[]}}'):
            with self.subTest(output=output):
                result = self.run_scan(output)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("invalid/unusable evidence", result.stderr)
                self.assertFalse((self.out / "semgrep.json").exists())

    def test_missing_scanner_fails_loud(self):
        result = subprocess.run(["bash", str(ROOT / "scripts/run-semgrep.sh"), str(self.out), "target"],
                                env=self.env, text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Semgrep runtime unavailable", result.stderr)


class PipelineFailureTests(unittest.TestCase):
    def test_failed_assessment_cannot_publish_diagnostic_artifacts(self):
        workflow = (ROOT / ".github/workflows/generate-reports.yml").read_text()
        organize = workflow.split("      - name: Organize Reports\n", 1)[1]
        shell = organize.split("        run: |\n", 1)[1].split("      - name:", 1)[0]
        shell = "\n".join(line[10:] for line in shell.splitlines())
        with tempfile.TemporaryDirectory() as tmp:
            for state in ("failure", "cancelled", "skipped"):
                with self.subTest(state=state):
                    result = subprocess.run(["bash", "-c", shell], cwd=tmp,
                                            env=dict(os.environ, ASSESS_RESULT=state), text=True, capture_output=True)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("refusing to publish", result.stdout)
                    self.assertFalse((pathlib.Path(tmp) / "reports").exists())

    def test_installer_names_failed_command_and_runtime_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            python = root / "python3.14"
            python.write_text("#!/bin/sh\necho 'venv creation failed: ensurepip unavailable' >&2\nexit 7\n")
            python.chmod(0o755)
            result = subprocess.run(["bash", str(ROOT / "scripts/install-semgrep.sh")],
                                    env=dict(os.environ, PATH=tmp + ":/usr/bin:/bin", RUNNER_TEMP=tmp,
                                             GITHUB_PATH=str(root / "path")), text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Semgrep install/runtime preflight failed", result.stderr)
            self.assertIn("ensurepip unavailable", result.stderr)
            self.assertIn("python3.14 -m venv", result.stderr)



class RaisedBarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        (self.root / "auth.ts").write_text("verify(token, {algorithms: ['RS256']});\n")
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.data = {"findings": [], "fixed": [], "chapters": [
            {"id": name, "status": "not_assessed",
             "note": "Cross repository alert access denied with HTTP 403 for this source.",
             "finding_ids": [], "evidence": []} for name in gate.CHAPTERS]}

    def test_finding_requires_impact_and_recommendation(self):
        self.data["findings"] = [{
            "id": "INJ-001", "severity": "Low",
            "evidence": [{"file": "auth.ts", "line": 1}],
            "title": "x",
        }]
        self.data["chapters"][5].update(
            status="analyzed",
            note="Semgrep 1.0 ran with 1 result(s) and promoted an injection finding.",
            finding_ids=["INJ-001"],
        )
        errors = gate.validate(self.data, render(self.data), self.root, self.evidence)
        self.assertTrue(any("impact" in e for e in errors))
        self.data["findings"][0]["impact"] = "User input reaches a dangerous sink."
        self.data["findings"][0]["recommendation"] = "Validate and encode output."
        # still needs markdown substance; render helper supplies it
        # also need semgrep evidence if we mark injection analyzed with scanner rule —
        # injection is a scanner chapter; without evidence file, skip-check does not fire.
        errors = gate.validate(self.data, render(self.data), self.root, self.evidence)
        self.assertEqual([], errors, errors)

    def test_scanner_chapter_cannot_skip_when_evidence_exists(self):
        (self.evidence / "semgrep.json").write_text(json.dumps({
            "results": [], "paths": {"scanned": ["auth.ts"]}, "version": "1.0"
        }))
        # code-scanning left not_assessed despite usable semgrep evidence
        errors = gate.validate(self.data, render(self.data), self.root, self.evidence)
        self.assertTrue(any("code-scanning" in e and "not_assessed" in e for e in errors), errors)

    def test_note_plus_ids_only_rejected(self):
        self.data["findings"] = [{
            "id": "INJ-001", "severity": "Low", "title": "eval",
            "impact": "User input reaches eval.",
            "recommendation": "Remove eval of untrusted input.",
            "evidence": [{"file": "auth.ts", "line": 1}],
        }]
        self.data["chapters"][5].update(
            status="analyzed",
            note="Semgrep 1.0 ran with 1 result(s) on the injection ruleset today.",
            finding_ids=["INJ-001"], evidence=[],
        )
        # Hand-build a #95-shaped shallow markdown section for injection only
        md = render(self.data)
        # Replace injection section with note+ids only
        shallow = []
        for line in md.splitlines():
            shallow.append(line)
        md2 = md
        import re as _re
        md2 = _re.sub(
            r"## injection\nStatus: analyzed\n.*?(?=\n## |\Z)",
            "## injection\nStatus: analyzed\nSemgrep 1.0 ran with 1 result(s) on the injection ruleset today.\n- INJ-001\n\n",
            md2,
            count=1,
            flags=_re.S,
        )
        errors = gate.validate(self.data, md2, self.root, self.evidence)
        self.assertTrue(any("only a note plus IDs" in e for e in errors), errors)


class DigestTests(unittest.TestCase):
    def test_digest_cite_check_drops_unknown_finding(self):
        spec = importlib.util.spec_from_file_location("digest", ROOT / "scripts/write-digest.py")
        dig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dig)
        data = {
            "repository": "bcgov/nr-fom",
            "findings": [{"id": "DEPS-001", "severity": "High", "title": "x",
                          "impact": "GHSA-aaaa-bbbb-cccc in pkg", "recommendation": "upgrade"}],
            "fixed": [],
            "chapters": [{"id": c, "status": "analyzed"} for c in gate.CHAPTERS],
            "coverage_gaps": [],
        }
        fids, ch, adv = dig.allowed_refs(data)
        bad = "See FIND-999 and CVE-2099-0001 in architecture."
        errs = dig.cite_check(bad, fids, ch, adv)
        self.assertTrue(errs)

    def test_deterministic_digest_passes_cite_check(self):
        spec = importlib.util.spec_from_file_location("digest", ROOT / "scripts/write-digest.py")
        dig = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dig)
        data = {
            "repository": "bcgov/nr-fom",
            "findings": [{"id": "DEPS-001", "severity": "High", "title": "joi advisory",
                          "impact": "DoS", "recommendation": "upgrade"}],
            "fixed": [{"id": "AUTH-001"}],
            "chapters": [{"id": c, "status": "analyzed"} for c in gate.CHAPTERS],
            "coverage_gaps": ["GitHub's own alert list was not read (code-scanning: HTTP 403 or unavailable)."],
        }
        text = dig.deterministic_digest(data, "reports/nr-fom/security-assessment.md")
        fids, ch, adv = dig.allowed_refs(data)
        self.assertEqual([], dig.cite_check(text, fids, ch, adv), text)




class CompileTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("compile_findings", ROOT / "scripts/compile-findings.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_crypto_comment_is_not_default_key_and_fail_closed_is_fixed(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "t"
            svc = root / "api/src/app/modules/public-comment"
            svc.mkdir(parents=True)
            (svc / "public-comment.service.ts").write_text(
                "const key = process.env.DATA_ENCRYPTION_KEY;\n"
                "// never use a guessable default key\n"
                "throw new Error('DATA_ENCRYPTION_KEY environment variable must be set.');\n")
            ev = pathlib.Path(tmp) / "e"; ev.mkdir()
            c = mod.Compiler("bcgov/nr-fom", root, ev)
            c.seed_auth_crypto()
            self.assertEqual(["CRYPTO-001"], [f["id"] for f in c.fixed])
            self.assertEqual([], c.findings)

    def test_trivy_cve_alias_of_osv_ghsa_is_deduped(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "t"; root.mkdir()
            (root / "package-lock.json").write_text('{\n "node_modules/joi": {}\n}\n')
            ev = pathlib.Path(tmp) / "e"; ev.mkdir()
            (ev / "osv-scanner.json").write_text(json.dumps({"results": [{"source": {"path": "package-lock.json"},
                "packages": [{"package": {"name": "joi", "version": "18.3.0"}, "vulnerabilities": [
                    {"id": "GHSA-4528-x5fx-h6hg", "aliases": ["CVE-2026-118772"], "summary": "ReDoS",
                     "database_specific": {"severity": "HIGH"}}]}]}]}))
            (ev / "trivy.json").write_text(json.dumps({"Trivy": {"Version": "0.76.1"}, "Results": [
                {"Target": "package-lock.json", "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-2026-118772", "PkgName": "joi", "InstalledVersion": "18.3.0", "Severity": "HIGH"}]}]}))
            c = mod.Compiler("bcgov/x", root, ev)
            c.ingest_osv(); c.ingest_trivy()
            self.assertEqual(1, len(c.findings))


class ReviewRegressionTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("compile_findings2", ROOT / "scripts/compile-findings.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_absolute_path_inside_root_becomes_relative(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); (root / "api").mkdir(); (root / "api/package-lock.json").write_text("{}\n")
            self.assertEqual("api/package-lock.json", mod.rel_path(str(root / "api/package-lock.json"), root))
            self.assertIsNone(mod.rel_path("/etc/passwd", root))

    def test_symlink_escape_not_read(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp); (root / "leak").symlink_to("/etc/hostname")
            self.assertIsNone(mod.cite(root, "leak", 1))

    def test_auth_fixed_only_when_every_verify_pinned(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "t"; d = root / "api/src/core/security"; d.mkdir(parents=True)
            (d / "auth.service.ts").write_text("verify(a, k, {\n  algorithms: ['RS256'],\n});\nverify(b, k);\n")
            ev = pathlib.Path(tmp) / "e"; ev.mkdir()
            c = mod.Compiler("bcgov/nr-fom", root, ev); c.seed_auth_crypto()
            self.assertEqual([], c.fixed)
            self.assertEqual(["AUTH-001"], [f["id"] for f in c.findings])
            self.assertEqual(4, c.findings[0]["evidence"][0]["line"])

    def test_gitleaks_empty_with_failure_note_is_not_clean(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "t"; root.mkdir()
            ev = pathlib.Path(tmp) / "e"; ev.mkdir()
            (ev / "gitleaks.json").write_text("[]")
            (ev / "NOTES.txt").write_text("WARN: gitleaks not installed\n")
            c = mod.Compiler("bcgov/x", root, ev); c.ingest_gitleaks()
            self.assertFalse(c.tool_meta["gitleaks"]["ok"])


class ComponentTopologyTests(unittest.TestCase):
    def load_modules(self):
        spec_cc = importlib.util.spec_from_file_location("cc", ROOT / "scripts/classify-components.py")
        mod_cc = importlib.util.module_from_spec(spec_cc)
        spec_cc.loader.exec_module(mod_cc)

        spec_cf = importlib.util.spec_from_file_location("cf", ROOT / "scripts/compile-findings.py")
        mod_cf = importlib.util.module_from_spec(spec_cf)
        spec_cf.loader.exec_module(mod_cf)

        spec_rr = importlib.util.spec_from_file_location("rr", ROOT / "scripts/render-report.py")
        mod_rr = importlib.util.module_from_spec(spec_rr)
        spec_rr.loader.exec_module(mod_rr)
        return mod_cc, mod_cf, mod_rr

    def test_nr_fom_layout_classification(self):
        cc, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "admin" / "angular.json").parent.mkdir(parents=True)
            (t / "admin" / "angular.json").write_text("{}")
            (t / "admin" / "Caddyfile").write_text(":8080")
            (t / "public" / "angular.json").parent.mkdir(parents=True)
            (t / "public" / "angular.json").write_text("{}")
            (t / "api" / "src" / "core" / "security").mkdir(parents=True)
            (t / "api" / "nest-cli.json").write_text("{}")
            (t / "db").mkdir()

            comps = cc.classify_components(t, "bcgov/nr-fom")
            c_ids = {c["id"]: c for c in comps}

            self.assertIn("admin-web-server", c_ids)
            self.assertIn("admin", c_ids)
            self.assertEqual("frontend", c_ids["admin"]["type"])
            self.assertIn("public", c_ids)
            self.assertEqual("frontend", c_ids["public"]["type"])
            self.assertIn("api", c_ids)
            self.assertEqual("api", c_ids["api"]["type"])
            self.assertIn("auth-gateway", c_ids)
            self.assertEqual("auth-gateway", c_ids["auth-gateway"]["type"])
            self.assertIn("database", c_ids)
            self.assertEqual("database", c_ids["database"]["type"])

    def test_nested_portals_and_batch_classification(self):
        cc, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "frontend" / "src" / "app" / "admin").mkdir(parents=True)
            (t / "frontend" / "src" / "app" / "public").mkdir(parents=True)
            (t / "frontend" / "angular.json").write_text("{}")
            (t / "api" / "src" / "core" / "security").mkdir(parents=True)
            (t / "api" / "src" / "batch").mkdir(parents=True)
            (t / "api" / "nest-cli.json").write_text("{}")
            (t / "Caddyfile").write_text(":8080")
            (t / "db").mkdir()

            comps = cc.classify_components(t, "bcgov/nr-fom")
            c_ids = {c["id"]: c for c in comps}

            self.assertIn("admin-portal", c_ids)
            self.assertIn("public-portal", c_ids)
            self.assertIn("auth-gateway", c_ids)
            self.assertIn("api-src-batch", c_ids)
            self.assertEqual("batch", c_ids["api-src-batch"]["type"])

    def test_django_and_crawler_classification(self):
        cc, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "frontend" / "rctool" / "migrations").mkdir(parents=True)
            (t / "frontend" / "manage.py").write_text("# django")
            (t / "frontend" / "nginx.conf.template").write_text("# nginx")
            (t / "compose.yml").write_text("services:\n  db:\n    image: postgres:15\n")
            comps = cc.classify_components(t, "bcgov/nr-hydrometric-rating-curve")
            c_ids = {c["id"]: c for c in comps}
            self.assertIn("frontend-ingress", c_ids)
            self.assertIn("frontend-app", c_ids)
            self.assertIn("database", c_ids)

        with tempfile.TemporaryDirectory() as tmp2:
            t2 = pathlib.Path(tmp2)
            (t2 / "api" / "src").mkdir(parents=True)
            (t2 / "api" / "package.json").write_text('{"dependencies": {"express": "^4.0"}}')
            (t2 / "crawler" / "src").mkdir(parents=True)
            (t2 / "database").mkdir()
            comps2 = cc.classify_components(t2, "bcgov/pubcode")
            c_ids2 = {c["id"]: c for c in comps2}
            self.assertIn("crawler", c_ids2)
            self.assertEqual("batch", c_ids2["crawler"]["type"])
            self.assertIn("api", c_ids2)
            self.assertIn("database", c_ids2)

    def test_finding_attribution_and_risk_ranking(self):
        cc, cf, rr = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "target"; root.mkdir()
            (root / "api" / "src" / "core" / "security").mkdir(parents=True)
            (root / "api" / "nest-cli.json").write_text("{}")
            (root / "admin" / "angular.json").parent.mkdir(parents=True)
            (root / "admin" / "angular.json").write_text("{}")
            (root / "db").mkdir()
            ev = pathlib.Path(tmp) / "evidence"; ev.mkdir()

            compiler = cf.Compiler("bcgov/nr-fom", root, ev)
            compiler.findings = [
                {
                    "id": "AUTH-002",
                    "severity": "Critical",
                    "title": "Bypass in auth gateway",
                    "evidence": [{"file": "api/src/core/security/auth.guard.ts", "line": 10}],
                    "impact": "Full authentication bypass",
                    "recommendation": "Fix the guard check",
                    "domain": "AUTH",
                    "source": "semgrep",
                },
                {
                    "id": "DEPS-001",
                    "severity": "High",
                    "title": "Vulnerable lib in admin",
                    "evidence": [{"file": "admin/package.json", "line": 15}],
                    "impact": "XSS in admin portal",
                    "recommendation": "Upgrade library",
                    "domain": "DEPS",
                    "source": "osv-scanner",
                },
                {
                    "id": "API-001",
                    "severity": "Medium",
                    "title": "Unvalidated param in api",
                    "evidence": [{"file": "api/src/controllers/fom.controller.ts", "line": 20}],
                    "impact": "Input validation gap",
                    "recommendation": "Use class-validator",
                    "domain": "INJ",
                    "source": "semgrep",
                },
            ]

            data = compiler.run()
            self.assertIn("components", data)
            self.assertIn("architecture", data)
            self.assertIn("mermaid", data["architecture"])
            self.assertTrue(data["architecture"]["mermaid"].startswith("graph TD"))

            findings_by_id = {f["id"]: f for f in data["findings"]}
            self.assertEqual("auth-gateway", findings_by_id["AUTH-002"].get("component"))
            self.assertEqual("admin", findings_by_id["DEPS-001"].get("component"))
            self.assertEqual("api", findings_by_id["API-001"].get("component"))

            md = rr.render(data)
            self.assertIn("## Component risk ranking", md)
            # auth-gateway has Critical (10), admin has High (5), api has Medium (2)
            self.assertIn("Authentication Gateway (`auth-gateway`) — Risk Score: 10", md)
            self.assertIn("Admin Portal (`admin`) — Risk Score: 5", md)
            self.assertIn("API Service (`api`) — Risk Score: 2", md)
            self.assertIn("### Architecture overview", md)
            self.assertIn("```mermaid", md)

    def test_copilot_review_edge_cases(self):
        cc, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            # 1. Merge paths for auth-gateway (both api/src/core/security and api/src/auth)
            (t / "api" / "src" / "core" / "security").mkdir(parents=True)
            (t / "api" / "src" / "auth").mkdir(parents=True)
            (t / "api" / "requirements.txt").write_text("fastapi==0.100.0\n")
            (t / "api" / "src" / "main.py").write_text("# main")

            # 2. Nested portals & shared frontend
            (t / "frontend" / "src" / "app" / "admin").mkdir(parents=True)
            (t / "frontend" / "package.json").write_text('{"dependencies": {"react": "^18.0"}}')

            # 3. Ingress
            (t / "Caddyfile").write_text(":8080\nreverse_proxy api:3000\n")

            comps = cc.classify_components(t, "test-repo")
            c_by_id = {c["id"]: c for c in comps}

            # Verify auth-gateway merged both paths
            self.assertIn("auth-gateway", c_by_id)
            self.assertIn("api/src/core/security", c_by_id["auth-gateway"]["paths"])
            self.assertIn("api/src/auth", c_by_id["auth-gateway"]["paths"])

            # Verify api-src is NOT registered as a separate duplicate component
            self.assertIn("api", c_by_id)
            self.assertNotIn("api-src", c_by_id)

            # Verify frontend is retained alongside admin-portal
            self.assertIn("admin-portal", c_by_id)
            self.assertIn("frontend", c_by_id)

            # Verify attribution of shared frontend file vs nested admin file
            f_shared = {"title": "Shared UI flaw", "evidence": [{"file": "frontend/package.json"}]}
            f_admin = {"title": "Admin flaw", "evidence": [{"file": "frontend/src/app/admin/users.tsx"}]}
            self.assertEqual("frontend", cc.attribute_finding_to_component(f_shared, comps))
            self.assertEqual("admin-portal", cc.attribute_finding_to_component(f_admin, comps))

            # Verify confirmed-fixed / seed findings with top-level file or cite attribute properly
            fixed_auth = {"id": "AUTH-001", "file": "api/src/auth/token.py", "title": "Token flaw"}
            fixed_cite = {"id": "AUTH-002", "cite": "api/src/core/security/keycloak.py:42", "title": "Keycloak flaw"}
            self.assertEqual("auth-gateway", cc.attribute_finding_to_component(fixed_auth, comps))
            self.assertEqual("auth-gateway", cc.attribute_finding_to_component(fixed_cite, comps))

            # Verify Mermaid diagram retains ingress connections alongside frontends
            diagram = cc.generate_mermaid_diagram(comps)
            self.assertIn("node_web_server", diagram)
            self.assertIn("node_api", diagram)
            self.assertIn("node_frontend", diagram)

        # 4. Root-level Django project mapping to '.'
        with tempfile.TemporaryDirectory() as tmp2:
            t2 = pathlib.Path(tmp2)
            (t2 / "manage.py").write_text("# django")
            (t2 / "myapp" / "views.py").parent.mkdir(parents=True)
            (t2 / "myapp" / "views.py").write_text("# view")
            comps2 = cc.classify_components(t2, "django-repo")
            c_by_id2 = {c["id"]: c for c in comps2}
            self.assertIn("django-app", c_by_id2)
            self.assertIn(".", c_by_id2["django-app"]["paths"])

            f_view = {"title": "View flaw", "evidence": [{"file": "myapp/views.py"}]}
            self.assertEqual("django-app", cc.attribute_finding_to_component(f_view, comps2))


if __name__ == "__main__":
    unittest.main()
