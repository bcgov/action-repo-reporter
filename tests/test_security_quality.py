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


class DashboardSummaryTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location("dashboard", ROOT / "scripts/render-dashboard-summary.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_empty_reports_renders_clean_message(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            out = mod.render_dashboard(pathlib.Path(tmp))
            self.assertIn("No organized target reports found.", out)

    def test_rollup_table_and_target_details_rendered(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "nr-fom"
            target.mkdir()
            (target / "score.json").write_text(json.dumps({
                "score": 94,
                "counts": {"Critical": 0, "High": 5, "Medium": 34, "Low": 1}
            }))
            (target / "findings.json").write_text(json.dumps({
                "repository": "bcgov/nr-fom",
                "commit": "abc1234",
                "findings": [{"id": "DEPS-001", "severity": "High", "title": "joi"}],
                "fixed": [{"id": "AUTH-001", "note": "RS256 pinned"}],
                "coverage_gaps": ["No alerts API access"]
            }))
            (target / "cover-letter.md").write_text("Executive cover letter text with [security-assessment.md](security-assessment.md).")

            out = mod.render_dashboard(root)
            self.assertIn("# Multi-Repo Security Assessments Dashboard", out)
            self.assertIn("| [bcgov/nr-fom](https://github.com/bcgov/nr-fom) | **94** / 100 | 0 | 5 | 34 | 1 | 1 | 1 | `bcgov-nr-fom-security-assessment` |", out)
            self.assertIn("<summary><strong>bcgov/nr-fom</strong> — Score: 94 / 100 (1 findings, 1 fixed)</summary>", out)
            self.assertIn("Executive cover letter text with [security-assessment.md](https://github.com/bcgov/action-repo-reporter/blob/main/reports/nr-fom/security-assessment.md).", out)
            self.assertIn("**Confirmed Fixed:**", out)
            self.assertIn("- `AUTH-001`: RS256 pinned", out)
            self.assertIn("- **DEPS-001** [High]: joi", out)
            self.assertIn("- No alerts API access", out)
            # Ensure file on disk was not mutated
            self.assertEqual("Executive cover letter text with [security-assessment.md](security-assessment.md).", (target / "cover-letter.md").read_text())

    def test_rollup_table_with_artifact_map(self):
        mod = self.load()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = root / "nr-fom"
            target.mkdir()
            (target / "score.json").write_text(json.dumps({
                "score": 94,
                "counts": {"Critical": 0, "High": 5, "Medium": 34, "Low": 1}
            }))
            (target / "findings.json").write_text(json.dumps({
                "repository": "bcgov/nr-fom",
                "commit": "abc1234",
                "findings": [],
                "fixed": []
            }))
            art_map = {
                "bcgov-nr-fom-security-assessment": "https://github.com/bcgov/action-repo-reporter/actions/runs/123/artifacts/456"
            }
            out = mod.render_dashboard(root, art_map)
            self.assertIn("| [bcgov/nr-fom](https://github.com/bcgov/nr-fom) | **94** / 100 | 0 | 5 | 34 | 1 | 0 | 0 | [`bcgov-nr-fom-security-assessment`](https://github.com/bcgov/action-repo-reporter/actions/runs/123/artifacts/456) |", out)




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


class SemanticAnalyzersTests(unittest.TestCase):
    def load_modules(self):
        spec_sem = importlib.util.spec_from_file_location("sem", ROOT / "scripts/analyze-semantic-domains.py")
        mod_sem = importlib.util.module_from_spec(spec_sem)
        spec_sem.loader.exec_module(mod_sem)

        spec_cf = importlib.util.spec_from_file_location("cf", ROOT / "scripts/compile-findings.py")
        mod_cf = importlib.util.module_from_spec(spec_cf)
        spec_cf.loader.exec_module(mod_cf)

        spec_vc = importlib.util.spec_from_file_location("vc", ROOT / "scripts/validate-chapters.py")
        mod_vc = importlib.util.module_from_spec(spec_vc)
        spec_vc.loader.exec_module(mod_vc)

        spec_rr = importlib.util.spec_from_file_location("rr", ROOT / "scripts/render-report.py")
        mod_rr = importlib.util.module_from_spec(spec_rr)
        spec_rr.loader.exec_module(mod_rr)
        return mod_sem, mod_cf, mod_vc, mod_rr

    def test_nestjs_route_protection_analyzer(self):
        sem, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            ctrl = t / "src" / "items.controller.ts"
            ctrl.parent.mkdir(parents=True)
            ctrl.write_text(
                "@Controller('items')\n"
                "export class ItemsController {\n"
                "  @Post('create')\n"
                "  createItem(@Body() dto: any) { return true; }\n"
                "\n"
                "  @UseGuards(JwtAuthGuard)\n"
                "  @Put(':id')\n"
                "  updateItem() { return true; }\n"
                "\n"
                "  @Post('login')\n"
                "  login() { return true; }\n"
                "}\n"
            )
            findings = sem.analyze_authz_nestjs(t)
            self.assertEqual(1, len(findings))
            self.assertEqual("High", findings[0]["severity"])
            self.assertIn("createItem", findings[0]["evidence"][0]["snippet"])
            self.assertEqual("AUTHZ", findings[0]["domain"])

    def test_express_route_protection_analyzer(self):
        sem, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            router_file = t / "src" / "api.router.ts"
            router_file.parent.mkdir(parents=True)
            router_file.write_text(
                "import express from 'express';\n"
                "const router = express.Router();\n"
                "router.post('/users', createHandler);\n"
                "router.post('/login', authHandler);\n"
                "router.put('/users/:id', verifyToken, updateHandler);\n"
            )
            findings = sem.analyze_authz_express(t)
            self.assertEqual(1, len(findings))
            self.assertIn("/users", findings[0]["title"])
            self.assertEqual("AUTHZ", findings[0]["domain"])

    def test_django_views_authorization_analyzer(self):
        sem, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            views_file = t / "myapp" / "views.py"
            views_file.parent.mkdir(parents=True)
            views_file.write_text(
                "from django.http import HttpResponse\n"
                "def mutate_resource(request):\n"
                "    if request.method in ['POST', 'PUT']:\n"
                "        return HttpResponse('mutated')\n"
                "    return HttpResponse('ok')\n"
                "\n"
                "class UnprotectedAPIView(APIView):\n"
                "    def post(self, request):\n"
                "        return Response('created')\n"
            )
            findings = sem.analyze_authz_django(t)
            self.assertEqual(2, len(findings))
            self.assertTrue(all(f["domain"] == "AUTHZ" for f in findings))

    def test_sensitive_logging_and_token_hygiene(self):
        sem, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            log_file = t / "src" / "client.ts"
            log_file.parent.mkdir(parents=True)
            log_file.write_text(
                "import axios from 'axios';\n"
                "try {\n"
                "  await axios.get('/api');\n"
                "} catch (err) {\n"
                "  logger.error(err);\n"
                "}\n"
                "console.log('Got bearer token', token);\n"
                "if (token === expectedToken) { authenticate(); }\n"
                "const secret = process.env.JWT_SECRET || 'insecure-default-key';\n"
            )
            findings = sem.analyze_semantic_domains(t)
            domains = {f["domain"] for f in findings}
            self.assertIn("DATA", domains)
            self.assertIn("CRYPTO", domains)
            self.assertIn("AUTH", domains)

    def test_copilot_regression_edge_cases(self):
        sem, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)

            # 1. Symlink escape check
            (t / "external").mkdir()
            (t / "external" / "leak.ts").write_text("@Controller('leak')\nexport class LeakController { @Post() save() {} }")
            src_dir = t / "src"
            src_dir.mkdir()
            (src_dir / "symlink.ts").symlink_to(t / "external" / "leak.ts")
            # Should not follow symlinks outside/inside without regular file
            self.assertEqual([], sem.analyze_authz_nestjs(src_dir))

            # 2. NestJS decorator ordering: @Controller followed by @UseGuards protects class
            ctrl_file = src_dir / "users.controller.ts"
            ctrl_file.write_text(
                "@Controller('users')\n"
                "@UseGuards(JwtAuthGuard)\n"
                "export class UsersController {\n"
                "  @Post()\n"
                "  create() { return true; }\n"
                "}\n"
            )
            self.assertEqual([], sem.analyze_authz_nestjs(t))

            # 3. NestJS method decorator block scoping: guarded method does not protect next method
            items_ctrl = src_dir / "items.controller.ts"
            items_ctrl.write_text(
                "@Controller('items')\n"
                "export class ItemsController {\n"
                "  @UseGuards(AuthGuard)\n"
                "  @Post()\n"
                "  create() { return true; }\n"
                "  @Delete(':id')\n"
                "  remove() { return true; }\n"
                "}\n"
            )
            findings = sem.analyze_authz_nestjs(t)
            self.assertEqual(1, len(findings))
            self.assertIn("Delete", findings[0]["title"])

            # 4. Express: resource routes /authors and /publications are NOT exempted as auth
            route_f = src_dir / "resources.router.ts"
            route_f.write_text(
                "import express from 'express';\n"
                "const router = express.Router();\n"
                "router.post('/authors', saveAuthor);\n"
                "router.delete('/publications/:id', deletePub);\n"
            )
            exp_findings = sem.analyze_authz_express(t)
            self.assertEqual(2, len(exp_findings))

            # 5. Express: router.use(requireAuth) protects downstream routes
            guarded_router = src_dir / "guarded.router.ts"
            guarded_router.write_text(
                "import express from 'express';\n"
                "const router = express.Router();\n"
                "router.use(requireAuth);\n"
                "router.post('/items', createHandler);\n"
            )
            self.assertEqual(2, len(sem.analyze_authz_express(t))) # Still only 2 from resources.router.ts

            # 6. Django: request.method == 'POST' recognized; permission_classes = [] or [AllowAny] flagged
            py_views = t / "views.py"
            py_views.write_text(
                "from rest_framework.views import APIView\n"
                "from rest_framework.permissions import AllowAny, IsAuthenticated\n"
                "def func_post_equality(request):\n"
                "    if request.method == 'POST':\n"
                "        Item.objects.create()\n"
                "class EmptyPermView(APIView):\n"
                "    permission_classes = []\n"
                "    def post(self, request):\n"
                "        pass\n"
                "class AllowAnyPermView(APIView):\n"
                "    permission_classes = [AllowAny]\n"
                "    def post(self, request):\n"
                "        pass\n"
                "class ProtectedView(APIView):\n"
                "    permission_classes = [IsAuthenticated]\n"
                "    def post(self, request):\n"
                "        pass\n"
            )
            dj_findings = sem.analyze_authz_django(t)
            self.assertEqual(3, len(dj_findings))

            # 7. Sensitive logging: string literal labels not flagged, but raw error objects are
            log_test = src_dir / "logger_test.ts"
            log_test.write_text(
                "import axios from 'axios';\n"
                "logger.warn('Invalid token');\n"
                "console.info('JWT validation failed');\n"
                "await axios.get('/api');\n"
                "logger.error(err, err.message);\n"
            )
            data_findings = sem.analyze_sensitive_logging(t)
            self.assertEqual(1, len(data_findings))
            self.assertEqual("Raw HTTP client error object passed directly to logger", data_findings[0]["title"])

            # 8. Token crypto hygiene: Python os.environ.get fallback forms
            py_sec = t / "secrets.py"
            py_sec.write_text(
                "import os\n"
                "s1 = os.environ.get('SECRET_KEY', 'insecure-default')\n"
                "s2 = os.environ.get('TOKEN_SECRET') or 'fallback-secret'\n"
            )
            crypto_findings = sem.analyze_token_crypto_hygiene(t)
            self.assertEqual(2, len(crypto_findings))

    def test_full_compiler_and_chapter_validation_with_semantic_findings(self):
        _, cf, vc, rr = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "target"; root.mkdir()
            (root / "README.md").write_text("# Demo Project\nArchitecture info.\n")
            (root / "package.json").write_text('{"name": "demo", "engines": {"node": ">=20"}}')
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: push\njobs: {}\n")

            # NestJS unprotected route
            ctrl = root / "api" / "src" / "fom.controller.ts"
            ctrl.parent.mkdir(parents=True)
            ctrl.write_text(
                "@Controller('fom')\n"
                "export class FomController {\n"
                "  @Post('update')\n"
                "  updateRecord() { return true; }\n"
                "}\n"
            )
            # Sensitive logging
            log_f = root / "api" / "src" / "logger.ts"
            log_f.write_text(
                "import axios from 'axios';\n"
                "function logCall(err: any, token: string) {\n"
                "  logger.error(err);\n"
                "  console.log('Session accessToken: ', token);\n"
                "}\n"
            )
            ev = pathlib.Path(tmp) / "evidence"; ev.mkdir()

            compiler = cf.Compiler("bcgov/test-semantic", root, ev)
            data = compiler.run()

            # Verify semantic findings were ingested
            finding_ids = [f["id"] for f in data["findings"]]
            self.assertTrue(any(fid.startswith("AUTHZ") for fid in finding_ids))
            self.assertTrue(any(fid.startswith("DATA") for fid in finding_ids))

            # Verify authz chapter status is analyzed
            authz_ch = next(c for c in data["chapters"] if c["id"] == "authz")
            self.assertEqual("analyzed", authz_ch["status"])
            self.assertTrue(len(authz_ch["finding_ids"]) > 0)

            # Verify logging-data chapter status is analyzed
            data_ch = next(c for c in data["chapters"] if c["id"] == "logging-data")
            self.assertEqual("analyzed", data_ch["status"])
            self.assertTrue(len(data_ch["finding_ids"]) > 0)

            # Verify report renders cleanly
            md = rr.render(data)
            self.assertIn("## authz", md)
            self.assertIn("## logging-data", md)

            # Verify validate-chapters passes with zero errors
            errors = vc.validate(data, md, root, ev)
            self.assertEqual([], errors)


class ReachabilityAndAttackChainingTests(unittest.TestCase):
    def load_modules(self):
        spec_rc = importlib.util.spec_from_file_location("rc", ROOT / "scripts/analyze-reachability-and-chains.py")
        mod_rc = importlib.util.module_from_spec(spec_rc)
        spec_rc.loader.exec_module(mod_rc)

        spec_cf = importlib.util.spec_from_file_location("cf", ROOT / "scripts/compile-findings.py")
        mod_cf = importlib.util.module_from_spec(spec_cf)
        spec_cf.loader.exec_module(mod_cf)

        spec_vc = importlib.util.spec_from_file_location("vc", ROOT / "scripts/validate-chapters.py")
        mod_vc = importlib.util.module_from_spec(spec_vc)
        spec_vc.loader.exec_module(mod_vc)

        spec_rr = importlib.util.spec_from_file_location("rr", ROOT / "scripts/render-report.py")
        mod_rr = importlib.util.module_from_spec(spec_rr)
        spec_rr.loader.exec_module(mod_rr)

        spec_ds = importlib.util.spec_from_file_location("ds", ROOT / "scripts/render-dashboard-summary.py")
        mod_ds = importlib.util.module_from_spec(spec_ds)
        spec_ds.loader.exec_module(mod_ds)
        return mod_rc, mod_cf, mod_vc, mod_rr, mod_ds

    def test_import_extraction_js_ts_and_python(self):
        rc, _, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)

            # JS/TS files
            src = t / "src"
            src.mkdir()
            (src / "app.ts").write_text(
                "import { get } from 'lodash';\n"
                "import express from 'express';\n"
                "import { Controller } from '@nestjs/common';\n"
                "const axios = require('axios');\n"
                "import('dotenv/config');\n"
            )

            # Python file
            (src / "worker.py").write_text(
                "import yaml\n"
                "from pyjwt import decode\n"
                "from dateutil.parser import parse\n"
            )

            # Ignored paths (e.g. tests or node_modules)
            ignored = t / "tests"
            ignored.mkdir()
            (ignored / "app.test.ts").write_text("import supertest from 'supertest';\n")

            imported = rc.extract_imported_packages(t)
            # Check lodash, express, @nestjs/common, axios, dotenv
            self.assertIn("lodash", imported)
            self.assertIn("express", imported)
            self.assertIn("@nestjs/common", imported)
            self.assertNotIn("@nestjs", imported)
            self.assertIn("axios", imported)
            self.assertIn("dotenv", imported)

            # Check Python imports and aliases
            self.assertIn("yaml", imported)
            self.assertIn("pyyaml", imported)
            self.assertIn("pyjwt", imported)
            self.assertIn("dateutil", imported)
            self.assertIn("python-dateutil", imported)

            # supertest from ignored dir should NOT be in imported
            self.assertNotIn("supertest", imported)

    def test_reachability_vex_tagging(self):
        rc, _, _, _, _ = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            (t / "index.ts").write_text("import express from 'express';\n")

            findings = [
                {
                    "id": "DEP-001",
                    "domain": "dependencies",
                    "package": "express",
                    "title": "express 4.16.0 affected by CVE-2022-24999",
                    "severity": "High",
                },
                {
                    "id": "DEP-002",
                    "domain": "dependencies",
                    "package": "uncalled-transitive-pkg",
                    "title": "uncalled-transitive-pkg 1.0.0 affected by CVE-2023-1111",
                    "severity": "High",
                },
            ]

            assessed, summary = rc.assess_reachability(t, findings)
            self.assertEqual(2, summary["total_dependency_findings"])
            self.assertEqual(1, summary["reachable_findings"])
            self.assertEqual(1, summary["unreachable_findings"])
            self.assertEqual(["express"], summary["reachable_packages"])
            self.assertEqual(["uncalled-transitive-pkg"], summary["unreachable_packages"])

            # Reachable finding checks
            f1 = next(f for f in assessed if f["id"] == "DEP-001")
            self.assertEqual("reachable", f1["reachability"])
            self.assertEqual("affected", f1["vex_status"])
            self.assertIn("Directly imported", f1["vex_justification"])
            self.assertEqual("High", f1["severity"])

            # Unreachable finding checks
            f2 = next(f for f in assessed if f["id"] == "DEP-002")
            self.assertEqual("unreachable", f2["reachability"])
            self.assertEqual("not_affected", f2["vex_status"])
            self.assertIn("not_in_execute_path", f2["vex_justification"])
            self.assertEqual("Low", f2["effective_severity"])

    def test_correlate_attack_chains_scenarios(self):
        rc, _, _, _, _ = self.load_modules()

        findings = [
            # Scenario 1: DATA + AUTHZ
            {"id": "DATA-001", "domain": "logging-data", "title": "Sensitive token logged to console", "severity": "High"},
            {"id": "AUTHZ-001", "domain": "authz", "title": "Unprotected mutating endpoint @Post('admin')", "severity": "High"},
            # Scenario 2: AUTHN fallback + CRYPTO
            {"id": "AUTHN-001", "domain": "authn", "title": "Hardcoded JWT secret fallback in auth service", "severity": "High"},
            {"id": "CRYPTO-001", "domain": "cryptography", "title": "Insecure non-constant-time token verify", "severity": "Medium"},
            # Scenario 3: Reachable DEPS + SECRETS
            {"id": "DEP-001", "domain": "dependencies", "title": "lodash 4.17.15: Prototype pollution", "reachability": "reachable", "severity": "High"},
            {"id": "SEC-001", "domain": "secrets", "title": "Gitleaks API key in git history", "severity": "High"},
            # Scenario 4: CONFIG + AUTHN
            {"id": "CFG-001", "domain": "configuration", "title": "Permissive CORS origin wildcard *", "severity": "Medium"},
        ]

        chains = rc.correlate_attack_chains(findings)
        self.assertGreaterEqual(len(chains), 3)

        titles = [c["title"] for c in chains]
        self.assertTrue(any("Credential Disclosure" in t for t in titles))
        self.assertTrue(any("Hardcoded Secret Fallback" in t for t in titles))
        self.assertTrue(any("Reachable Component Flaw" in t for t in titles))
        self.assertTrue(any("Permissive Configuration" in t for t in titles))

        for chain in chains:
            self.assertIn("id", chain)
            self.assertIn("severity", chain)
            self.assertIn("narrative", chain)
            self.assertIn("remediation", chain)
            self.assertIn("mermaid", chain)
            self.assertTrue(chain["mermaid"].startswith("graph LR"))

    def test_end_to_end_compiler_and_report_integration(self):
        rc, cf, vc, rr, ds = self.load_modules()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            target = tmp_path / "target"
            target.mkdir()
            evidence = tmp_path / "evidence"
            evidence.mkdir()

            # Create basic target structure
            (target / "README.md").write_text("# Demo Project\nArchitecture info.\n")
            (target / "package.json").write_text('{"name": "demo", "engines": {"node": ">=20"}}')
            (target / "package-lock.json").write_text('{\n  "name": "demo",\n  "packages": {\n    "node_modules/lodash": {\n      "version": "4.17.15"\n    }\n  }\n}\n')
            (target / ".github" / "workflows").mkdir(parents=True)
            (target / ".github" / "workflows" / "ci.yml").write_text("name: CI\non: push\njobs: {}\n")

            # Source code importing lodash
            src = target / "src"
            src.mkdir()
            (src / "app.ts").write_text(
                "import { merge } from 'lodash';\n"
                "console.log('User bearer token:', token);\n"
            )

            # Evidence files
            (evidence / "osv-scanner.json").write_text(json.dumps({
                "results": [
                    {
                        "source": {"path": "package-lock.json", "type": "lockfile"},
                        "packages": [
                            {
                                "package": {"name": "lodash", "version": "4.17.15"},
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-p6mc-m468-83gw",
                                        "summary": "Prototype Pollution in lodash",
                                        "database_specific": {"severity": "High"},
                                    }
                                ]
                            },
                            {
                                "package": {"name": "uncalled-dep", "version": "1.0.0"},
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-uncalled-1111",
                                        "summary": "Flaw in uncalled-dep",
                                        "database_specific": {"severity": "High"},
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }))
            (evidence / "semgrep.json").write_text(json.dumps({"results": [], "paths": {"scanned": ["src/app.ts"]}}))
            (evidence / "gitleaks.json").write_text(json.dumps([]))

            compiler = cf.Compiler("bcgov/test-reachability", target, evidence)
            data = compiler.run()

            # Verify VEX summary
            self.assertIn("vex_summary", data)
            vex = data["vex_summary"]
            self.assertEqual(2, vex["total_dependency_findings"])
            self.assertEqual(1, vex["reachable_findings"])
            self.assertEqual(1, vex["unreachable_findings"])
            self.assertEqual(["lodash"], vex["reachable_packages"])

            # Verify attack chains
            self.assertIn("attack_chains", data)
            chains = data["attack_chains"]
            self.assertTrue(len(chains) >= 1)

            # Verify report generation
            md = rr.render(data)
            self.assertIn("## Attack chains (exploit correlation)", md)
            self.assertIn("### VEX Reachability Analysis", md)
            self.assertIn("graph LR", md)
            self.assertIn("VEX status: `affected`", md)
            self.assertIn("VEX status: `not_affected`", md)

            # Validate report against chapter substance gate
            errors = vc.validate(data, md, target, evidence)
            self.assertEqual([], errors)

            # Test dashboard summary rendering
            rep_dir = tmp_path / "reports"
            target_rep = rep_dir / "target"
            target_rep.mkdir(parents=True)
            (target_rep / "findings.json").write_text(json.dumps(data))
            (target_rep / "score.json").write_text(json.dumps({"score": 85, "counts": {"Critical": 0, "High": 2, "Medium": 0, "Low": 0}}))
            dash_md = ds.render_dashboard(rep_dir)
            self.assertIn("Exploit Attack Chains", dash_md)
            self.assertIn("VEX Reachability", dash_md)


class NoiseFiltersAndScoringTests(unittest.TestCase):
    def test_is_allowlisted_action_tag(self):
        spec = importlib.util.spec_from_file_location("compile_findings", ROOT / "scripts/compile-findings.py")
        cf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cf)

        # Official allowed orgs should be ignored
        title = "GitHub Actions step uses a mutable tag or branch reference."
        self.assertTrue(cf.is_allowlisted_action_tag("uses: actions/checkout@v4", title))
        self.assertTrue(cf.is_allowlisted_action_tag("- uses: actions/setup-node@v4", title))
        self.assertTrue(cf.is_allowlisted_action_tag("uses: github/codeql-action/upload-sarif@v3", title))
        self.assertTrue(cf.is_allowlisted_action_tag("uses: docker/setup-buildx-action@v3", title))
        self.assertTrue(cf.is_allowlisted_action_tag("uses: bcgov/action-builder@v1.0.0", title))

        # Untrusted third-party actions with floating tags should NOT be ignored
        self.assertFalse(cf.is_allowlisted_action_tag("uses: random-user/action@main", title))
        self.assertFalse(cf.is_allowlisted_action_tag("uses: evil-corp/build@v1", title))
        self.assertFalse(cf.is_allowlisted_action_tag("uses: untrusted-actions/build@main", title))
        self.assertFalse(cf.is_allowlisted_action_tag("uses: my-docker/action@v1", title))

        # Different title should not match
        self.assertFalse(cf.is_allowlisted_action_tag("uses: actions/checkout@v4", "SQL injection in query"))

    def test_is_internal_secrets_inherit(self):
        spec = importlib.util.spec_from_file_location("compile_findings", ROOT / "scripts/compile-findings.py")
        cf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cf)

        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            wf_dir = t / ".github" / "workflows"
            wf_dir.mkdir(parents=True)
            wf = wf_dir / "caller.yml"
            wf.write_text(
                "name: MultiJob\n"
                "jobs:\n"
                "  internal-job:\n"
                "    uses: ./.github/workflows/reusable.yml\n"
                "    secrets: inherit\n"
                "  external-job:\n"
                "    uses: evil-org/repo/.github/workflows/malicious.yml@main\n"
                "    secrets: inherit\n"
            )

            title = "This workflow uses `secrets: inherit` to pass all of the calling workflow's secrets"
            # Line 5 is secrets: inherit in internal-job -> True
            self.assertTrue(cf.is_internal_secrets_inherit(t, ".github/workflows/caller.yml", 5, title))
            # Line 8 is secrets: inherit in external-job -> False (must not bleed from adjacent job)
            self.assertFalse(cf.is_internal_secrets_inherit(t, ".github/workflows/caller.yml", 8, title))

    def test_is_ignorable_plaintext_http(self):
        spec = importlib.util.spec_from_file_location("compile_findings", ROOT / "scripts/compile-findings.py")
        cf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cf)

        title = "This link points to a plaintext HTTP URL. Prefer an encrypted HTTPS URL if possible."
        # Ignorable documentation
        self.assertTrue(cf.is_ignorable_plaintext_http("README.md", "http://example.com", title))

        # Ignorable footer link with valid *.gov.bc.ca host
        self.assertTrue(cf.is_ignorable_plaintext_http("footer.component.html", '<a href="http://www2.gov.bc.ca/copyright">Copyright</a>', title))

        # Subdomain spoofing attacker URL in footer must NOT be ignored
        self.assertFalse(cf.is_ignorable_plaintext_http("footer.component.html", '<a href="http://gov.bc.ca.attacker.test/phish">Copyright</a>', title))

        # Schema declarations with trusted schema hosts
        self.assertTrue(cf.is_ignorable_plaintext_http("schema.json", '{"$schema": "http://json-schema.org/draft-07/schema#"}', title))
        self.assertTrue(cf.is_ignorable_plaintext_http("icon.svg", '<svg xmlns="http://www.w3.org/2000/svg">', title))

        # Config / appsettings JSON with runtime API endpoints must NOT be ignored
        self.assertFalse(cf.is_ignorable_plaintext_http("appsettings.json", '{"apiUrl": "http://api.internal.service/data"}', title))

        # Actual production API endpoint in code must NOT be ignored
        self.assertFalse(cf.is_ignorable_plaintext_http("src/api.ts", "const url = 'http://api.gov.bc.ca/private';", title))
        self.assertFalse(cf.is_ignorable_plaintext_http("src/api.ts", "const url = 'http://api.internal.service:8080/data';", title))

    def test_sensitive_logging_refinements(self):
        spec = importlib.util.spec_from_file_location("sem", ROOT / "scripts/analyze-semantic-domains.py")
        sem = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sem)

        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            src = t / "src"
            src.mkdir()

            # Scalar properties (message, code, status) should NOT be flagged
            scalar_file = src / "scalar_log.ts"
            scalar_file.write_text(
                "import axios from 'axios';\n"
                "try {\n"
                "  await axios.get('/api');\n"
                "} catch (axiosError) {\n"
                "  logger.error(axiosError.message);\n"
                "  console.info(err.response.status);\n"
                "  logger.warn(err.code);\n"
                "}\n"
            )
            f_scalar = sem.analyze_sensitive_logging(t)
            self.assertEqual(0, len(f_scalar))

            # Raw error object or err.config must be flagged
            raw_file = src / "raw_log.ts"
            raw_file.write_text(
                "import axios from 'axios';\n"
                "try {\n"
                "  await axios.get('/api');\n"
                "} catch (err) {\n"
                "  logger.error(err);\n"
                "  logger.error('Config:', err.config);\n"
                "}\n"
            )
            f_raw = sem.analyze_sensitive_logging(t)
            self.assertEqual(2, len(f_raw))

            # Fetch with literal argument followed by catch logging err
            fetch_file = src / "fetch_log.ts"
            fetch_file.write_text(
                "fetch('/api/users')\n"
                "  .then(res => res.json())\n"
                "  .catch(err => {\n"
                "    console.error(err);\n"
                "  });\n"
            )
            f_fetch = sem.analyze_sensitive_logging(t)
            # raw_log.ts (2) + fetch_log.ts (1) = 3
            self.assertEqual(3, len(f_fetch))

    def test_compute_risk_score(self):
        spec = importlib.util.spec_from_file_location("score", ROOT / "scripts/score.py")
        score_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(score_mod)

        # 0 findings = 0 score
        self.assertEqual(0, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 0, "Low": 0}))

        # 1 Critical = 25
        self.assertEqual(25, score_mod.compute_risk_score({"Critical": 1, "High": 0, "Medium": 0, "Low": 0}))

        # 4 Critical = 100
        self.assertEqual(100, score_mod.compute_risk_score({"Critical": 4, "High": 0, "Medium": 0, "Low": 0}))

        # High cap is 40 (5 Highs = 40, 10 Highs = 40)
        self.assertEqual(8, score_mod.compute_risk_score({"Critical": 0, "High": 1, "Medium": 0, "Low": 0}))
        self.assertEqual(40, score_mod.compute_risk_score({"Critical": 0, "High": 5, "Medium": 0, "Low": 0}))
        self.assertEqual(40, score_mod.compute_risk_score({"Critical": 0, "High": 10, "Medium": 0, "Low": 0}))

        # Medium diminishing returns (cap 15)
        self.assertEqual(3, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 1, "Low": 0}))
        # 10 mediums: round(4 * ln(11)) = round(4 * 2.398) = round(9.59) = 10
        self.assertEqual(10, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 10, "Low": 0}))
        # 100 mediums: capped at 15
        self.assertEqual(15, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 100, "Low": 0}))

        # Low cap is 5
        self.assertEqual(1, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 0, "Low": 5}))
        self.assertEqual(5, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 0, "Low": 25}))
        self.assertEqual(5, score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 0, "Low": 100}))

        # Typical well-maintained repo (e.g. nr-fom post-filtering): 0 C, 0 H, 3 M, 5 L -> 0 + 0 + 6 + 1 = 7
        nr_fom_score = score_mod.compute_risk_score({"Critical": 0, "High": 0, "Medium": 3, "Low": 5})
        self.assertTrue(0 <= nr_fom_score <= 15)

    def test_backtick_template_logging_and_test_exclusion(self):
        spec = importlib.util.spec_from_file_location("sem", ROOT / "scripts/analyze-semantic-domains.py")
        sem = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sem)

        with tempfile.TemporaryDirectory() as tmp:
            t = pathlib.Path(tmp)
            src = t / "src"
            src.mkdir()

            # Static prose inside backtick template literals must not trigger DATA-001,
            # while real interpolated credentials inside template literals still flag.
            svc = src / "CognitoAuthService.ts"
            svc.write_text(
                "console.error(`Token refresh failed: ${response.status} - ${errorText}`);\n"
                "console.info(`Authorization token: ${accessToken}`);\n"
            )
            # Unit tests and spec/fixture files must be skipped by semantic analyzers
            tests_dir = t / "backend" / "__tests__"
            tests_dir.mkdir(parents=True)
            (tests_dir / "health.test.js").write_text("console.error(accessToken);\n")
            (src / "deploy-template.spec.ts").write_text("console.error(refreshToken);\n")

            findings = sem.analyze_sensitive_logging(t)
            self.assertEqual(1, len(findings))
            self.assertEqual("src/CognitoAuthService.ts", findings[0]["evidence"][0]["file"])
            self.assertEqual(2, findings[0]["evidence"][0]["line"])

    def test_semgrep_test_and_tooling_subprocess_filters(self):
        spec = importlib.util.spec_from_file_location("compile_findings", ROOT / "scripts/compile-findings.py")
        cf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cf)

        self.assertTrue(cf.is_test_or_spec_path("backend/__tests__/health.test.js"))
        self.assertTrue(cf.is_test_or_spec_path("api/src/app/modules/deploy-template.spec.ts"))
        self.assertTrue(cf.is_test_or_spec_path("fixtures/mock-auth.ts"))
        self.assertFalse(cf.is_test_or_spec_path("src/api.ts"))
        self.assertFalse(cf.is_test_or_spec_path("src/logger_test.ts"))

        self.assertTrue(
            cf.is_tooling_subprocess_finding(
                "scripts/generate-security-report.js",
                "javascript.lang.security.detect-child-process.detect-child-process",
                "Detected calls to child_process",
            )
        )
        self.assertFalse(
            cf.is_tooling_subprocess_finding(
                "src/api.js",
                "javascript.lang.security.detect-child-process.detect-child-process",
                "Detected calls to child_process",
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "repo"
            ev = pathlib.Path(tmp) / "evidence"
            (root / "backend" / "__tests__").mkdir(parents=True)
            (root / "scripts").mkdir(parents=True)
            (root / "src").mkdir(parents=True)
            ev.mkdir(parents=True)

            (root / "backend" / "__tests__" / "health.test.js").write_text("app.use(cors());\n")
            (root / "scripts" / "generate-security-report.js").write_text("execSync(cmd);\n")
            (root / "src" / "api.js").write_text("execSync(userInput);\n")

            semgrep_payload = {
                "version": "1.0.0",
                "paths": {"scanned": ["backend/__tests__/health.test.js", "scripts/generate-security-report.js", "src/api.js"]},
                "results": [
                    {
                        "check_id": "javascript.express.security.audit.express-check-csurf-middleware-usage",
                        "path": "backend/__tests__/health.test.js",
                        "start": {"line": 1},
                        "extra": {"severity": "WARNING", "message": "Missing CSRF middleware", "lines": "app.use(cors());"},
                    },
                    {
                        "check_id": "javascript.lang.security.detect-child-process.detect-child-process",
                        "path": "scripts/generate-security-report.js",
                        "start": {"line": 1},
                        "extra": {"severity": "ERROR", "message": "Detected calls to child_process", "lines": "execSync(cmd);"},
                    },
                    {
                        "check_id": "javascript.lang.security.detect-child-process.detect-child-process",
                        "path": "src/api.js",
                        "start": {"line": 1},
                        "extra": {"severity": "ERROR", "message": "Detected calls to child_process", "lines": "execSync(userInput);"},
                    },
                ],
            }
            (ev / "semgrep.json").write_text(json.dumps(semgrep_payload))
            (ev / "gitleaks.json").write_text(
                json.dumps(
                    [
                        {
                            "RuleID": "generic-api-key",
                            "Description": "Generic API Key",
                            "File": "backend/__tests__/health.test.js",
                            "StartLine": 1,
                            "Match": "REDACTED",
                        }
                    ]
                )
            )

            comp = cf.Compiler("org/repo", root, ev)
            comp.ingest_semgrep()
            comp.ingest_gitleaks()

            semgrep_files = [f["evidence"][0]["file"] for f in comp.findings if f["source"] == "semgrep"]
            gitleaks_files = [f["evidence"][0]["file"] for f in comp.findings if f["source"] == "gitleaks"]
            self.assertEqual(["src/api.js"], semgrep_files)
            self.assertEqual(["backend/__tests__/health.test.js"], gitleaks_files)


if __name__ == "__main__":
    unittest.main()
