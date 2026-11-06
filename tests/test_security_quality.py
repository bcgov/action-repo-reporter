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
    for c in data["chapters"]:
        text += f"\n## {c['id']}\nStatus: {c['status']}\n{c['note']}\n"
        text += " ".join(c["finding_ids"]) + "\n"
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
                entry = {"id": "AUTH-001", "evidence": [{"file": "auth.ts", "line": 1}]}
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
        self.out = self.root / "evidence"
        self.out.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + ":/usr/bin:/bin")

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
            python = root / "python3.12"
            python.write_text("#!/bin/sh\necho 'venv creation failed: ensurepip unavailable' >&2\nexit 7\n")
            python.chmod(0o755)
            result = subprocess.run(["bash", str(ROOT / "scripts/install-semgrep.sh")],
                                    env=dict(os.environ, PATH=tmp + ":/usr/bin:/bin", RUNNER_TEMP=tmp,
                                             GITHUB_PATH=str(root / "path")), text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Semgrep install/runtime preflight failed", result.stderr)
            self.assertIn("ensurepip unavailable", result.stderr)
            self.assertIn("python3.12 -m venv", result.stderr)


if __name__ == "__main__":
    unittest.main()
