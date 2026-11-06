#!/usr/bin/env python3
"""Fail closed on unsupported chapter coverage claims before report publication.

Raises the bar so a shallow outline (#95-shaped: note + IDs only, missing
impact/recommendation, scanner chapters skipped when evidence exists) fails.
This checks traceability and minimum substance, not EY narrative quality.
"""
import argparse
import json
import pathlib
import re
import sys

from score import valid, W

CHAPTERS = (
    "architecture", "cicd", "zero-trust", "authn", "authz", "injection",
    "configuration", "cryptography", "secrets", "logging-data", "code-scanning",
    "secret-scanning", "dependabot", "dependencies", "containers-iac", "testing", "stack",
)

# Chapters whose evidence comes primarily from a named local scanner.
SCANNER_CHAPTERS = {
    "injection": "semgrep",
    "code-scanning": "semgrep",
    "secrets": "gitleaks",
    "secret-scanning": "gitleaks",
    "dependabot": ("osv-scanner", "trivy"),
    "dependencies": ("osv-scanner", "trivy"),
    "containers-iac": "trivy",
}


def normalize(text):
    return " ".join(text.split())


def cited(entry, root):
    return valid(entry, root) and type(entry.get("line")) is int


def evidence_ran(evidence_dir: pathlib.Path | None, names) -> bool:
    """True when evidence shows the scanner produced a usable artifact (ran)."""
    if evidence_dir is None or not evidence_dir.is_dir():
        return False
    if isinstance(names, str):
        names = (names,)
    for name in names:
        path = evidence_dir / f"{name}.json"
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if name == "semgrep":
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                scanned = (data.get("paths") or {}).get("scanned") or []
                if scanned:
                    return True
        elif name == "gitleaks":
            if isinstance(data, list):
                return True
            if isinstance(data, dict) and data == {}:
                # ensure() placeholder — check NOTES for install failure
                notes = evidence_dir / "NOTES.txt"
                text = notes.read_text(errors="replace") if notes.is_file() else ""
                if "gitleaks not installed" in text or "gitleaks failed" in text:
                    continue
                return True
        elif name in ("osv-scanner", "trivy"):
            if isinstance(data, dict) and data and data != {}:
                return True
        elif isinstance(data, list):
            return True
    return False


def validate(data, markdown, root, evidence_dir=None):
    errors = []
    chapters = data.get("chapters")
    if not isinstance(chapters, list) or any(not isinstance(c, dict) for c in chapters):
        return ["chapters must be a list of chapter objects"]
    ids = [c.get("id") for c in chapters]
    if len(ids) != len(CHAPTERS) or set(x for x in ids if isinstance(x, str)) != set(CHAPTERS):
        errors.append("chapters must contain each canonical ID exactly once: " + ", ".join(CHAPTERS))

    references = {}
    findings = data.get("findings", [])
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        findings = []
    for entry in findings:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            continue
        # Raised bar: every open finding needs impact + recommendation.
        for field in ("impact", "recommendation"):
            val = entry.get(field)
            if not isinstance(val, str) or len(val.split()) < 3:
                errors.append(f"{entry.get('id')}: finding requires non-trivial {field}")
        evs = entry.get("evidence", [])
        severity_ok = entry.get("severity") in W
        if isinstance(evs, list) and evs and all(cited(e, root) for e in evs) and severity_ok:
            references[entry["id"]] = entry

    for collection in ("fixed",):
        entries = data.get(collection, [])
        if not isinstance(entries, list):
            errors.append(f"{collection} must be an array")
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            evs = [entry] if "file" in entry else entry.get("evidence", [])
            if isinstance(evs, list) and evs and all(cited(e, root) for e in evs):
                references[entry["id"]] = entry

    headings = list(re.finditer(r"^## (.+?)\s*$", markdown, re.M))
    sections = {}
    for i, heading in enumerate(headings):
        name = heading.group(1)
        body = markdown[heading.end():headings[i + 1].start() if i + 1 < len(headings) else len(markdown)]
        sections.setdefault(name, []).append(body)

    for chapter in chapters:
        name = chapter.get("id")
        if name not in CHAPTERS:
            continue
        status = chapter.get("status")
        note = chapter.get("note")
        findings_ids = chapter.get("finding_ids")
        evidence = chapter.get("evidence")
        if status not in ("analyzed", "not_assessed"):
            errors.append(f"{name}: status must be analyzed or not_assessed")
        if (not isinstance(note, str) or len(note.split()) < 6
                or re.search(r"limited review;? scanners (clean|quiet)|^(?:not assessed|n/a|unknown|none)[. ]*$", note, re.I)):
            errors.append(f"{name}: provide a specific conclusion or limitation (at least six words), not a placeholder")
        if (not isinstance(findings_ids, list) or any(not isinstance(f, str) for f in findings_ids)
                or not isinstance(evidence, list)):
            errors.append(f"{name}: finding_ids and evidence must be arrays")
            continue

        # Scanner chapters cannot be skipped when evidence exists.
        if name in SCANNER_CHAPTERS and status == "not_assessed":
            if evidence_ran(evidence_dir, SCANNER_CHAPTERS[name]):
                errors.append(
                    f"{name}: scanner evidence exists but chapter is not_assessed; "
                    "mark analyzed (or record a real scanner failure reason without skipping usable evidence)"
                )

        if status == "analyzed":
            if not findings_ids and not evidence:
                errors.append(f"{name}: analyzed requires cited findings or source file:line evidence")
            for finding in findings_ids:
                if finding not in references:
                    errors.append(f"{name}: {finding} is not a cite-valid finding/fixed entry")
            for ev in evidence:
                if not cited(ev, root):
                    errors.append(f"{name}: invalid source file:line evidence {ev!r}")
        elif status == "not_assessed" and (findings_ids or evidence):
            errors.append(f"{name}: not_assessed must leave finding_ids and evidence empty")

        bodies = sections.get(name, [])
        if len(bodies) != 1:
            errors.append(f"{name}: Markdown needs exactly one '## {name}' section")
            continue
        body = bodies[0]
        statuses = re.findall(r"^Status: (.+?)\s*$", body, re.M)
        if statuses != [status]:
            errors.append(f"{name}: Markdown status does not match JSON")
        if isinstance(note, str) and normalize(note) not in normalize(body):
            errors.append(f"{name}: Markdown must include the JSON conclusion/limitation")
        for finding in findings_ids:
            if not re.search(r"(?<![\w-])" + re.escape(finding) + r"(?![\w-])", body):
                errors.append(f"{name}: Markdown missing finding {finding}")
        for ev in evidence:
            citation = f"{ev['file']}:{ev['line']}" if cited(ev, root) else None
            if citation and not re.search(r"(?<![\w:./\\-])" + re.escape(citation) + r"(?![\w:./\\-])", body):
                errors.append(f"{name}: Markdown missing source citation {ev['file']}:{ev['line']}")

        # Raised bar: a chapter cannot be only a note plus IDs.
        if status == "analyzed":
            stripped = body
            stripped = re.sub(r"^Status:.*$", "", stripped, flags=re.M)
            if isinstance(note, str):
                stripped = stripped.replace(note, " ")
            for finding in findings_ids:
                stripped = re.sub(r"(?<![\w-])" + re.escape(finding) + r"(?![\w-])", " ", stripped)
            for ev in evidence:
                if cited(ev, root):
                    stripped = stripped.replace(f"{ev['file']}:{ev['line']}", " ")
            # Remove bullets/whitespace; require leftover substance (titles, impact, tool counts, etc.)
            leftover = re.sub(r"[\W_]+", " ", stripped).strip()
            leftover_words = [w for w in leftover.split() if len(w) > 2]
            if len(leftover_words) < 8:
                errors.append(
                    f"{name}: chapter markdown is only a note plus IDs/cites; "
                    "include tool/version/counts or per-finding impact substance"
                )
            # Scanner analyzed chapters should mention a tool-ish token or result count.
            if name in SCANNER_CHAPTERS:
                if not re.search(r"(semgrep|gitleaks|osv|trivy|version|\d+\s+result)", note + "\n" + body, re.I):
                    errors.append(
                        f"{name}: analyzed scanner chapter note/body must name the tool and result count"
                    )

        row = rf"^\|\s*{re.escape(name)}\s*\|\s*{re.escape(str(status))}\s*\|\s*{len(findings_ids)}\s*\|\s*$"
        rows = re.findall(rf"^\|\s*{re.escape(name)}\s*\|.*$", markdown, re.M)
        if len(rows) != 1 or not re.fullmatch(row, rows[0]):
            errors.append(f"{name}: scope table must match JSON status and finding count")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings")
    parser.add_argument("report")
    parser.add_argument("--repo-dir", default="target")
    parser.add_argument("--evidence-dir", default="",
                        help="Optional evidence/ dir so scanner chapters cannot be skipped when artifacts exist")
    args = parser.parse_args()
    try:
        data = json.loads(pathlib.Path(args.findings).read_text())
        if not isinstance(data, dict):
            raise ValueError("findings must be a JSON object")
        evidence_dir = pathlib.Path(args.evidence_dir) if args.evidence_dir else None
        errors = validate(
            data,
            pathlib.Path(args.report).read_text(),
            pathlib.Path(args.repo_dir),
            evidence_dir,
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors = [str(exc)]
    for error in errors:
        print(f"::error::Chapter substance gate: {error}", file=sys.stderr)
    if errors:
        return 1
    print(f"Chapter substance gate passed: {len(CHAPTERS)} chapters traceable or explicitly not assessed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
