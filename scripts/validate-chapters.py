#!/usr/bin/env python3
"""Fail closed on unsupported chapter coverage claims before report publication.

This checks traceability, not the correctness/completeness of security analysis.
The canonical IDs name only the domains already required by the assessment prompt.
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


def normalize(text):
    return " ".join(text.split())


def cited(entry, root):
    return valid(entry, root) and type(entry.get("line")) is int


def validate(data, markdown, root):
    errors = []
    chapters = data.get("chapters")
    if not isinstance(chapters, list) or any(not isinstance(c, dict) for c in chapters):
        return ["chapters must be a list of chapter objects"]
    ids = [c.get("id") for c in chapters]
    if len(ids) != len(CHAPTERS) or set(x for x in ids if isinstance(x, str)) != set(CHAPTERS):
        errors.append("chapters must contain each canonical ID exactly once: " + ", ".join(CHAPTERS))

    # Only findings that pass cite-or-ask may support an analyzed claim.
    references = {}
    for collection in ("findings", "fixed"):
        entries = data.get(collection, [])
        if not isinstance(entries, list):
            errors.append(f"{collection} must be an array")
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
                continue
            # Open findings must satisfy the scorer's evidence-array contract.
            # Only confirmed-fixed entries may use a top-level file/line cite.
            evs = ([entry] if "file" in entry else entry.get("evidence", [])) if collection == "fixed" else entry.get("evidence", [])
            severity_ok = collection == "fixed" or entry.get("severity") in W
            if isinstance(evs, list) and evs and all(cited(e, root) for e in evs) and severity_ok:
                references[entry["id"]] = entry

    headings = list(re.finditer(r"^## (.+?)\s*$", markdown, re.M))
    sections = {}
    for i, heading in enumerate(headings):
        name = heading.group(1)
        body = markdown[heading.end():headings[i+1].start() if i+1 < len(headings) else len(markdown)]
        sections.setdefault(name, []).append(body)

    for chapter in chapters:
        name = chapter.get("id")
        if name not in CHAPTERS:
            continue
        status = chapter.get("status")
        note = chapter.get("note")
        findings = chapter.get("finding_ids")
        evidence = chapter.get("evidence")
        if status not in ("analyzed", "not_assessed"):
            errors.append(f"{name}: status must be analyzed or not_assessed")
        if (not isinstance(note, str) or len(note.split()) < 6
                or re.search(r"limited review;? scanners (clean|quiet)|^(?:not assessed|n/a|unknown|none)[. ]*$", note, re.I)):
            errors.append(f"{name}: provide a specific conclusion or limitation (at least six words), not a placeholder")
        if (not isinstance(findings, list) or any(not isinstance(f, str) for f in findings)
                or not isinstance(evidence, list)):
            errors.append(f"{name}: finding_ids and evidence must be arrays")
            continue
        if status == "analyzed":
            if not findings and not evidence:
                errors.append(f"{name}: analyzed requires cited findings or source file:line evidence")
            for finding in findings:
                if finding not in references:
                    errors.append(f"{name}: {finding} is not a cite-valid finding/fixed entry")
            for ev in evidence:
                if not cited(ev, root):
                    errors.append(f"{name}: invalid source file:line evidence {ev!r}")
        elif status == "not_assessed" and (findings or evidence):
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
        for finding in findings:
            if not re.search(r"(?<![\w-])" + re.escape(finding) + r"(?![\w-])", body):
                errors.append(f"{name}: Markdown missing finding {finding}")
        for ev in evidence:
            citation = f"{ev['file']}:{ev['line']}" if cited(ev, root) else None
            if citation and not re.search(r"(?<![\w:./\\-])" + re.escape(citation) + r"(?![\w:./\\-])", body):
                errors.append(f"{name}: Markdown missing source citation {ev['file']}:{ev['line']}")
        row = rf"^\|\s*{re.escape(name)}\s*\|\s*{re.escape(str(status))}\s*\|\s*{len(findings)}\s*\|\s*$"
        rows = re.findall(rf"^\|\s*{re.escape(name)}\s*\|.*$", markdown, re.M)
        if len(rows) != 1 or not re.fullmatch(row, rows[0]):
            errors.append(f"{name}: scope table must match JSON status and finding count")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("findings")
    parser.add_argument("report")
    parser.add_argument("--repo-dir", default="target")
    args = parser.parse_args()
    try:
        data = json.loads(pathlib.Path(args.findings).read_text())
        if not isinstance(data, dict):
            raise ValueError("findings must be a JSON object")
        errors = validate(data, pathlib.Path(args.report).read_text(), pathlib.Path(args.repo_dir))
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
