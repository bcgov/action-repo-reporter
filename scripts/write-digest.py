#!/usr/bin/env python3
"""Optional cover-letter digest for a security report.

Reads already-valid findings.json (+ optional markdown). Never invents findings
or changes severities/chapters. Every claim must cite a finding ID or chapter
already in the JSON. Mentions of CVE/GHSA/CWE IDs that are not present in the
JSON cause the digest to be dropped. Hard word cap (~300 words).

The digest always links to the script-generated report path. If the optional LLM
path is unavailable, over budget, or fails the cite check, exit 0 without a
digest — the compiled report still ships.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

MAX_WORDS = 300
FINDING_ID_RE = re.compile(r"\b([A-Z]{2,8}-\d{3})\b")
CVE_RE = re.compile(r"\b(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CWE-\d+)\b", re.I)


def allowed_refs(data: dict) -> tuple[set[str], set[str], set[str]]:
    finding_ids = {f["id"] for f in data.get("findings") or [] if isinstance(f, dict) and f.get("id")}
    finding_ids |= {f["id"] for f in data.get("fixed") or [] if isinstance(f, dict) and f.get("id")}
    chapters = {c["id"] for c in data.get("chapters") or [] if isinstance(c, dict) and c.get("id")}
    advisories: set[str] = set()
    blob_parts = []
    for f in (data.get("findings") or []) + (data.get("fixed") or []):
        if not isinstance(f, dict):
            continue
        for key in ("title", "impact", "recommendation", "note", "snippet"):
            if f.get(key):
                blob_parts.append(str(f[key]))
        for c in f.get("cwe") or []:
            advisories.add(str(c).upper())
    blob = "\n".join(blob_parts)
    for m in CVE_RE.finditer(blob):
        advisories.add(m.group(1).upper())
    return finding_ids, chapters, advisories


def cite_check(text: str, finding_ids: set[str], chapters: set[str], advisories: set[str]) -> list[str]:
    errors = []
    for m in FINDING_ID_RE.finditer(text):
        if m.group(1) not in finding_ids:
            errors.append(f"unknown finding id {m.group(1)}")
    # chapter mentions: look for `##`-style or bare canonical ids as words after "chapter"
    for cid in re.findall(r"\b(architecture|cicd|zero-trust|authn|authz|injection|configuration|"
                          r"cryptography|secrets|logging-data|code-scanning|secret-scanning|"
                          r"dependabot|dependencies|containers-iac|testing|stack)\b", text):
        if cid not in chapters:
            errors.append(f"unknown chapter {cid}")
    for m in CVE_RE.finditer(text):
        token = m.group(1).upper()
        if token not in advisories and token.replace("CWE-", "CWE-") not in advisories:
            # allow CWE-N if CWE-N in advisories set
            if token not in {a.upper() for a in advisories}:
                errors.append(f"advisory/CWE not in findings JSON: {m.group(1)}")
    return errors


def deterministic_digest(data: dict, report_link: str) -> str:
    repo = data.get("repository") or "unknown"
    findings = data.get("findings") or []
    fixed = data.get("fixed") or []
    gaps = data.get("coverage_gaps") or []
    chapters = data.get("chapters") or []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        if f.get("severity") in counts:
            counts[f["severity"]] += 1
    analyzed = sum(1 for c in chapters if c.get("status") == "analyzed")
    not_assessed = sum(1 for c in chapters if c.get("status") == "not_assessed")
    top = findings[:5]
    lines = [
        f"# Cover letter: {repo}",
        "",
        f"This digest summarizes the scripted security assessment for `{repo}`. "
        f"The source of truth is the compiled report at [{report_link}]({report_link}).",
        "",
        f"Open findings: {len(findings)} "
        f"(Critical {counts['Critical']}, High {counts['High']}, "
        f"Medium {counts['Medium']}, Low {counts['Low']}); "
        f"confirmed-fixed: {len(fixed)}. "
        f"Chapters analyzed: {analyzed}; not_assessed: {not_assessed}.",
        "",
    ]
    if top:
        lines.append("Highest-priority items (by severity order in findings.json):")
        for f in top:
            lines.append(f"- {f['id']} ({f.get('severity')}): {f.get('title')}")
        lines.append("")
    if fixed:
        lines.append("Confirmed-fixed seeds/checks: " + ", ".join(e["id"] for e in fixed if e.get("id")) + ".")
        lines.append("")
    if gaps:
        lines.append("Named coverage gaps:")
        for g in gaps[:4]:
            lines.append(f"- {g}")
        lines.append("")
    # cite a couple of analyzed chapters by id
    named = [c["id"] for c in chapters if c.get("status") == "analyzed"][:4]
    if named:
        lines.append("See chapters " + ", ".join(f"`{c}`" for c in named) + " in the full report for tool versions and counts.")
        lines.append("")
    lines.append(
        "This cover letter does not add findings. Green CI / schema pass is not EY consulting quality; "
        "read the scripted chapters and per-finding impact/recommendation fields."
    )
    lines.append("")
    text = "\n".join(lines)
    words = text.split()
    if len(words) > MAX_WORDS:
        text = " ".join(words[:MAX_WORDS]) + "\n"
    return text


def try_llm_digest(data: dict, report_link: str, markdown_path: pathlib.Path | None) -> str | None:
    """Best-effort optional LLM. Returns None on any failure."""
    if os.environ.get("RSA_DIGEST_LLM", "").lower() not in ("1", "true", "yes"):
        return None
    # Prefer gh models if present; otherwise skip.
    if subprocess.call(["bash", "-lc", "command -v gh >/dev/null"], stdout=subprocess.DEVNULL) != 0:
        return None
    # Keep prompt tiny: only JSON summary, not full markdown rewrite.
    summary = {
        "repository": data.get("repository"),
        "finding_ids": [f.get("id") for f in data.get("findings") or []],
        "fixed_ids": [f.get("id") for f in data.get("fixed") or []],
        "chapters": [{"id": c.get("id"), "status": c.get("status")} for c in data.get("chapters") or []],
        "top": [
            {"id": f.get("id"), "severity": f.get("severity"), "title": f.get("title")}
            for f in (data.get("findings") or [])[:8]
        ],
        "coverage_gaps": data.get("coverage_gaps") or [],
        "report_link": report_link,
    }
    prompt = (
        "Write a <=300 word cover letter for a security assessment. "
        "Only cite finding IDs and chapter ids from the JSON. Do not invent findings, "
        "CVEs, or chapters. Link to report_link. Return markdown only.\n\n"
        + json.dumps(summary)
    )
    try:
        # gh models is not universally installed; treat any failure as skip.
        proc = subprocess.run(
            ["gh", "models", "run", "openai/gpt-4.1-mini", prompt],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            print(f"digest LLM unavailable: rc={proc.returncode} {proc.stderr[:200]}", file=sys.stderr)
            return None
        return proc.stdout.strip() + "\n"
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"digest LLM skipped: {exc}", file=sys.stderr)
        return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("findings")
    p.add_argument("--report", default="reports/security-assessment.md")
    p.add_argument("--out", default="reports/cover-letter.md")
    p.add_argument("--report-link", default="",
                   help="Link to the scripted report, relative to the digest (default: sibling security-assessment.md)")
    args = p.parse_args()
    findings_path = pathlib.Path(args.findings)
    try:
        data = json.loads(findings_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"digest skipped: cannot read findings ({exc})", file=sys.stderr)
        return 0
    if not isinstance(data, dict):
        print("digest skipped: findings not an object", file=sys.stderr)
        return 0

    report_link = args.report_link or __import__("os").path.relpath(
        pathlib.Path(args.report).resolve(), pathlib.Path(args.out).resolve().parent)

    finding_ids, chapters, advisories = allowed_refs(data)

    text = try_llm_digest(data, report_link, pathlib.Path(args.report))
    source = "llm"
    if not text:
        text = deterministic_digest(data, report_link)
        source = "deterministic"

    # Ensure link present
    if report_link not in text:
        text = text.rstrip() + f"\n\nFull report: [{report_link}]({report_link})\n"

    words = text.split()
    if len(words) > MAX_WORDS:
        print(f"digest dropped: over word cap ({len(words)} > {MAX_WORDS})", file=sys.stderr)
        pathlib.Path(args.out).unlink(missing_ok=True)
        return 0

    errors = cite_check(text, finding_ids, chapters, advisories)
    if errors:
        print("digest dropped: cite-check failed: " + "; ".join(errors[:8]), file=sys.stderr)
        pathlib.Path(args.out).unlink(missing_ok=True)
        return 0

    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print(f"Wrote {out} ({source}, {len(words)} words)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
