#!/usr/bin/env python3
"""Render top-level executive dashboard summary for $GITHUB_STEP_SUMMARY.

Collects organized target reports in reports/<name>/, reads score.json and
findings.json, and produces a single Markdown summary with:
1. Executive Rollup Table (Repository, Score, Severity Counts, Findings, Fixed)
2. Per-target highlights (Commit, Top Findings, Fixed items, Coverage Gaps)
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys


def render_dashboard(reports_dir: pathlib.Path) -> str:
    lines = [
        "# Multi-Repo Security Assessments Dashboard",
        "",
        "Executive rollup across assessed Forest Digital Services (FDS) repositories.",
        "",
    ]

    targets = []
    if reports_dir.is_dir():
        for d in sorted(reports_dir.iterdir()):
            if not d.is_dir():
                continue
            score_file = d / "score.json"
            findings_file = d / "findings.json"
            if not (score_file.is_file() and findings_file.is_file()):
                continue
            try:
                score_data = json.loads(score_file.read_text())
                findings_data = json.loads(findings_file.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            targets.append((d, score_data, findings_data))

    if not targets:
        lines.append("No organized target reports found.")
        return "\n".join(lines)

    # Rollup Table
    lines.append("| Repository | Score | Critical | High | Medium | Low | Total Findings | Fixed |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for d, s, f in targets:
        repo = f.get("repository") or d.name
        score = s.get("score", 0)
        counts = s.get("counts", {})
        crit = counts.get("Critical", 0)
        high = counts.get("High", 0)
        med = counts.get("Medium", 0)
        low = counts.get("Low", 0)
        total = len(f.get("findings") or [])
        fixed = len(f.get("fixed") or [])
        repo_link = f"[{repo}](https://github.com/{repo})" if "/" in repo else f"`{repo}`"
        lines.append(f"| {repo_link} | **{score}** / 100 | {crit} | {high} | {med} | {low} | {total} | {fixed} |")

    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Target Details")
    lines.append("")

    for d, s, f in targets:
        repo = f.get("repository") or d.name
        commit = f.get("commit") or "unknown"
        score = s.get("score", 0)
        findings = f.get("findings") or []
        fixed = f.get("fixed") or []
        gaps = f.get("coverage_gaps") or []
        cover_letter = d / "cover-letter.md"

        lines.append(f"<details>")
        lines.append(f"<summary><strong>{repo}</strong> — Score: {score} / 100 ({len(findings)} findings, {len(fixed)} fixed)</summary>")
        lines.append("")
        lines.append(f"Commit: `{commit}`")
        lines.append("")

        if cover_letter.is_file():
            cl_text = cover_letter.read_text().strip()
            if cl_text:
                # Rewrite relative security-assessment.md link to absolute target report link in the repo
                server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
                server_repo = os.environ.get("GITHUB_REPOSITORY", "bcgov/action-repo-reporter")
                ref = os.environ.get("GITHUB_REF_NAME", "main")
                if "merge" in ref or ref.isdigit() or ref.startswith("refs/pull"):
                    ref = "main"
                report_url = f"{server_url}/{server_repo}/blob/{ref}/reports/{d.name}/security-assessment.md"
                cl_text = re.sub(
                    r"\[([^\]]+)\]\((?:\./)?security-assessment\.md\)",
                    rf"[\1]({report_url})",
                    cl_text,
                )
                lines.append(cl_text)
                lines.append("")

        if fixed:
            lines.append("**Confirmed Fixed:**")
            for fx in fixed:
                fid = fx.get("id") if isinstance(fx, dict) else str(fx)
                note = fx.get("note", "") if isinstance(fx, dict) else ""
                lines.append(f"- `{fid}`: {note}" if note else f"- `{fid}`")
            lines.append("")

        if findings:
            lines.append(f"**Top Open Findings ({min(5, len(findings))} of {len(findings)}):**")
            for fnd in findings[:5]:
                fid = fnd.get("id", "UNKNOWN")
                sev = fnd.get("severity", "Info")
                title = fnd.get("title", "")
                lines.append(f"- **{fid}** [{sev}]: {title}")
            lines.append("")

        if gaps:
            lines.append("**Coverage Gaps:**")
            for g in gaps:
                lines.append(f"- {g}")
            lines.append("")

        lines.append("</details>")
        lines.append("")

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports_dir", nargs="?", default="reports",
                        help="Path to reports directory containing target folders (default: reports)")
    args = parser.parse_args()
    reports_path = pathlib.Path(args.reports_dir)
    print(render_dashboard(reports_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
