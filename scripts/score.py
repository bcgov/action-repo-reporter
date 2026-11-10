#!/usr/bin/env python3
"""Validate findings.json (cite-or-ask) and compute bounded risk score: 0 (spotless) to 100 (max risk).
Findings whose file:line citations don't exist in the repo are rejected (moved to `rejected`).
--require IDs pass if present as an accepted open finding OR in `fixed`/`resolved` with a valid cite."""
import argparse, json, math, pathlib, sys

W = {"Critical": 25, "High": 8, "Medium": 2, "Low": 1}

def compute_risk_score(counts: dict[str, int]) -> int:
    """Calculate bounded risk score (0-100, where 0 is spotless) with diminishing returns on minor items."""
    c = counts.get("Critical", 0)
    h = counts.get("High", 0)
    m = counts.get("Medium", 0)
    l = counts.get("Low", 0)

    crit_pts = 25 * c
    high_pts = min(40, 8 * h)
    med_pts = min(15, round(4 * math.log(1 + m))) if m > 0 else 0
    low_pts = min(5, round(l * 0.2)) if l > 0 else 0

    return min(100, crit_pts + high_pts + med_pts + low_pts)

def valid(ev, root):
    """Cite must be a relative path that resolves (symlinks included) inside repo-dir."""
    if not isinstance(ev, dict):
        return False
    f = ev.get("file")
    if not isinstance(f, str) or not f or pathlib.PurePath(f).is_absolute() or ".." in pathlib.PurePath(f).parts:
        return False
    try:
        base = root.resolve(strict=True)
        p = (root / f).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    if p != base and base not in p.parents or not p.is_file():
        return False
    try:
        with p.open(errors="ignore") as fp:
            n = sum(1 for _ in fp)
    except OSError:
        return False
    return isinstance(ev.get("line"), int) and 1 <= ev["line"] <= n

def fixed_ok(entry, root):
    """A confirmed-fixed entry needs id + a cite that exists under repo-dir."""
    if not isinstance(entry, dict) or not entry.get("id"):
        return False
    # Accept either top-level file/line or evidence[0]
    if entry.get("file") is not None:
        return valid({"file": entry.get("file"), "line": entry.get("line")}, root)
    evs = entry.get("evidence") or []
    return bool(evs) and all(valid(e, root) for e in evs)

def main():
    a = argparse.ArgumentParser(); a.add_argument("findings"); a.add_argument("--repo-dir", default="target")
    a.add_argument("--out", default="score.json"); a.add_argument("--require", nargs="*", default=[],
                   help="IDs that must be an accepted finding OR confirmed-fixed cite, e.g. AUTH-001 CRYPTO-001")
    o = a.parse_args(); root = pathlib.Path(o.repo_dir)
    data = json.load(open(o.findings)); ok, bad = [], []
    for f in data.get("findings", []):
        if not isinstance(f, dict):
            bad.append(f); continue
        evs = f.get("evidence") or []
        (ok if evs and all(valid(e, root) for e in evs) and f.get("severity") in W else bad).append(f)
    fixed_raw = list(data.get("fixed") or []) + list(data.get("resolved") or [])
    fixed_ok_list, fixed_bad = [], []
    for entry in fixed_raw:
        (fixed_ok_list if fixed_ok(entry, root) else fixed_bad).append(entry)
    counts = {s: sum(f["severity"] == s for f in ok) for s in ("Critical", "High", "Medium", "Low")}
    score = compute_risk_score(counts)
    satisfied = {f.get("id") for f in ok} | {e.get("id") for e in fixed_ok_list}
    missing = [r for r in o.require if r not in satisfied]
    m_cnt = counts.get("Medium", 0)
    l_cnt = counts.get("Low", 0)
    res = {
        "score": score,
        "counts": counts,
        "breakdown": {
            "Critical": 25 * counts.get("Critical", 0),
            "High": min(40, 8 * counts.get("High", 0)),
            "Medium": min(15, round(4 * math.log(1 + m_cnt))) if m_cnt > 0 else 0,
            "Low": min(5, round(l_cnt * 0.2)) if l_cnt > 0 else 0,
        },
        "accepted": len(ok),
        "rejected": [f.get("id") if isinstance(f, dict) else None for f in bad],
        "fixed_accepted": [e.get("id") for e in fixed_ok_list],
        "fixed_rejected": [e.get("id") if isinstance(e, dict) else None for e in fixed_bad],
        "missing_required": missing,
    }
    pathlib.Path(o.out).parent.mkdir(parents=True, exist_ok=True)
    with open(o.out, "w") as out_fp:
        json.dump(res, out_fp, indent=2)
    print(json.dumps(res, indent=2))
    sys.exit(1 if missing else 0)

if __name__ == "__main__":
    main()
