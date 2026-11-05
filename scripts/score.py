#!/usr/bin/env python3
"""Validate findings.json (cite-or-ask) and compute the EY-style risk score: min(100, 10C+5H+2M+1L).
Findings whose file:line citations don't exist in the repo are rejected (moved to `rejected`).
--require IDs pass if present as an accepted open finding OR in `fixed`/`resolved` with a valid cite."""
import argparse, json, pathlib, sys

W = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}

def valid(ev, root):
    p = root / ev.get("file", "")
    try:
        n = sum(1 for _ in p.open(errors="ignore"))
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
        evs = f.get("evidence") or []
        (ok if evs and all(valid(e, root) for e in evs) and f.get("severity") in W else bad).append(f)
    fixed_raw = list(data.get("fixed") or []) + list(data.get("resolved") or [])
    fixed_ok_list, fixed_bad = [], []
    for entry in fixed_raw:
        (fixed_ok_list if fixed_ok(entry, root) else fixed_bad).append(entry)
    counts = {s: sum(f["severity"] == s for f in ok) for s in W}
    score = min(100, sum(W[s] * c for s, c in counts.items()))
    satisfied = {f.get("id") for f in ok} | {e.get("id") for e in fixed_ok_list}
    missing = [r for r in o.require if r not in satisfied]
    res = {"score": score, "counts": counts, "accepted": len(ok), "rejected": [f.get("id") for f in bad],
           "fixed_accepted": [e.get("id") for e in fixed_ok_list],
           "fixed_rejected": [e.get("id") for e in fixed_bad],
           "missing_required": missing}
    pathlib.Path(o.out).parent.mkdir(parents=True, exist_ok=True); json.dump(res, open(o.out, "w"), indent=2)
    print(json.dumps(res, indent=2)); sys.exit(1 if missing else 0)

if __name__ == "__main__":
    main()
