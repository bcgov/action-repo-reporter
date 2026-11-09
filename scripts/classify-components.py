#!/usr/bin/env python3
"""Component inventory and architecture topology extractor.

Analyzes repository layout under target/ (monorepo workspaces, framework entrypoints,
routes, Caddyfiles, migrations, batch processors) and generates structured components,
Mermaid architecture diagrams, and finding attribution.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any


def _safe_read(path: pathlib.Path, max_chars: int = 100_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:max_chars]
    except OSError:
        return ""


def classify_components(repo_dir: pathlib.Path, repo_name: str = "") -> list[dict[str, Any]]:
    """Scan repo directory layout and return structured component list."""
    components: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def add_component(cid: str, name: str, ctype: str, paths: list[str], integrations: list[str]) -> None:
        # Normalize and filter existing paths
        valid_paths = [p for p in paths if p == "." or (repo_dir / p).exists()]
        if not valid_paths and paths:
            # If specified paths don't exist, don't register ghost component
            return
        if cid in seen_ids:
            # Merge paths and integrations into existing component registration
            for c in components:
                if c["id"] == cid:
                    c["paths"] = sorted(set(c["paths"] + valid_paths))
                    c["integrations"] = sorted(set(c["integrations"] + integrations))
                    break
            return
        seen_ids.add(cid)
        components.append({
            "id": cid,
            "name": name,
            "type": ctype,
            "paths": sorted(set(valid_paths)),
            "integrations": sorted(set(integrations)),
        })

    # 1. Check for dedicated web servers / ingress (Caddyfile, nginx.conf)
    caddyfiles = list(repo_dir.glob("**/Caddyfile"))
    nginx_confs = list(repo_dir.glob("**/nginx.conf*"))
    for cf in caddyfiles:
        if "node_modules" in cf.parts:
            continue
        rel = cf.parent.relative_to(repo_dir)
        cid = f"{rel.parts[0]}-web-server" if rel.parts else "web-server"
        add_component(cid, f"{cid.replace('-', ' ').title()}", "ingress", [str(cf.relative_to(repo_dir))], ["api" if (repo_dir / "api").is_dir() else "backend"])

    for nc in nginx_confs:
        if "node_modules" in nc.parts:
            continue
        rel = nc.parent.relative_to(repo_dir)
        cid = f"{rel.parts[0]}-ingress" if rel.parts else "ingress"
        add_component(cid, f"{cid.replace('-', ' ').title()}", "ingress", [str(nc.relative_to(repo_dir))], ["api" if (repo_dir / "api").is_dir() else "backend"])

    # 2. Look for nested portal paths first (e.g. frontend/src/app/admin, frontend/src/app/public)
    nested_portals = [
        ("admin-portal", "Admin Portal", "frontend/src/app/admin"),
        ("public-portal", "Public Portal", "frontend/src/app/public"),
    ]
    for cid, name, path_str in nested_portals:
        if (repo_dir / path_str).is_dir():
            add_component(cid, name, "frontend", [path_str], ["api" if (repo_dir / "api").is_dir() else "backend"])

    # 3. Look for known portal / frontend directories
    candidate_fe_dirs = [
        "frontend", "admin", "public", "client", "web", "ui", "app",
    ]
    for fed in candidate_fe_dirs:
        dir_path = repo_dir / fed
        if not dir_path.is_dir():
            continue

        # Check if it has frontend indicators
        has_angular = (dir_path / "angular.json").is_file() or any(dir_path.glob("**/angular.json"))
        has_vite = any(dir_path.glob("*vite.config*"))
        has_pkg = (dir_path / "package.json").is_file()
        pkg_has_fe = False
        if has_pkg:
            pkg_data = {}
            try:
                pkg_data = json.loads(_safe_read(dir_path / "package.json"))
            except json.JSONDecodeError:
                pass
            deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
            if any(k in deps for k in ("@angular/core", "react", "vue", "@vue/core", "svelte")):
                pkg_has_fe = True

        if has_angular or has_vite or pkg_has_fe:
            cid = fed.replace("/", "-")
            name = f"{cid.replace('-', ' ').title()} Portal" if ("admin" in cid or "public" in cid) else f"{cid.replace('-', ' ').title()} App"
            add_component(cid, name, "frontend", [fed], ["api" if (repo_dir / "api").is_dir() else "backend-api"])

    # 4. Check for dedicated API / Backend
    candidate_api_dirs = ["api", "backend", "server", "services", "backend/src", "api/src"]
    for apid in candidate_api_dirs:
        dir_path = repo_dir / apid
        if not dir_path.is_dir():
            continue

        # Skip source-directory candidate when containing service was already classified,
        # unless there is evidence of an independent service boundary
        parent_candidate = str(pathlib.Path(apid).parent)
        if parent_candidate != "." and any(c["id"] == parent_candidate.replace("/", "-") for c in components):
            has_independent_pkg = (dir_path / "package.json").is_file() and not (repo_dir / parent_candidate / "package.json").is_file()
            has_independent_req = (dir_path / "requirements.txt").is_file() and not (repo_dir / parent_candidate / "requirements.txt").is_file()
            if not (has_independent_pkg or has_independent_req):
                continue

        # Check if NestJS, Express, FastAPI, Django, Spring
        has_nest = (dir_path / "nest-cli.json").is_file() or any(dir_path.glob("**/nest-cli.json"))
        has_manage = (dir_path / "manage.py").is_file() or (repo_dir / "manage.py").is_file()
        has_pkg = (dir_path / "package.json").is_file()
        is_api = has_nest or has_manage
        if has_pkg:
            try:
                pkg_data = json.loads(_safe_read(dir_path / "package.json"))
                deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                if any(k in deps for k in ("@nestjs/core", "express", "fastify", "koa", "hapi")):
                    is_api = True
            except json.JSONDecodeError:
                pass

        # Python API
        if any(dir_path.glob("**/settings.py")) or any(dir_path.glob("**/main.py")) or (dir_path / "requirements.txt").is_file():
            is_api = True

        if is_api:
            cid = apid.replace("/", "-")
            add_component(cid, f"{cid.upper()} Service", "api", [apid], ["database", "auth-gateway"])

    # 5. Check Django apps (e.g. nr-hydrometric-rating-curve has frontend/manage.py, frontend/rctool)
    if (repo_dir / "frontend" / "manage.py").is_file() or (repo_dir / "manage.py").is_file():
        manage_path = "frontend/manage.py" if (repo_dir / "frontend" / "manage.py").is_file() else "manage.py"
        parent_dir = str(pathlib.Path(manage_path).parent)
        cid = "django-app" if parent_dir == "." else f"{parent_dir.replace('/', '-')}-app"
        rctool = repo_dir / parent_dir / "rctool" if parent_dir != "." else repo_dir / "rctool"
        paths = [parent_dir]
        if rctool.is_dir():
            paths.append(str(rctool.relative_to(repo_dir)))
        name = "Django Web App" if cid == "django-app" else f"{cid.replace('-', ' ').title()}"
        add_component(cid, name, "api", paths, ["database", "ingress"])

    # 6. Check for Auth Gateway / Core Security
    auth_paths = [
        "api/src/core/security",
        "backend/src/core/security",
        "api/src/auth",
        "src/core/security",
    ]
    for ap in auth_paths:
        if (repo_dir / ap).is_dir():
            add_component("auth-gateway", "Authentication Gateway", "auth-gateway", [ap], ["idp-oidc"])

    # 7. Check for Batch / Workers / Crawlers
    batch_paths = [
        ("crawler", "Crawler Service"),
        ("batch", "Batch Processor"),
        ("jobs", "Job Worker"),
        ("workers", "Worker Service"),
        ("worker", "Worker Service"),
        ("api/src/batch", "API Batch Processor"),
        ("backend/src/batch", "Backend Batch Processor"),
        ("utilities", "Utilities Service"),
    ]
    for bp, bname in batch_paths:
        if (repo_dir / bp).is_dir():
            cid = bp.replace("/", "-")
            add_component(cid, bname, "batch", [bp], ["api" if (repo_dir / "api").is_dir() else "database"])

    # 8. Check for Database / Migrations
    db_paths = []
    for dp in ["db", "database", "api/src/migrations", "migrations", "frontend/rctool/migrations"]:
        if (repo_dir / dp).is_dir():
            db_paths.append(dp)
    has_compose_db = False
    for compose_name in ("docker-compose.yml", "compose.yml", "docker-compose.dev.yml"):
        compose_file = repo_dir / compose_name
        if compose_file.is_file():
            content = _safe_read(compose_file)
            if re.search(r"\b(postgres|postgis|crunchy|mysql|mongo|mariadb)\b", content, re.I):
                has_compose_db = True
                if compose_name not in db_paths:
                    db_paths.append(compose_name)
    if db_paths or has_compose_db:
        add_component("database", "Relational Database", "database", db_paths if db_paths else ["db"], [])

    # 9. Check for Shared Libraries
    lib_paths = ["libs", "lib", "common", "packages"]
    for lp in lib_paths:
        if (repo_dir / lp).is_dir():
            add_component(lp, f"Shared {lp.title()}", "library", [lp], [])

    # Fallback if nothing detected: create a root component
    if not components:
        components.append({
            "id": "root-app",
            "name": f"{repo_name or 'Application'} Core",
            "type": "api",
            "paths": ["."],
            "integrations": [],
        })

    return components


def generate_mermaid_diagram(components: list[dict[str, Any]]) -> str:
    """Generate Mermaid architecture diagram from classified components."""
    lines = ["graph TD"]
    lines.append("    subgraph Users[\"Users & Clients\"]")
    lines.append("        UserClient[\"End Users / Browsers\"]")
    lines.append("    end")

    ingresses = [c for c in components if c["type"] == "ingress"]
    frontends = [c for c in components if c["type"] == "frontend"]
    apis = [c for c in components if c["type"] == "api"]
    auths = [c for c in components if c["type"] == "auth-gateway"]
    batches = [c for c in components if c["type"] == "batch"]
    dbs = [c for c in components if c["type"] == "database"]
    libs = [c for c in components if c["type"] == "library"]

    def sanitize_id(raw: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", raw)
        return f"node_{clean}"

    # Render Edge / Presentation layer
    edge_nodes = ingresses + frontends
    if edge_nodes:
        lines.append("    subgraph Presentation[\"Edge & Presentation Layer\"]")
        for c in edge_nodes:
            nid = sanitize_id(c["id"])
            shape_open, shape_close = ("[", "]") if c["type"] == "frontend" else ("([", "])")
            lines.append(f"        {nid}{shape_open}\"{c['name']}\"{shape_close}")
        lines.append("    end")
        lines.append("    UserClient --> Presentation")

    # Render Application Services
    app_nodes = apis + auths + batches
    if app_nodes:
        lines.append("    subgraph Application[\"Application Services\"]")
        for c in app_nodes:
            nid = sanitize_id(c["id"])
            shape_open, shape_close = ("[", "]") if c["type"] != "auth-gateway" else ("{{", "}}")
            lines.append(f"        {nid}{shape_open}\"{c['name']}\"{shape_close}")
        lines.append("    end")

    # Render Data & Storage
    if dbs:
        lines.append("    subgraph Storage[\"Data & Persistence\"]")
        for c in dbs:
            nid = sanitize_id(c["id"])
            lines.append(f"        {nid}[(\"{c['name']}\")]")
        lines.append("    end")

    # Render Libraries
    if libs:
        lines.append("    subgraph Shared[\"Shared Libraries\"]")
        for c in libs:
            nid = sanitize_id(c["id"])
            lines.append(f"        {nid}[\"{c['name']}\"]")
        lines.append("    end")

    comp_by_id = {c["id"]: c for c in components}
    seen_edges: set[tuple[str, str]] = set()

    def add_edge(src_c: dict[str, Any], tgt_c: dict[str, Any], label: str = "") -> None:
        src_nid = sanitize_id(src_c["id"])
        tgt_nid = sanitize_id(tgt_c["id"])
        if (src_nid, tgt_nid) in seen_edges or src_nid == tgt_nid:
            return
        seen_edges.add((src_nid, tgt_nid))
        if tgt_c["type"] == "auth-gateway":
            edge_syntax = f"-.->|{label or 'Authenticates with'}|"
        elif tgt_c["type"] == "database":
            edge_syntax = f"-->|{label or 'Persists to'}|"
        elif tgt_c["type"] == "library":
            edge_syntax = f"-.->|{label or 'Consumes'}|"
        elif label:
            edge_syntax = f"-->|{label}|"
        else:
            edge_syntax = "-->"
        lines.append(f"    {src_nid} {edge_syntax} {tgt_nid}")

    # 1. Resolve explicit recorded integrations first
    for src in components:
        for int_id in src.get("integrations", []):
            if int_id in comp_by_id:
                add_edge(src, comp_by_id[int_id])
            else:
                # Type or prefix match (e.g. "api", "backend", "database")
                candidates = [c for c in components if c["type"] == int_id or c["id"] == int_id or c["id"].startswith(int_id)]
                for tgt in candidates:
                    add_edge(src, tgt)

    # 2. Retain ingress connections alongside frontend connections
    for ing in ingresses:
        ing_nid = sanitize_id(ing["id"])
        has_outbound = any(s == ing_nid for s, _ in seen_edges)
        if not has_outbound:
            if frontends:
                for fe in frontends:
                    add_edge(ing, fe, "Routes to")
            if apis:
                for api in apis:
                    add_edge(ing, api, "Proxies to")

    # 3. Frontend fallback connections
    for fe in frontends:
        fe_nid = sanitize_id(fe["id"])
        if not any(s == fe_nid for s, _ in seen_edges) and apis:
            for api in apis:
                add_edge(fe, api)

    # 4. APIs to Auth / Database fallback connections
    for api in apis:
        api_nid = sanitize_id(api["id"])
        has_auth = any(s == api_nid and comp_by_id.get(t_id, {}).get("type") == "auth-gateway" for s, t in seen_edges for t_id in comp_by_id if sanitize_id(t_id) == t)
        if not has_auth and auths:
            for auth in auths:
                add_edge(api, auth, "Authenticates with")
        has_db = any(s == api_nid and comp_by_id.get(t_id, {}).get("type") == "database" for s, t in seen_edges for t_id in comp_by_id if sanitize_id(t_id) == t)
        if not has_db and dbs:
            for db in dbs:
                add_edge(api, db, "Persists to")

    # 5. Batches fallback connections
    for b in batches:
        b_nid = sanitize_id(b["id"])
        if not any(s == b_nid for s, _ in seen_edges):
            if apis:
                for api in apis:
                    add_edge(b, api)
            elif dbs:
                for db in dbs:
                    add_edge(b, db, "Reads/Writes")

    # 6. Shared library fallback connections
    for l in libs:
        l_nid = sanitize_id(l["id"])
        if not any(t == l_nid for _, t in seen_edges):
            target = apis[0] if apis else (frontends[0] if frontends else None)
            if target:
                add_edge(target, l, "Consumes")

    return "\n".join(lines)


def attribute_finding_to_component(finding: dict[str, Any], components: list[dict[str, Any]]) -> str:
    """Attribute a finding to a component ID based on evidence file paths."""
    evidence = finding.get("evidence") or []
    files: list[str] = []
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("file"):
            files.append(ev["file"])
        elif isinstance(ev, str):
            files.append(ev)

    # Accept the finding itself as citation evidence when evidence array is absent or empty
    if not files:
        if finding.get("file"):
            files.append(str(finding["file"]))
        elif finding.get("cite"):
            cite_file = str(finding["cite"]).split(":")[0].strip()
            if cite_file:
                files.append(cite_file)

    if not files:
        title = finding.get("title", "")
        for c in components:
            if c["id"] in title.lower() or any(p in title for p in c["paths"]):
                return c["id"]
        return "root"

    # Match file against component paths (longest matching prefix wins)
    best_match = "root"
    best_match_len = -1

    for f in files:
        for c in components:
            for p in c["paths"]:
                p_clean = p.rstrip("/")
                if p_clean == "." or not p_clean:
                    if best_match_len < 0:
                        best_match = c["id"]
                        best_match_len = 0
                elif f == p_clean or f.startswith(f"{p_clean}/"):
                    if len(p_clean) > best_match_len:
                        best_match = c["id"]
                        best_match_len = len(p_clean)

    return best_match
