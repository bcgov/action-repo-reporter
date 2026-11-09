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
        if cid in seen_ids:
            return
        # Normalize and filter existing paths
        valid_paths = [p for p in paths if (repo_dir / p).exists()]
        if not valid_paths and paths:
            # If specified paths don't exist, don't register ghost component
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
    has_nested_portals = False
    for cid, name, path_str in nested_portals:
        if (repo_dir / path_str).is_dir():
            has_nested_portals = True
            add_component(cid, name, "frontend", [path_str], ["api" if (repo_dir / "api").is_dir() else "backend"])

    # 3. Look for known portal / frontend directories
    candidate_fe_dirs = [
        "frontend", "admin", "public", "client", "web", "ui", "app",
    ]
    for fed in candidate_fe_dirs:
        dir_path = repo_dir / fed
        if not dir_path.is_dir():
            continue
        # If nested portals were already extracted inside this frontend, don't re-add whole frontend as portal
        if has_nested_portals and fed == "frontend":
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
        paths = [parent_dir] if parent_dir != "." else [manage_path]
        if rctool.is_dir():
            paths.append(str(rctool.relative_to(repo_dir)))
        add_component(cid, "Rating Curve Web App", "api", paths, ["database", "ingress"])

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

    # Default connections if no explicit integrations match
    if frontends and apis:
        for fe in frontends:
            for api in apis:
                lines.append(f"    {sanitize_id(fe['id'])} --> {sanitize_id(api['id'])}")
    elif ingresses and apis:
        for ing in ingresses:
            for api in apis:
                lines.append(f"    {sanitize_id(ing['id'])} --> {sanitize_id(api['id'])}")

    if apis and auths:
        for api in apis:
            for auth in auths:
                lines.append(f"    {sanitize_id(api['id'])} -.->|Authenticates with| {sanitize_id(auth['id'])}")

    if apis and dbs:
        for api in apis:
            for db in dbs:
                lines.append(f"    {sanitize_id(api['id'])} -->|Persists to| {sanitize_id(db['id'])}")

    if batches and dbs:
        for b in batches:
            for db in dbs:
                lines.append(f"    {sanitize_id(b['id'])} -->|Reads/Writes| {sanitize_id(db['id'])}")

    if libs and (apis or frontends):
        for l in libs:
            target = apis[0] if apis else frontends[0]
            lines.append(f"    {sanitize_id(target['id'])} -.->|Consumes| {sanitize_id(l['id'])}")

    return "\n".join(lines)


def attribute_finding_to_component(finding: dict[str, Any], components: list[dict[str, Any]]) -> str:
    """Attribute a finding to a component ID based on evidence file paths."""
    evidence = finding.get("evidence") or []
    files = []
    for ev in evidence:
        if isinstance(ev, dict) and ev.get("file"):
            files.append(ev["file"])
        elif isinstance(ev, str):
            files.append(ev)

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
