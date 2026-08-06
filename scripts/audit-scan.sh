#!/usr/bin/env bash
set -euo pipefail

# Pre-Audit Deterministic Scanner Script
# Usage: ./scripts/audit-scan.sh [target_repository_directory]

TARGET_DIR="${1:-.}"
OUTPUT_DIR="reports"
OUTPUT_FILE="${OUTPUT_DIR}/audit_evidence.json"

mkdir -p "${OUTPUT_DIR}"

python3 - "$TARGET_DIR" "$OUTPUT_FILE" << 'EOF'
import sys
import os
import re
import json
from pathlib import Path

target_dir = os.path.abspath(sys.argv[1])
output_file = sys.argv[2]

evidence = {
    "target_directory": target_dir,
    "domains": {
        "cicd": {
            "unpinned_actions": [],
            "secrets_inherit": [],
            "workflow_level_env_secrets": [],
            "script_injection_risks": []
        },
        "shell_scripts": {
            "missing_pipefail": []
        },
        "backend": {
            "has_pom_xml": False,
            "has_spring_boot_parent": False,
            "has_spring_data_jpa": False,
            "has_lombok": False,
            "has_oauth2_resource_server": False,
            "missing_transactional_writes": []
        },
        "frontend": {
            "has_package_json": False,
            "has_react_query": False,
            "has_auth_context": False,
            "has_error_boundary": False,
            "uses_import_meta_env_prod": False,
            "uses_process_env_node_env": False,
            "has_ci_false": False,
            "eslint_disabled_files": [],
            "storage_token_leaks": []
        },
        "security": {
            "hardcoded_credentials": [],
            "unvalidated_tls": []
        }
    },
    "summary": {
        "total_findings": 0
    }
}

# Helper to check if path should be skipped
IGNORE_DIRS = {'.git', 'node_modules', 'target', 'dist', 'build', '.tmp', 'vendor', '.idea', 'reports'}

def is_ignored(path_str):
    parts = Path(path_str).parts
    return any(ignored in parts for ignored in IGNORE_DIRS)

# 1. Scan CI/CD (.github/workflows/*.yml, *.yaml)
workflows_dir = os.path.join(target_dir, ".github", "workflows")
if os.path.isdir(workflows_dir):
    for root, _, files in os.walk(workflows_dir):
        for file in files:
            if file.endswith((".yml", ".yaml")):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, target_dir)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    
                    in_workflow_env = False
                    in_jobs = False
                    in_run_block = False
                    run_block_indent = 0
                    
                    for idx, line in enumerate(lines, 1):
                        stripped = line.strip()
                        
                        # Track workflow-level env vs jobs
                        if re.match(r'^\s*jobs\s*:', line):
                            in_jobs = True
                            in_workflow_env = False
                        elif re.match(r'^\s*env\s*:', line) and not in_jobs:
                            in_workflow_env = True
                        elif in_workflow_env and re.match(r'^\S', line):
                            in_workflow_env = False
                        
                        # Workflow-level env secrets
                        if in_workflow_env:
                            if re.search(r'(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)', line, re.IGNORECASE):
                                evidence["domains"]["cicd"]["workflow_level_env_secrets"].append({
                                    "file": rel_path,
                                    "line": idx,
                                    "content": stripped
                                })
                        
                        # Unpinned actions (uses: action@tag where tag is not 40-char SHA)
                        uses_match = re.search(r'uses:\s*([^\s#]+)', line)
                        if uses_match:
                            action_ref = uses_match.group(1)
                            if not action_ref.startswith("./") and "@" in action_ref:
                                action_name, tag = action_ref.split("@", 1)
                                if not re.match(r'^[0-9a-fA-F]{40}$', tag):
                                    evidence["domains"]["cicd"]["unpinned_actions"].append({
                                        "file": rel_path,
                                        "line": idx,
                                        "action": action_ref,
                                        "content": stripped
                                    })
                        
                        # secrets: inherit
                        if re.search(r'secrets:\s*inherit', line):
                            evidence["domains"]["cicd"]["secrets_inherit"].append({
                                "file": rel_path,
                                "line": idx,
                                "content": stripped
                            })
                        
                        # Script injection check inside run: blocks
                        if re.search(r'^\s*run\s*:', line):
                            in_run_block = True
                            run_block_indent = len(line) - len(line.lstrip())
                        elif in_run_block:
                            curr_indent = len(line) - len(line.lstrip())
                            if stripped and curr_indent <= run_block_indent and not line.lstrip().startswith("#"):
                                in_run_block = False
                        
                        if in_run_block:
                            injection_match = re.search(r'\$\{\{\s*(github\.(event|head_ref|ref_name|actor|inputs)[^\}]*)\s*\}\}', line)
                            if injection_match:
                                evidence["domains"]["cicd"]["script_injection_risks"].append({
                                    "file": rel_path,
                                    "line": idx,
                                    "expression": injection_match.group(1),
                                    "content": stripped
                                })
                except Exception as e:
                    pass

# 2. Scan Shell Scripts (*.sh)
for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
        if file.endswith(".sh"):
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, target_dir)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                
                # Check for set -euo pipefail
                if not (("set -euo pipefail" in content) or ("set -e" in content and "set -u" in content and "pipefail" in content)):
                    evidence["domains"]["shell_scripts"]["missing_pipefail"].append({
                        "file": rel_path
                    })
            except Exception as e:
                pass

# 3. Scan Backend (pom.xml & Java files)
pom_path = os.path.join(target_dir, "pom.xml")
if os.path.isfile(pom_path):
    evidence["domains"]["backend"]["has_pom_xml"] = True
    try:
        with open(pom_path, "r", encoding="utf-8", errors="ignore") as f:
            pom_content = f.read()
        
        if "spring-boot-starter-parent" in pom_content:
            evidence["domains"]["backend"]["has_spring_boot_parent"] = True
        if "spring-boot-starter-data-jpa" in pom_content:
            evidence["domains"]["backend"]["has_spring_data_jpa"] = True
        if "lombok" in pom_content:
            evidence["domains"]["backend"]["has_lombok"] = True
        if "spring-boot-starter-security-oauth2-resource-server" in pom_content:
            evidence["domains"]["backend"]["has_oauth2_resource_server"] = True
    except Exception as e:
        pass

for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
        if file.endswith(".java"):
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, target_dir)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                content = "".join(lines)
                if "@Service" in content or "@Repository" in content:
                    has_class_transactional = "@Transactional" in content
                    for idx, line in enumerate(lines, 1):
                        if re.search(r'public\s+.*\b(save|update|delete|create|remove|insert)\b', line, re.IGNORECASE):
                            # check if line or method or class has @Transactional
                            prev_snippet = "".join(lines[max(0, idx-5):idx])
                            if not has_class_transactional and "@Transactional" not in prev_snippet:
                                evidence["domains"]["backend"]["missing_transactional_writes"].append({
                                    "file": rel_path,
                                    "line": idx,
                                    "content": line.strip()
                                })
            except Exception as e:
                pass

# 4. Scan Frontend (package.json & JS/TS files)
pkg_path = os.path.join(target_dir, "package.json")
if os.path.isfile(pkg_path):
    evidence["domains"]["frontend"]["has_package_json"] = True
    try:
        with open(pkg_path, "r", encoding="utf-8", errors="ignore") as f:
            pkg_data = json.load(f)
        deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
        if "@tanstack/react-query" in deps or "react-query" in deps:
            evidence["domains"]["frontend"]["has_react_query"] = True
        
        scripts = json.dumps(pkg_data.get("scripts", {}))
        if "CI=false" in scripts:
            evidence["domains"]["frontend"]["has_ci_false"] = True
    except Exception as e:
        pass

for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
        if file.endswith((".ts", ".tsx", ".js", ".jsx")):
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, target_dir)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                content = "".join(lines)
                
                if "AuthContext" in content or "useAuth" in content:
                    evidence["domains"]["frontend"]["has_auth_context"] = True
                if "ErrorBoundary" in content:
                    evidence["domains"]["frontend"]["has_error_boundary"] = True
                if "import.meta.env.PROD" in content:
                    evidence["domains"]["frontend"]["uses_import_meta_env_prod"] = True
                if "process.env.NODE_ENV" in content:
                    evidence["domains"]["frontend"]["uses_process_env_node_env"] = True
                
                for idx, line in enumerate(lines, 1):
                    stripped = line.strip()
                    if "eslint-disable" in line or "@ts-ignore" in line or "@ts-nocheck" in line:
                        evidence["domains"]["frontend"]["eslint_disabled_files"].append({
                            "file": rel_path,
                            "line": idx,
                            "content": stripped
                        })
                    
                    if re.search(r'(localStorage|sessionStorage)\.setItem\s*\(\s*["\'].*(token|key|auth|jwt|password|credential)', line, re.IGNORECASE):
                        evidence["domains"]["frontend"]["storage_token_leaks"].append({
                            "file": rel_path,
                            "line": idx,
                            "content": stripped
                        })
            except Exception as e:
                pass

# 5. Scan Security (Hardcoded credentials & Unvalidated TLS)
SECRET_PATTERNS = [
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'-----BEGIN PRIVATE KEY-----', "Private Key Header"),
    (r'(api_key|apikey|secret_key|private_key)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', "Hardcoded API Key / Secret")
]

TLS_PATTERNS = [
    (r'checkServerTrusted', "Unvalidated SSL checkServerTrusted"),
    (r'TrustAllStrategy', "TrustAllStrategy SSL Bypass"),
    (r'ALLOW_ALL_HOSTNAME_VERIFIER', "Disabled Hostname Verifier"),
    (r'NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0[\'"]?', "Disabled Node TLS Rejection"),
    (r'curl\s+.*(-k|--insecure)', "Insecure Curl TLS Request"),
    (r'InsecureSkipVerify\s*:\s*true', "InsecureSkipVerify TLS Bypass")
]

for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
        if file.endswith("audit-scan.sh"):
            continue
        filepath = os.path.join(root, file)
        rel_path = os.path.relpath(filepath, target_dir)
        
        # Skip binary files, lock files, json reports
        if file.endswith((".png", ".jpg", ".jpeg", ".ico", ".pdf", ".lock", ".json", ".svg", ".zip", ".tar", ".gz")):
            continue
            
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            for idx, line in enumerate(lines, 1):
                stripped = line.strip()
                for pattern, desc in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        evidence["domains"]["security"]["hardcoded_credentials"].append({
                            "file": rel_path,
                            "line": idx,
                            "type": desc,
                            "content": stripped
                        })
                for pattern, desc in TLS_PATTERNS:
                    if re.search(pattern, line):
                        evidence["domains"]["security"]["unvalidated_tls"].append({
                            "file": rel_path,
                            "line": idx,
                            "type": desc,
                            "content": stripped
                        })
        except Exception as e:
            pass

# Count total findings
total = (
    len(evidence["domains"]["cicd"]["unpinned_actions"]) +
    len(evidence["domains"]["cicd"]["secrets_inherit"]) +
    len(evidence["domains"]["cicd"]["workflow_level_env_secrets"]) +
    len(evidence["domains"]["cicd"]["script_injection_risks"]) +
    len(evidence["domains"]["shell_scripts"]["missing_pipefail"]) +
    len(evidence["domains"]["backend"]["missing_transactional_writes"]) +
    len(evidence["domains"]["frontend"]["eslint_disabled_files"]) +
    len(evidence["domains"]["frontend"]["storage_token_leaks"]) +
    len(evidence["domains"]["security"]["hardcoded_credentials"]) +
    len(evidence["domains"]["security"]["unvalidated_tls"])
)

evidence["summary"]["total_findings"] = total

with open(output_file, "w", encoding="utf-8") as out:
    json.dump(evidence, out, indent=2)

print(f"Audit scan complete. Findings saved to {output_file}. Total issues detected: {total}")
EOF
