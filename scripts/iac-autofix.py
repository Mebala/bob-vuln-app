#!/usr/bin/env python3
"""
Bob IaC Auto-Fixer
Reads Checkov results and applies hardening fixes to:
  - Dockerfile
  - Kubernetes manifests (*.yaml / *.yml in k8s/, manifests/, deploy/)
  - docker-compose.yml
"""

import json
import os
import re
import sys
from pathlib import Path

results_file = sys.argv[1] if len(sys.argv) > 1 else "/tmp/checkov-results.json"
ROOT = Path(".")

# ── Dockerfile fixers ──────────────────────────────────────────────────────
def fix_dockerfile(content: str, check_id: str) -> str:
    lines = content.splitlines(keepends=True)

    # CKV_DOCKER_2 — HEALTHCHECK missing
    if check_id == "CKV_DOCKER_2" and "HEALTHCHECK" not in content:
        lines.append("\n# Bob-AutoFix: Added HEALTHCHECK\nHEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1\n")

    # CKV_DOCKER_3 — USER not set (running as root)
    if check_id == "CKV_DOCKER_3" and not any("USER " in l for l in lines):
        # Insert before last CMD/ENTRYPOINT
        for i in reversed(range(len(lines))):
            if lines[i].startswith("CMD") or lines[i].startswith("ENTRYPOINT"):
                lines.insert(i, "# Bob-AutoFix: Drop root privileges\nUSER node\n")
                break

    # CKV_DOCKER_4 — ADD instead of COPY
    if check_id == "CKV_DOCKER_4":
        new_lines = []
        for l in lines:
            if re.match(r"^ADD\s+(?!http)", l):
                l = l.replace("ADD ", "COPY ", 1) + "  # Bob-AutoFix: ADD→COPY\n"
            new_lines.append(l)
        lines = new_lines

    # CKV_DOCKER_7 — FROM :latest tag
    if check_id == "CKV_DOCKER_7":
        new_lines = []
        for l in lines:
            if re.match(r"^FROM\s+\S+:latest", l):
                l = re.sub(r":latest(\s)", r":20-alpine\\1", l) + "  # Bob-AutoFix: pin version\n"
            new_lines.append(l)
        lines = new_lines

    # CKV_DOCKER_8 — apt-get without --no-install-recommends
    if check_id == "CKV_DOCKER_8":
        content_new = "".join(lines)
        content_new = re.sub(
            r"apt-get install(?! --no-install-recommends)",
            "apt-get install --no-install-recommends",
            content_new,
        )
        return content_new

    return "".join(lines)


# ── Kubernetes manifest fixers ─────────────────────────────────────────────
def fix_k8s_yaml(content: str, check_id: str) -> str:
    # CKV_K8S_6 — runAsRoot / no securityContext
    if check_id in ("CKV_K8S_6", "CKV_K8S_8", "CKV_K8S_30"):
        if "securityContext:" not in content:
            # Inject under containers: block
            security_ctx = (
                "          securityContext:\n"
                "            runAsNonRoot: true\n"
                "            runAsUser: 1000\n"
                "            readOnlyRootFilesystem: true\n"
                "            allowPrivilegeEscalation: false\n"
                "            # Bob-AutoFix: hardened securityContext\n"
            )
            content = re.sub(
                r"(        - name: .+\n)",
                r"\1" + security_ctx,
                content,
                count=1,
            )

    # CKV_K8S_14 — image tag :latest
    if check_id == "CKV_K8S_14":
        content = re.sub(
            r"(image:\s+\S+):latest",
            r"\1:stable  # Bob-AutoFix: pinned from :latest",
            content,
        )

    # CKV_K8S_20 — no resource limits
    if check_id == "CKV_K8S_20" and "resources:" not in content:
        resources = (
            "          resources:\n"
            "            requests:\n"
            "              memory: '64Mi'\n"
            "              cpu: '250m'\n"
            "            limits:\n"
            "              memory: '128Mi'\n"
            "              cpu: '500m'\n"
            "            # Bob-AutoFix: resource limits added\n"
        )
        content = re.sub(
            r"(        - name: .+\n)",
            r"\1" + resources,
            content,
            count=1,
        )

    # CKV_K8S_43 — no imagePullPolicy
    if check_id == "CKV_K8S_43" and "imagePullPolicy" not in content:
        content = re.sub(
            r"(image:\s+\S+\n)",
            r"\1          imagePullPolicy: Always  # Bob-AutoFix\n",
            content,
        )

    return content


# ── docker-compose fixers ─────────────────────────────────────────────────
def fix_compose(content: str, check_id: str) -> str:
    # CKV_DC_1 — privileged: true
    if "CKV_DC" in check_id:
        content = content.replace("privileged: true", "privileged: false  # Bob-AutoFix")
        if "no-new-privileges" not in content:
            content = re.sub(
                r"(    \w+:\n      image:)",
                "\\1\n      security_opt:\n        - no-new-privileges:true  # Bob-AutoFix\n",
                content,
                count=1,
            )
    return content


# ── File dispatcher ────────────────────────────────────────────────────────
DOCKERFILE_RE = re.compile(r"Dockerfile(\.\w+)?$", re.IGNORECASE)
K8S_DIRS = {"k8s", "kubernetes", "manifests", "deploy", "helm", "charts"}
COMPOSE_RE = re.compile(r"docker-compose.*\.ya?ml$", re.IGNORECASE)


def dispatch(file_path: str, check_id: str) -> bool:
    p = Path(file_path)
    if not p.exists():
        return False

    content = p.read_text()
    original = content

    if DOCKERFILE_RE.search(p.name):
        content = fix_dockerfile(content, check_id)
    elif COMPOSE_RE.search(p.name):
        content = fix_compose(content, check_id)
    elif p.suffix in (".yaml", ".yml") and any(d in p.parts for d in K8S_DIRS):
        content = fix_k8s_yaml(content, check_id)
    else:
        return False

    if content != original:
        p.write_text(content)
        print(f"  🔧 [{check_id}] Fixed → {file_path}")
        return True

    return False


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    if not os.path.exists(results_file):
        print("No Checkov results file. Skipping IaC auto-fix.")
        return

    raw = json.load(open(results_file))
    # Checkov can return a list (one per framework) or a single dict
    if isinstance(raw, list):
        all_checks = []
        for r in raw:
            all_checks.extend(r.get("results", {}).get("failed_checks", []))
    else:
        all_checks = raw.get("results", {}).get("failed_checks", [])

    if not all_checks:
        print("✅ No IaC issues found.")
        return

    patched = 0
    for check in all_checks:
        check_id = check.get("check_id", "")
        file_path = check.get("file_path", "").lstrip("/")
        if dispatch(file_path, check_id):
            patched += 1

    print(f"\n✅ Bob IaC Auto-Fix complete: {patched} fixes applied")


if __name__ == "__main__":
    main()
