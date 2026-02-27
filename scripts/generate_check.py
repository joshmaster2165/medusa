#!/usr/bin/env python3
"""Scaffold generator for Medusa MCP security checks.

Reads per-category YAML manifests from ``scripts/manifests/`` and generates:
  1. ``src/medusa/checks/{category}/{id}_{slug}.py``         — stub check class
  2. ``src/medusa/checks/{category}/{id}_{slug}.metadata.yaml`` — metadata sidecar
  3. Appends test stubs to ``tests/unit/test_checks/test_{category}.py``

Usage:
    python scripts/generate_check.py --manifest scripts/manifests/tool_poisoning.yaml --write
    python scripts/generate_check.py --all --write
    python scripts/generate_check.py --all --dry-run
"""

from __future__ import annotations

import argparse
import re
import sys
import textwrap
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader

ROOT = Path(__file__).resolve().parent.parent
SRC_CHECKS = ROOT / "src" / "medusa" / "checks"
TESTS_DIR = ROOT / "tests" / "unit" / "test_checks"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
MANIFESTS_DIR = Path(__file__).resolve().parent / "manifests"


def slug_to_class(slug: str) -> str:
    """Convert snake_case slug to PascalCase class name + 'Check' suffix."""
    return "".join(word.capitalize() for word in slug.split("_")) + "Check"


def load_manifest(path: Path) -> dict:
    """Load and return a category manifest YAML."""
    return yaml.safe_load(path.read_text())


def generate_checks(manifest_path: Path, *, write: bool = False) -> list[str]:
    """Generate check files from a single manifest.  Returns list of created paths."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    check_tpl = env.get_template("check.py.j2")
    meta_tpl = env.get_template("metadata.yaml.j2")
    test_tpl = env.get_template("test_stub.py.j2")

    manifest = load_manifest(manifest_path)
    category = manifest["category"]
    created: list[str] = []

    cat_dir = SRC_CHECKS / category
    if write and not cat_dir.exists():
        cat_dir.mkdir(parents=True, exist_ok=True)
        (cat_dir / "__init__.py").touch()
        created.append(str(cat_dir / "__init__.py"))

    # Collect test stubs for this category
    test_stubs: list[str] = []
    test_imports: list[str] = []

    for entry in manifest["checks"]:
        check_id = entry["id"]
        slug = entry["slug"]
        class_name = slug_to_class(slug)
        module_name = f"{check_id}_{slug}"

        ctx = {
            "check_id": check_id,
            "slug": slug,
            "class_name": class_name,
            "title": entry["title"],
            "category": category,
            "severity": entry["severity"],
            "description": entry["description"].strip(),
            "risk_explanation": entry["risk_explanation"].strip(),
            "remediation": entry["remediation"].strip(),
            "references": entry.get("references", ["https://owasp.org/www-project-mcp-top-10/"]),
            "owasp_mcp": entry.get("owasp_mcp", []),
            "tags": entry.get("tags", [category]),
        }

        # --- Check .py ---
        py_path = cat_dir / f"{module_name}.py"
        py_content = check_tpl.render(**ctx)
        if write:
            if not py_path.exists():
                py_path.write_text(py_content)
                created.append(str(py_path))
            else:
                print(f"  SKIP (exists): {py_path.relative_to(ROOT)}")
        else:
            print(f"  [dry-run] would create: {py_path.relative_to(ROOT)}")

        # --- Metadata .yaml ---
        yaml_path = cat_dir / f"{module_name}.metadata.yaml"
        yaml_content = meta_tpl.render(**ctx)
        if write:
            if not yaml_path.exists():
                yaml_path.write_text(yaml_content)
                created.append(str(yaml_path))
            else:
                print(f"  SKIP (exists): {yaml_path.relative_to(ROOT)}")
        else:
            print(f"  [dry-run] would create: {yaml_path.relative_to(ROOT)}")

        # --- Collect test stub ---
        test_imports.append(
            f"from medusa.checks.{category}.{module_name} import {class_name}"
        )
        test_stubs.append(test_tpl.render(**ctx))

    # --- Write test file ---
    test_path = TESTS_DIR / f"test_{category}.py"
    if write:
        if not test_path.exists():
            # Create brand new test file
            imports_block = "\n".join(sorted(test_imports))
            header = (
                f'"""Unit tests for {category.replace("_", " ").title()} checks (auto-generated stubs)."""\n'
                f"\n"
                f"from __future__ import annotations\n"
                f"\n"
                f"import pytest\n"
                f"\n"
                f"{imports_block}\n"
                f"from medusa.core.models import Severity\n"
                f"from tests.conftest import make_snapshot\n"
            )
            test_path.write_text(header + "\n".join(test_stubs) + "\n")
            created.append(str(test_path))
        else:
            # Append new stubs to existing test file
            existing = test_path.read_text()
            new_imports = []
            new_stubs = []
            for imp, stub, entry in zip(test_imports, test_stubs, manifest["checks"]):
                class_name = slug_to_class(entry["slug"])
                if class_name not in existing:
                    new_imports.append(imp)
                    new_stubs.append(stub)
                else:
                    print(f"  SKIP test (exists): Test{class_name} in {test_path.name}")

            if new_imports:
                # Insert imports after the last existing import line
                lines = existing.split("\n")
                last_import_idx = 0
                for i, line in enumerate(lines):
                    if line.startswith("from ") or line.startswith("import "):
                        last_import_idx = i
                    elif line.startswith(")"):
                        # Handle multi-line imports
                        last_import_idx = i

                for imp in new_imports:
                    lines.insert(last_import_idx + 1, imp)
                    last_import_idx += 1

                updated = "\n".join(lines)
                if not updated.endswith("\n"):
                    updated += "\n"
                updated += "\n".join(new_stubs) + "\n"
                test_path.write_text(updated)
                created.append(str(test_path) + " (updated)")
    else:
        print(f"  [dry-run] would create/update: {test_path.relative_to(ROOT)}")

    return created


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Medusa check scaffolds")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--manifest", type=Path, help="Path to a single manifest YAML")
    group.add_argument("--all", action="store_true", help="Process all manifests in scripts/manifests/")
    parser.add_argument("--write", action="store_true", help="Actually write files (default is dry-run)")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be created")
    args = parser.parse_args()

    write = args.write and not args.dry_run

    if args.all:
        manifests = sorted(MANIFESTS_DIR.glob("*.yaml"))
        if not manifests:
            print(f"No manifests found in {MANIFESTS_DIR}", file=sys.stderr)
            sys.exit(1)
    else:
        manifests = [args.manifest]

    total_created = 0
    for manifest_path in manifests:
        print(f"\n{'='*60}")
        print(f"Processing: {manifest_path.name}")
        print(f"{'='*60}")
        created = generate_checks(manifest_path, write=write)
        total_created += len(created)
        for p in created:
            print(f"  ✓ {p}")

    print(f"\n{'='*60}")
    mode = "Created" if write else "Would create"
    print(f"{mode} {total_created} files total.")


if __name__ == "__main__":
    main()
