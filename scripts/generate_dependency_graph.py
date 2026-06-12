#!/usr/bin/env python3
"""
Auto-Generate Dependency Graph for Tor-Bridges-Collector.

Analyzes Python import statements across the project to build a
complete dependency graph. Outputs both Mermaid diagram code and
a textual adjacency list.

Usage:
    python scripts/generate_dependency_graph.py [--format mermaid|text|dot] [--output deps.md]
"""

import os
import sys
import ast
from pathlib import Path
from collections import defaultdict
from typing import Dict, Set, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCAN_DIRS = [
    "torshield_ai_gateway",
    "core",
    "sources",
    "monitoring",
    "scripts",
    "diagnostics",
    "anti_censorship",
]
EXCLUDE_DIRS = {"__pycache__", ".git", "vendor", "node_modules"}


def extract_imports(filepath: Path) -> Set[str]:
    """Extract all import module names from a Python file."""
    imports = set()
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError):
        return imports

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
    return imports


def scan_all_imports(root: Path) -> Dict[str, Set[str]]:
    """Scan all Python files and return file->imports mapping."""
    results = {}
    for scan_dir in SCAN_DIRS:
        dir_path = root / scan_dir
        if not dir_path.exists():
            continue
        for py_file in dir_path.rglob("*.py"):
            parts = py_file.relative_to(root).parts
            if any(p in EXCLUDE_DIRS for p in parts):
                continue
            module = str(py_file.relative_to(root)).replace("/", ".").replace("\\", ".").replace(".py", "")
            imports = extract_imports(py_file)
            results[module] = imports
    # Root-level files
    for py_file in root.glob("*.py"):
        module = py_file.stem
        imports = extract_imports(py_file)
        results[module] = imports
    return results


def build_project_deps(all_imports: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    """Filter imports to only project-internal dependencies."""
    project_modules = set(all_imports.keys())
    # Also add parent modules (e.g., torshield_ai_gateway from torshield_ai_gateway.providers)
    for m in list(project_modules):
        parts = m.split(".")
        for i in range(1, len(parts)):
            project_modules.add(".".join(parts[:i]))

    dep_graph = defaultdict(set)
    for module, imports in all_imports.items():
        for imp in imports:
            if imp in project_modules:
                dep_graph[module].add(imp)
            # Check if import is a submodule of a project module
            elif any(imp.startswith(pm + ".") for pm in project_modules):
                dep_graph[module].add(imp)
    return dict(dep_graph)


def classify_dependencies(dep_graph: Dict[str, Set[str]], all_imports: Dict[str, Set[str]]) -> Dict:
    """Classify dependencies as internal, stdlib, and third-party."""
    stdlib_modules = {
        "os", "sys", "json", "time", "logging", "random", "re", "datetime",
        "pathlib", "collections", "typing", "functools", "itertools",
        "hashlib", "base64", "struct", "io", "abc", "dataclasses",
        "urllib", "urllib.request", "urllib.error", "urllib.parse",
        "http", "http.client", "socket", "ssl", "subprocess", "shutil",
        "tempfile", "traceback", "unittest", "math", "statistics",
        "textwrap", "enum", "copy", "threading", "asyncio", "queue",
    }

    all_external = set()
    for imports in all_imports.values():
        all_external.update(imports)

    # Remove known project and stdlib
    project_modules = set(all_imports.keys())
    third_party = all_external - project_modules - stdlib_modules
    # Filter to only actual package names (first segment)
    third_party_packages = set()
    for pkg in third_party:
        if pkg and not pkg.startswith("_"):
            top_level = pkg.split(".")[0]
            third_party_packages.add(top_level)

    return {
        "internal": dep_graph,
        "third_party": sorted(third_party_packages),
        "stdlib_count": sum(1 for imp in all_external if imp in stdlib_modules),
    }


def generate_mermaid(dep_graph: Dict[str, Set[str]]) -> str:
    """Generate Mermaid diagram code."""
    lines = ["graph LR"]

    # Shorten module names for readability
    name_map = {}
    counter = 0
    for module in sorted(dep_graph.keys()):
        parts = module.split(".")
        if len(parts) > 2:
            short = ".".join(parts[-2:])
        else:
            short = module
        name_map[module] = f"M{counter}_{short.replace('.', '_')}"
        counter += 1

    for module, deps in sorted(dep_graph.items()):
        src = name_map[module]
        for dep in sorted(deps):
            if dep in name_map:
                dst = name_map[dep]
                lines.append(f"    {src} --> {dst}")

    return "\n".join(lines)


def generate_dot(dep_graph: Dict[str, Set[str]]) -> str:
    """Generate Graphviz DOT format."""
    lines = ["digraph dependencies {", '    rankdir=LR;', '    node [shape=box];']

    for module, deps in sorted(dep_graph.items()):
        src = module.replace(".", "_")
        for dep in sorted(deps):
            dst = dep.replace(".", "_")
            lines.append(f'    {src} -> {dst};')

    lines.append("}")
    return "\n".join(lines)


def generate_text(dep_graph: Dict[str, Set[str]]) -> str:
    """Generate textual adjacency list."""
    lines = ["Dependency Graph (module -> dependencies)", "=" * 50, ""]
    for module in sorted(dep_graph.keys()):
        deps = sorted(dep_graph[module])
        if deps:
            lines.append(f"{module}")
            for dep in deps:
                lines.append(f"  -> {dep}")
            lines.append("")
    return "\n".join(lines)


def main():
    fmt = "mermaid"
    output_path = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--format" and i + 1 < len(args):
            fmt = args[i + 1]
            i += 2
        elif args[i] == "--output" and i + 1 < len(args):
            output_path = Path(args[i + 1])
            i += 2
        else:
            i += 1

    print(f"[DepGraph] Scanning project at {PROJECT_ROOT}...")
    all_imports = scan_all_imports(PROJECT_ROOT)
    print(f"[DepGraph] Found {len(all_imports)} modules")

    dep_graph = build_project_deps(all_imports)
    classified = classify_dependencies(dep_graph, all_imports)
    print(f"[DepGraph] Internal dependencies: {sum(len(v) for v in dep_graph.values())}")
    print(f"[DepGraph] Third-party packages: {len(classified['third_party'])}")

    # Generate output
    if fmt == "mermaid":
        content = generate_mermaid(dep_graph)
    elif fmt == "dot":
        content = generate_dot(dep_graph)
    else:
        content = generate_text(dep_graph)

    # Add third-party listing
    content += "\n\n## Third-Party Dependencies\n\n"
    for pkg in classified["third_party"]:
        content += f"- `{pkg}`\n"

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"[DepGraph] Written to {output_path}")
    else:
        default_out = PROJECT_ROOT / "docs" / "DEPENDENCY_GRAPH.md"
        default_out.parent.mkdir(parents=True, exist_ok=True)
        default_out.write_text(content, encoding="utf-8")
        print(f"[DepGraph] Written to {default_out}")


if __name__ == "__main__":
    main()
