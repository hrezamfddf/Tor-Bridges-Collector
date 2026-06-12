#!/usr/bin/env python3
"""
Auto-Generate Architecture Documentation for Tor-Bridges-Collector.

Scans the entire project source tree, analyzes module dependencies,
class hierarchies, and data flow to produce a comprehensive
architecture document in Markdown format.

Usage:
    python scripts/generate_architecture_docs.py [--output docs/ARCHITECTURE.md]
"""

import os
import sys
import ast
import importlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple

# ── Configuration ─────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "docs" / "ARCHITECTURE.md"

# Directories to scan for Python source
SCAN_DIRS = [
    "torshield_ai_gateway",
    "core",
    "sources",
    "monitoring",
    "scripts",
    "diagnostics",
    "anti_censorship",
]

# Directories to exclude
EXCLUDE_DIRS = {"__pycache__", ".git", "vendor", "node_modules", "zig-scanner", "bridge-probe"}

SKIP_FILES = {"__init__.py", "setup.py"}


# ── AST Analysis ──────────────────────────────────────────────────────────────

def analyze_python_file(filepath: Path) -> Dict:
    """Analyze a single Python file using AST."""
    info = {
        "filepath": str(filepath),
        "classes": [],
        "functions": [],
        "imports": [],
        "docstring": None,
        "lines": 0,
    }
    try:
        source = filepath.read_text(encoding="utf-8", errors="replace")
        info["lines"] = source.count("\n") + 1
        tree = ast.parse(source, filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError):
        return info

    # Module docstring
    info["docstring"] = ast.get_docstring(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(f"{ast.dump(base)}")
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            info["classes"].append({
                "name": node.name,
                "bases": bases,
                "methods": methods,
                "docstring": ast.get_docstring(node) or "",
                "line": node.lineno,
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Only top-level functions (not class methods)
            if not any(
                isinstance(parent, ast.ClassDef)
                for parent in ast.walk(tree)
            ):
                info["functions"].append({
                    "name": node.name,
                    "line": node.lineno,
                    "docstring": ast.get_docstring(node) or "",
                })
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if isinstance(node, ast.ImportFrom) and node.module:
                info["imports"].append(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    info["imports"].append(alias.name)

    return info


def scan_project(root: Path) -> Dict[str, Dict]:
    """Scan all Python files in configured directories."""
    results = {}
    for scan_dir in SCAN_DIRS:
        dir_path = root / scan_dir
        if not dir_path.exists():
            continue
        for py_file in dir_path.rglob("*.py"):
            rel = py_file.relative_to(root)
            parts = rel.parts
            if any(p in EXCLUDE_DIRS for p in parts):
                continue
            if py_file.name in SKIP_FILES:
                continue
            info = analyze_python_file(py_file)
            results[str(rel)] = info
    # Also scan root-level Python files
    for py_file in root.glob("*.py"):
        if py_file.name in SKIP_FILES:
            continue
        info = analyze_python_file(py_file)
        results[str(py_file.name)] = info
    return results


def build_dependency_graph(results: Dict[str, Dict]) -> Dict[str, Set[str]]:
    """Build a module dependency graph from import analysis."""
    # Map file paths to module names
    path_to_module = {}
    for filepath in results:
        # Convert path like torshield_ai_gateway/providers.py -> torshield_ai_gateway.providers
        module = filepath.replace("/", ".").replace("\\", ".").replace(".py", "")
        path_to_module[filepath] = module

    module_set = set(path_to_module.values())
    graph = defaultdict(set)

    for filepath, info in results.items():
        source_module = path_to_module[filepath]
        for imp in info.get("imports", []):
            # Check if import refers to a project module
            if imp in module_set or any(imp.startswith(m + ".") for m in module_set):
                graph[source_module].add(imp)

    return dict(graph)


def count_project_stats(results: Dict[str, Dict]) -> Dict:
    """Compute aggregate project statistics."""
    stats = {
        "total_files": len(results),
        "total_lines": 0,
        "total_classes": 0,
        "total_functions": 0,
        "total_imports": 0,
        "by_directory": defaultdict(lambda: {"files": 0, "lines": 0, "classes": 0, "functions": 0}),
    }
    for filepath, info in results.items():
        parts = filepath.split("/")
        directory = "/".join(parts[:-1]) if len(parts) > 1 else "(root)"
        stats["total_lines"] += info["lines"]
        stats["total_classes"] += len(info["classes"])
        stats["total_functions"] += len(info["functions"])
        stats["total_imports"] += len(info["imports"])
        stats["by_directory"][directory]["files"] += 1
        stats["by_directory"][directory]["lines"] += info["lines"]
        stats["by_directory"][directory]["classes"] += len(info["classes"])
        stats["by_directory"][directory]["functions"] += len(info["functions"])
    return stats


def generate_markdown(
    results: Dict[str, Dict],
    dep_graph: Dict[str, Set[str]],
    stats: Dict,
) -> str:
    """Generate the architecture documentation Markdown."""
    lines = []

    # ── Title ──────────────────────────────────────────────────────────────
    lines.append("# Tor-Bridges-Collector Architecture Documentation")
    lines.append("")
    lines.append("> Auto-generated by `scripts/generate_architecture_docs.py`")
    lines.append("")

    # ── Overview ───────────────────────────────────────────────────────────
    lines.append("## 1. Project Overview")
    lines.append("")
    lines.append(
        "Tor-Bridges-Collector is a comprehensive bridge intelligence platform "
        "that collects, scores, tests, and distributes Tor bridge addresses "
        "with special emphasis on anti-censorship capabilities for Iran. "
        "The system integrates multiple AI providers (Cerebras, Cloudflare AI Gateway, "
        "Cloudflare Workers AI, Portkey) with intelligent fallback routing, "
        "circuit breakers, and a LocalAIEngine for zero-dependency degraded mode."
    )
    lines.append("")

    # ── Statistics ─────────────────────────────────────────────────────────
    lines.append("## 2. Project Statistics")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Python Files | {stats['total_files']} |")
    lines.append(f"| Total Lines | {stats['total_lines']:,} |")
    lines.append(f"| Classes | {stats['total_classes']} |")
    lines.append(f"| Functions | {stats['total_functions']} |")
    lines.append(f"| Internal Dependencies | {len(dep_graph)} |")
    lines.append("")

    # ── By Directory ───────────────────────────────────────────────────────
    lines.append("### 2.1 Code Distribution by Directory")
    lines.append("")
    lines.append("| Directory | Files | Lines | Classes | Functions |")
    lines.append("|-----------|-------|-------|---------|-----------|")
    for directory, dirstats in sorted(stats["by_directory"].items()):
        lines.append(
            f"| `{directory}/` | {dirstats['files']} | {dirstats['lines']:,} | "
            f"{dirstats['classes']} | {dirstats['functions']} |"
        )
    lines.append("")

    # ── Architecture Layers ────────────────────────────────────────────────
    lines.append("## 3. Architecture Layers")
    lines.append("")
    lines.append("The project follows a layered architecture with clear separation of concerns:")
    lines.append("")
    lines.append("```")
    lines.append("┌─────────────────────────────────────────────────────────┐")
    lines.append("│                   CI/CD Layer (GitHub Actions)          │")
    lines.append("│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ │")
    lines.append("│  │ Quality Gate │ │ Health Check │ │ Self-Healing CI  │ │")
    lines.append("│  └──────────────┘ └──────────────┘ └──────────────────┘ │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│                  Application Layer (main.py)             │")
    lines.append("│  ┌──────────┐ ┌────────────┐ ┌──────────────┐          │")
    lines.append("│  │ Scraper  │ │ Reranker   │ │ Results      │          │")
    lines.append("│  └──────────┘ └────────────┘ └──────────────┘          │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│                   AI Gateway Layer                       │")
    lines.append("│  ┌──────────────────────────────────────────────────┐   │")
    lines.append("│  │           TorShieldAIGateway (waterfall)          │   │")
    lines.append("│  │  Cerebras → CF-Gateway → CF-Workers → Portkey    │   │")
    lines.append("│  │       → LocalAIEngine (fallback)                  │   │")
    lines.append("│  └──────────────────────────────────────────────────┘   │")
    lines.append("│  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐   │")
    lines.append("│  │ Model        │ │ Circuit       │ │ Account      │   │")
    lines.append("│  │ Selector     │ │ Breaker       │ │ Rotator      │   │")
    lines.append("│  └──────────────┘ └───────────────┘ └──────────────┘   │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│              Anti-Censorship Layer (Iran)                │")
    lines.append("│  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐   │")
    lines.append("│  │ Smart Anti-  │ │ Anti-DPI v2   │ │ Auto-Defense │   │")
    lines.append("│  │ Filter v2    │ │ (AI-powered)  │ │ v3           │   │")
    lines.append("│  └──────────────┘ └───────────────┘ └──────────────┘   │")
    lines.append("│  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐   │")
    lines.append("│  │ Smart Bypass │ │ NIN Bypass    │ │ DPI Quantum  │   │")
    lines.append("│  │ Engine       │ │               │ │ Evasion      │   │")
    lines.append("│  └──────────────┘ └───────────────┘ └──────────────┘   │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│                 Core Bridge Collection Layer             │")
    lines.append("│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │")
    lines.append("│  │ Collector│ │ Formatter│ │ Scorer   │ │ Tester   │ │")
    lines.append("│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │")
    lines.append("│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │")
    lines.append("│  │ Notifier │ │ History  │ │ Iran     │ │ Censor-  │ │")
    lines.append("│  │          │ │          │ │ Detector │ │ ship Mon │ │")
    lines.append("│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│                   Data Source Layer                      │")
    lines.append("│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │")
    lines.append("│  │ BridgeDB │ │ TorProj  │ │ GitHub   │ │ Telegram │ │")
    lines.append("│  │ API      │ │ Scraper  │ │ Bridges  │ │ Bridges  │ │")
    lines.append("│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ │")
    lines.append("│  ┌──────────┐ ┌──────────┐ ┌──────────┐              │")
    lines.append("│  │ Moat     │ │ Static   │ │ Direct   │              │")
    lines.append("│  │          │ │ Bridges  │ │ Scraper  │              │")
    lines.append("│  └──────────┘ └──────────┘ └──────────┘              │")
    lines.append("├─────────────────────────────────────────────────────────┤")
    lines.append("│                 Monitoring & Observability               │")
    lines.append("│  ┌──────────────┐ ┌───────────────┐ ┌──────────────┐  │")
    lines.append("│  │ Health Check │ │ Provider      │ │ Structured   │  │")
    lines.append("│  │              │ │ Dashboard     │ │ Logging      │  │")
    lines.append("│  └──────────────┘ └───────────────┘ └──────────────┘  │")
    lines.append("└─────────────────────────────────────────────────────────┘")
    lines.append("```")
    lines.append("")

    # ── Module Details ─────────────────────────────────────────────────────
    lines.append("## 4. Module Details")
    lines.append("")

    # Group by directory
    by_dir = defaultdict(list)
    for filepath, info in sorted(results.items()):
        parts = filepath.split("/")
        directory = "/".join(parts[:-1]) if len(parts) > 1 else "(root)"
        by_dir[directory].append((filepath, info))

    for directory in sorted(by_dir.keys()):
        lines.append(f"### 4.{list(by_dir.keys()).index(directory) + 1} `{directory}/`")
        lines.append("")

        for filepath, info in by_dir[directory]:
            filename = Path(filepath).name
            lines.append(f"#### `{filename}`")
            lines.append("")

            if info["docstring"]:
                # First line of docstring as summary
                first_line = info["docstring"].split("\n")[0].strip()
                lines.append(f"**Purpose**: {first_line}")
                lines.append("")

            lines.append(f"- **Lines**: {info['lines']}")
            lines.append(f"- **Classes**: {len(info['classes'])}")
            lines.append(f"- **Functions**: {len(info['functions'])}")
            lines.append(f"- **Internal Imports**: {len(info['imports'])}")
            lines.append("")

            if info["classes"]:
                lines.append("**Classes**:")
                lines.append("")
                for cls in info["classes"]:
                    bases_str = f"({', '.join(cls['bases'])})" if cls["bases"] else ""
                    lines.append(f"- `{cls['name']}`{bases_str} — {cls['docstring'][:80] if cls['docstring'] else 'No docstring'}")
                    if cls["methods"]:
                        for m in cls["methods"][:10]:
                            lines.append(f"  - `{m}()`")
                        if len(cls["methods"]) > 10:
                            lines.append(f"  - ... and {len(cls['methods']) - 10} more methods")
                lines.append("")

    # ── Dependency Graph ───────────────────────────────────────────────────
    lines.append("## 5. Internal Dependency Graph")
    lines.append("")
    lines.append("```mermaid")
    lines.append("graph TD")

    # Create shortened names for readability
    short_names = {}
    for module in sorted(dep_graph.keys()):
        parts = module.split(".")
        if len(parts) > 2:
            short = ".".join(parts[-2:])
        else:
            short = module
        short_names[module] = short.replace(".", "_")

    for module, deps in sorted(dep_graph.items()):
        src = short_names[module]
        for dep in sorted(deps):
            if dep in short_names:
                dst = short_names[dep]
                lines.append(f"    {src} --> {dst}")

    lines.append("```")
    lines.append("")

    # ── Data Flow ──────────────────────────────────────────────────────────
    lines.append("## 6. Data Flow")
    lines.append("")
    lines.append("```")
    lines.append("Bridge Sources → Collector → Formatter → Scorer → Tester → Export")
    lines.append("                                    ↓")
    lines.append("                              Iran Scorer (if applicable)")
    lines.append("                                    ↓")
    lines.append("                            Censorship Monitor")
    lines.append("                                    ↓")
    lines.append("                          AI Gateway (analysis)")
    lines.append("                                    ↓")
    lines.append("                        Smart Bypass Engine")
    lines.append("```")
    lines.append("")

    # ── Provider Architecture ──────────────────────────────────────────────
    lines.append("## 7. AI Provider Architecture")
    lines.append("")
    lines.append("The AI Gateway uses a waterfall pattern with circuit breakers:")
    lines.append("")
    lines.append("```")
    lines.append("┌─────────────┐    ┌─────────────────┐    ┌──────────────────┐")
    lines.append("│  Cerebras   │───▶│  CF AI Gateway  │───▶│  CF Workers AI   │")
    lines.append("│  (fastest)  │    │  (cached, 11x)  │    │  (direct access) │")
    lines.append("└─────────────┘    └─────────────────┘    └──────────────────┘")
    lines.append("                                                     │")
    lines.append("                                                     ▼")
    lines.append("                           ┌─────────────┐    ┌──────────────┐")
    lines.append("                           │   Portkey   │───▶│ LocalAIEngine│")
    lines.append("                           │ (meta-router│    │  (fallback)  │")
    lines.append("                           └─────────────┘    └──────────────┘")
    lines.append("```")
    lines.append("")
    lines.append("### 7.1 Retry Strategy")
    lines.append("")
    lines.append("| HTTP Code | Category | Retry? | Rationale |")
    lines.append("|-----------|----------|--------|-----------|")
    lines.append("| 401 | Auth Failure | **NEVER** | Invalid credentials — retrying won't help |")
    lines.append("| 403 | Auth Failure | **NEVER** | Revoked permissions — requires credential rotation |")
    lines.append("| 400 | Bad Request | **NEVER** | Malformed request — model or payload is wrong |")
    lines.append("| 404 | Not Found | **NEVER** | Resource doesn't exist |")
    lines.append("| 429 | Rate Limited | **YES** | Transient — backoff and retry |")
    lines.append("| 500 | Server Error | **YES** | Transient — provider may recover |")
    lines.append("| 502 | Bad Gateway | **YES** | Transient — upstream may recover |")
    lines.append("| 503 | Unavailable | **YES** | Transient — service may recover |")
    lines.append("| 504 | Timeout | **YES** | Transient — request may succeed on retry |")
    lines.append("| 403+1010 | CF Bot | **YES** | Cloudflare bot detection is transient |")
    lines.append("")

    # ── Security ───────────────────────────────────────────────────────────
    lines.append("## 8. Security Architecture")
    lines.append("")
    lines.append("- API keys are never logged in full — all logging uses `_mask_key()`")
    lines.append("- URLs are sanitized before logging via `_mask_url()`")
    lines.append("- HTTPS is enforced for all provider endpoints")
    lines.append("- Portkey keys validated for `pk-` prefix format")
    lines.append("- Circuit breakers prevent credential exhaustion attacks")
    lines.append("- Auth failures (401/403) are NEVER retried to prevent account lockout")
    lines.append("- Dual auth strategy for Portkey (pk- keys vs provider keys)")
    lines.append("")

    return "\n".join(lines)


def main():
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[Architecture] Scanning project at {PROJECT_ROOT}...")
    results = scan_project(PROJECT_ROOT)
    print(f"[Architecture] Analyzed {len(results)} Python files")

    dep_graph = build_dependency_graph(results)
    print(f"[Architecture] Built dependency graph with {len(dep_graph)} nodes")

    stats = count_project_stats(results)
    print(f"[Architecture] {stats['total_lines']:,} lines, {stats['total_classes']} classes")

    markdown = generate_markdown(results, dep_graph, stats)

    output_path.write_text(markdown, encoding="utf-8")
    print(f"[Architecture] Documentation written to {output_path}")
    print(f"[Architecture] Size: {len(markdown):,} bytes")


if __name__ == "__main__":
    main()
