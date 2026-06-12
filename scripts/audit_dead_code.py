#!/usr/bin/env python3
"""
audit_dead_code.py — Dead code and duplicate code detection for the Tor-Bridges-Collector project.

Scans all .py files for:
  - Unreachable code (after return/raise/break/continue)
  - Unused imports
  - Unused variables / assignments
  - Functions / methods never called within the project
  - Duplicate / near-duplicate code blocks

Output: JSON report to data/dead_code_report.json

Usage:
    python3 scripts/audit_dead_code.py
    python3 scripts/audit_dead_code.py --project-root /path/to/project
    python3 scripts/audit_dead_code.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import logging
import os
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "data")
REPORT_FILENAME = "dead_code_report.json"

# Minimum number of AST nodes to consider a code block for duplication
MIN_BLOCK_NODES = 6
# Normalised hash similarity threshold (0-1); 1.0 = exact match
EXACT_MATCH_THRESHOLD = 1.0
NEAR_MATCH_THRESHOLD = 0.85

# Standard-library modules that are commonly side-effect imports
_SIDE_EFFECT_IMPORTS = {
    "antigravity",
    "this",
    "__future__",
    "rich",
    "logging",
}

log = logging.getLogger("audit_dead_code")


# ---------------------------------------------------------------------------
# AST Helpers
# ---------------------------------------------------------------------------

class ImportCollector(ast.NodeVisitor):
    """Collect all import names and their aliases in a module."""

    def __init__(self) -> None:
        self.imports: List[Dict[str, Any]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append({
                "name": alias.name,
                "alias": alias.asname,
                "line": node.lineno,
                "type": "import",
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.imports.append({
                "name": f"{module}.{alias.name}" if module else alias.name,
                "base": module,
                "alias": alias.asname,
                "line": node.lineno,
                "type": "from",
            })
        self.generic_visit(node)


class NameUsageCollector(ast.NodeVisitor):
    """Collect all names used (read) in the module body."""

    def __init__(self) -> None:
        self.used_names: Set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.used_names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Collect the root name in a.b.c chain
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            self.used_names.add(root.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # Decorators are used names
        for dec in node.decorator_list:
            self._collect_decorator_names(dec)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            self._collect_decorator_names(dec)
        self.generic_visit(node)

    def _collect_decorator_names(self, node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            self.used_names.add(node.id)
        elif isinstance(node, ast.Attribute):
            self.visit_Attribute(node)
        elif isinstance(node, ast.Call):
            self._collect_decorator_names(node.func)


class FunctionDefinitionCollector(ast.NodeVisitor):
    """Collect all top-level and class-level function definitions."""

    def __init__(self) -> None:
        self.functions: List[Dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append({
            "name": node.name,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", None),
            "args": [a.arg for a in node.args.args],
            "decorators": [
                self._decorator_str(d) for d in node.decorator_list
            ],
        })
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append({
            "name": node.name,
            "line": node.lineno,
            "end_line": getattr(node, "end_lineno", None),
            "args": [a.arg for a in node.args.args],
            "decorators": [
                self._decorator_str(d) for d in node.decorator_list
            ],
            "is_async": True,
        })
        self.generic_visit(node)

    @staticmethod
    def _decorator_str(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{ast.dump(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return FunctionDefinitionCollector._decorator_str(node.func) + "(...)"
        return ast.dump(node)


class FunctionCallCollector(ast.NodeVisitor):
    """Collect all function/method call names used in a module."""

    def __init__(self) -> None:
        self.called_names: Set[str] = set()

    def visit_Call(self, node: ast.Call) -> None:
        name = self._call_name(node.func)
        if name:
            self.called_names.add(name)
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return ""


class AssignmentCollector(ast.NodeVisitor):
    """Collect top-level and function-level variable assignments."""

    def __init__(self) -> None:
        self.assignments: List[Dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            names = self._extract_names(target)
            for n in names:
                self.assignments.append({
                    "name": n,
                    "line": node.lineno,
                })
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.target:
            names = self._extract_names(node.target)
            for n in names:
                self.assignments.append({
                    "name": n,
                    "line": node.lineno,
                })
        self.generic_visit(node)

    @staticmethod
    def _extract_names(node: ast.AST) -> List[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, ast.Tuple) or isinstance(node, ast.List):
            result: List[str] = []
            for elt in node.elts:
                result.extend(AssignmentCollector._extract_names(elt))
            return result
        if isinstance(node, ast.Starred):
            return AssignmentCollector._extract_names(node.value)
        return []


class UnreachableCodeDetector(ast.NodeVisitor):
    """Detect unreachable code after return/raise/break/continue."""

    def __init__(self) -> None:
        self.issues: List[Dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_body(node.body)
        self.generic_visit(node)

    def _check_body(self, stmts: List[ast.stmt]) -> None:
        terminator_types = (ast.Return, ast.Raise, ast.Break, ast.Continue)
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, terminator_types) and i < len(stmts) - 1:
                unreachable = stmts[i + 1]
                self.issues.append({
                    "type": "unreachable_code",
                    "line": getattr(unreachable, "lineno", 0),
                    "detail": f"Code after {type(stmt).__name__.lower()} on line {stmt.lineno}",
                })
            # Check inside if/for/while/try blocks as well
            if isinstance(stmt, ast.If):
                self._check_body(stmt.body)
                self._check_body(stmt.orelse)
            elif isinstance(stmt, ast.For):
                self._check_body(stmt.body)
                self._check_body(stmt.orelse)
            elif isinstance(stmt, ast.While):
                self._check_body(stmt.body)
                self._check_body(stmt.orelse)
            elif isinstance(stmt, ast.Try):
                self._check_body(stmt.body)
                for handler in stmt.handlers:
                    self._check_body(handler.body)
                self._check_body(stmt.orelse)
                self._check_body(stmt.finalbody)
            elif isinstance(stmt, ast.With):
                self._check_body(stmt.body)


# ---------------------------------------------------------------------------
# Duplicate code detection via AST hashing
# ---------------------------------------------------------------------------

def _normalize_ast(node: ast.AST) -> str:
    """Produce a normalised string representation of an AST subtree."""
    # Strip variable names and line numbers for structural comparison
    if isinstance(node, ast.Name):
        return "Name(_)"
    if isinstance(node, ast.Constant):
        return f"Const({type(node.value).__name__})"
    if isinstance(node, ast.arg):
        return "arg(_)"
    result = type(node).__name__ + "("
    children = []
    for child in ast.iter_child_nodes(node):
        children.append(_normalize_ast(child))
    if children:
        result += ",".join(children)
    result += ")"
    return result


def _ast_block_hash(stmts: List[ast.stmt]) -> str:
    """Hash a block of AST statements for duplicate detection."""
    normalized = ";".join(_normalize_ast(s) for s in stmts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _collect_code_blocks(
    tree: ast.AST, filepath: str
) -> List[Dict[str, Any]]:
    """Extract function/method bodies as code blocks for dedup."""
    blocks: List[Dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if len(node.body) < MIN_BLOCK_NODES:
                continue
            block_hash = _ast_block_hash(node.body)
            # Also compute a "loose" hash ignoring string constants
            normalized_body = []
            for stmt in node.body:
                normalized_body.append(_normalize_ast(stmt))
            blocks.append({
                "file": filepath,
                "function": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", None),
                "hash": block_hash,
                "node_count": len(node.body),
                "normalized": normalized_body,
            })

    return blocks


def _find_duplicates(
    blocks: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Find exact and near-exact duplicate code blocks."""
    hash_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for block in blocks:
        hash_groups[block["hash"]].append(block)

    duplicates: List[Dict[str, Any]] = []

    # Exact duplicates
    for h, group in hash_groups.items():
        if len(group) > 1:
            duplicates.append({
                "type": "exact_duplicate",
                "similarity": EXACT_MATCH_THRESHOLD,
                "locations": [
                    {
                        "file": b["file"],
                        "function": b["function"],
                        "line": b["line"],
                    }
                    for b in group
                ],
                "node_count": group[0]["node_count"],
            })

    # Near duplicates (structural similarity via Jaccard on normalized tokens)
    checked: Set[Tuple[str, str]] = set()
    for i, b1 in enumerate(blocks):
        for j, b2 in enumerate(blocks):
            if i >= j:
                continue
            pair_key = (b1["hash"], b2["hash"])
            if pair_key in checked:
                continue
            checked.add(pair_key)
            if b1["hash"] == b2["hash"]:
                continue  # already handled

            sim = _jaccard_similarity(b1["normalized"], b2["normalized"])
            if sim >= NEAR_MATCH_THRESHOLD:
                duplicates.append({
                    "type": "near_duplicate",
                    "similarity": round(sim, 3),
                    "locations": [
                        {
                            "file": b1["file"],
                            "function": b1["function"],
                            "line": b1["line"],
                        },
                        {
                            "file": b2["file"],
                            "function": b2["function"],
                            "line": b2["line"],
                        },
                    ],
                    "node_count": max(b1["node_count"], b2["node_count"]),
                })

    return duplicates


def _jaccard_similarity(
    tokens_a: List[str], tokens_b: List[str]
) -> float:
    """Compute Jaccard similarity between two token lists."""
    # Use n-gram (trigram) overlap for better structural comparison
    def _trigrams(tokens: List[str]) -> Set[str]:
        flat = " ".join(tokens)
        return {flat[i : i + 3] for i in range(len(flat) - 2)}

    ta = _trigrams(tokens_a)
    tb = _trigrams(tokens_b)
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _find_py_files(project_root: str) -> List[str]:
    """Recursively find all .py files, skipping hidden dirs and __pycache__."""
    py_files: List[str] = []
    for root, dirs, files in os.walk(project_root):
        # Skip hidden and cache dirs
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d != "__pycache__" and d != "node_modules"
        ]
        for f in sorted(files):
            if f.endswith(".py"):
                py_files.append(os.path.join(root, f))
    return py_files


def _parse_file(filepath: str) -> Tuple[ast.AST | None, str]:
    """Parse a Python file, returning (tree, source) or (None, source)."""
    try:
        source = Path(filepath).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("Cannot read %s: %s", filepath, exc)
        return None, ""
    try:
        tree = ast.parse(source, filename=filepath)
        return tree, source
    except SyntaxError as exc:
        log.warning("Syntax error in %s: %s", filepath, exc)
        return None, source


def analyze_unused_imports(
    tree: ast.AST, filepath: str
) -> List[Dict[str, Any]]:
    """Find imports that are never referenced in the module."""
    ic = ImportCollector()
    ic.visit(tree)
    nc = NameUsageCollector()
    nc.visit(tree)

    issues: List[Dict[str, Any]] = []
    for imp in ic.imports:
        local_name = imp.get("alias") or imp["name"].split(".")[-1]
        # Skip side-effect imports
        base = imp.get("base", imp["name"]).split(".")[0]
        if base in _SIDE_EFFECT_IMPORTS:
            continue
        # Skip relative imports (hard to resolve statically)
        if imp["type"] == "from" and imp.get("base", "").startswith("."):
            continue
        if local_name not in nc.used_names and local_name != "*":
            issues.append({
                "type": "unused_import",
                "file": filepath,
                "line": imp["line"],
                "name": imp["name"],
                "local_name": local_name,
            })
    return issues


def analyze_unused_variables(
    tree: ast.AST, filepath: str
) -> List[Dict[str, Any]]:
    """Find variables that are assigned but never read."""
    ac = AssignmentCollector()
    ac.visit(tree)
    nc = NameUsageCollector()
    nc.visit(tree)

    # Common false positives to skip
    _skip = {
        "_", "__all__", "__version__", "__doc__",
        # Dunder names typically used by import system
        "__name__", "__file__", "__package__",
    }

    issues: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for assign in ac.assignments:
        name = assign["name"]
        if name.startswith("__") and name.endswith("__"):
            continue
        if name in _skip:
            continue
        if name in nc.used_names:
            continue
        key = f"{filepath}:{name}:{assign['line']}"
        if key in seen:
            continue
        seen.add(key)
        issues.append({
            "type": "unused_variable",
            "file": filepath,
            "line": assign["line"],
            "name": name,
        })
    return issues


def analyze_unreachable_code(
    tree: ast.AST, filepath: str
) -> List[Dict[str, Any]]:
    """Find unreachable code after return/raise/break/continue."""
    ud = UnreachableCodeDetector()
    ud.visit(tree)
    return [
        {
            "type": "unreachable_code",
            "file": filepath,
            "line": issue["line"],
            "detail": issue["detail"],
        }
        for issue in ud.issues
    ]


def analyze_unused_functions(
    all_file_data: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Find functions defined but never called across the entire project.
    Excludes: __init__, main, test_*, setUp, tearDown, and
    anything decorated with @staticmethod/@classmethod/@property/@abstractmethod.
    """
    all_defined: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    all_called: Set[str] = set()

    for filepath, data in all_file_data.items():
        tree = data.get("tree")
        if tree is None:
            continue
        for func in data.get("functions", []):
            all_defined[func["name"]].append({
                "file": filepath,
                "line": func["line"],
                "decorators": func.get("decorators", []),
            })
        all_called.update(data.get("called_names", set()))

    # Whitelist of function names that are externally called
    _always_used = {
        "__init__", "__new__", "__call__", "__enter__", "__exit__",
        "__repr__", "__str__", "__len__", "__getitem__", "__setitem__",
        "__delitem__", "__iter__", "__next__", "__contains__", "__bool__",
        "__eq__", "__hash__", "__lt__", "__le__", "__gt__", "__ge__",
        "__add__", "__sub__", "__mul__", "__truediv__",
        "__aenter__", "__aexit__", "__aiter__", "__anext__",
        "main", "setup", "teardown",
    }

    issues: List[Dict[str, Any]] = []
    for name, locations in all_defined.items():
        if name in _always_used:
            continue
        if name.startswith("test_"):
            continue
        if name.startswith("_") and not name.startswith("__"):
            # Private methods may be called via self.xxx — check
            if name.lstrip("_") in all_called or name in all_called:
                continue

        # Check decorators that imply external use
        has_external_decorator = False
        for loc in locations:
            for dec in loc.get("decorators", []):
                if dec in ("staticmethod", "classmethod", "property",
                           "abstractmethod", "abstractmethod(...)"):
                    has_external_decorator = True
                    break
        if has_external_decorator:
            continue

        if name not in all_called:
            for loc in locations:
                issues.append({
                    "type": "unused_function",
                    "file": loc["file"],
                    "line": loc["line"],
                    "name": name,
                })

    return issues


def run_analysis(project_root: str, verbose: bool = False) -> Dict[str, Any]:
    """Run the full dead-code analysis and return the report dict."""
    log.info("Scanning project at: %s", project_root)

    py_files = _find_py_files(project_root)
    log.info("Found %d Python files", len(py_files))

    all_unused_imports: List[Dict[str, Any]] = []
    all_unused_vars: List[Dict[str, Any]] = []
    all_unreachable: List[Dict[str, Any]] = []
    all_blocks: List[Dict[str, Any]] = []
    all_file_data: Dict[str, Dict[str, Any]] = {}
    file_summaries: Dict[str, Dict[str, int]] = {}

    for filepath in py_files:
        tree, source = _parse_file(filepath)
        rel = os.path.relpath(filepath, project_root)

        if tree is None:
            file_summaries[rel] = {"parse_error": 1}
            all_file_data[filepath] = {"tree": None, "functions": [], "called_names": set()}
            continue

        # Collect function definitions and calls
        fc = FunctionDefinitionCollector()
        fc.visit(tree)
        cc = FunctionCallCollector()
        cc.visit(tree)

        all_file_data[filepath] = {
            "tree": tree,
            "functions": fc.functions,
            "called_names": cc.called_names,
        }

        # Per-file analyses
        imp_issues = analyze_unused_imports(tree, filepath)
        var_issues = analyze_unused_variables(tree, filepath)
        unreach_issues = analyze_unreachable_code(tree, filepath)

        all_unused_imports.extend(imp_issues)
        all_unused_vars.extend(var_issues)
        all_unreachable.extend(unreach_issues)

        # Code blocks for dedup
        blocks = _collect_code_blocks(tree, filepath)
        all_blocks.extend(blocks)

        file_summaries[rel] = {
            "unused_imports": len(imp_issues),
            "unused_variables": len(var_issues),
            "unreachable_code": len(unreach_issues),
        }

        if verbose:
            for iss in imp_issues:
                log.debug("  %s:%d unused import: %s", rel, iss["line"], iss["name"])
            for iss in var_issues:
                log.debug("  %s:%d unused var: %s", rel, iss["line"], iss["name"])

    # Cross-file: unused functions
    unused_funcs = analyze_unused_functions(all_file_data)

    # Duplicate code
    log.info("Checking %d code blocks for duplicates...", len(all_blocks))
    duplicates = _find_duplicates(all_blocks)

    # Make file paths relative in all results
    for item_list in (all_unused_imports, all_unused_vars, all_unreachable, unused_funcs):
        for item in item_list:
            if "file" in item:
                item["file"] = os.path.relpath(item["file"], project_root)

    for dup in duplicates:
        for loc in dup.get("locations", []):
            if "file" in loc:
                loc["file"] = os.path.relpath(loc["file"], project_root)

    report = {
        "summary": {
            "total_files_scanned": len(py_files),
            "files_with_parse_errors": sum(
                1 for v in file_summaries.values() if "parse_error" in v
            ),
            "unused_imports": len(all_unused_imports),
            "unused_variables": len(all_unused_vars),
            "unreachable_code_blocks": len(all_unreachable),
            "unused_functions": len(unused_funcs),
            "duplicate_code_blocks": len(duplicates),
        },
        "file_summaries": file_summaries,
        "issues": {
            "unused_imports": all_unused_imports,
            "unused_variables": all_unused_vars,
            "unreachable_code": all_unreachable,
            "unused_functions": unused_funcs,
            "duplicate_code": duplicates,
        },
    }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dead code and duplicate code detection for Tor-Bridges-Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Exit codes:
              0 — analysis completed successfully
              1 — fatal error (e.g. project root not found)
        """),
    )
    parser.add_argument(
        "--project-root",
        default=DEFAULT_PROJECT_ROOT,
        help="Path to the project root (default: auto-detected)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output JSON path (default: {{project-root}}/data/{REPORT_FILENAME})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug-level logging output",
    )
    args = parser.parse_args()

    # Logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="[%(levelname)-8s] %(name)s: %(message)s",
    )

    project_root = os.path.abspath(args.project_root)
    if not os.path.isdir(project_root):
        log.error("Project root does not exist: %s", project_root)
        return 1

    # Output path
    data_dir = os.path.join(project_root, "data")
    output_path = args.output or os.path.join(data_dir, REPORT_FILENAME)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Run
    try:
        report = run_analysis(project_root, verbose=args.verbose)
    except Exception:
        log.exception("Fatal error during analysis")
        return 1

    # Write report
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
        log.info("Report written to: %s", output_path)
    except OSError as exc:
        log.error("Cannot write report: %s", exc)
        return 1

    # Summary on console
    s = report["summary"]
    log.info("─── Dead Code Audit Summary ───")
    log.info("  Files scanned          : %d", s["total_files_scanned"])
    log.info("  Parse errors           : %d", s["files_with_parse_errors"])
    log.info("  Unused imports         : %d", s["unused_imports"])
    log.info("  Unused variables       : %d", s["unused_variables"])
    log.info("  Unreachable code blocks: %d", s["unreachable_code_blocks"])
    log.info("  Unused functions       : %d", s["unused_functions"])
    log.info("  Duplicate code blocks  : %d", s["duplicate_code_blocks"])

    return 0


if __name__ == "__main__":
    sys.exit(main())
