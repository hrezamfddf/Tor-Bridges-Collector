#!/usr/bin/env python3
"""
validate_dependencies.py — Dependency validation for the Tor-Bridges-Collector project.

Validates:
  - Python: Parse requirements.txt, check if packages are importable,
    check version compatibility against installed versions
  - Go: Parse go.mod, check if module path is valid
  - Rust: Parse Cargo.toml, check if dependencies are present and versions valid
  - Zig: Parse build.zig, check if dependencies are present

Output: JSON report to data/dependency_report.json

Usage:
    python3 scripts/validate_dependencies.py
    python3 scripts/validate_dependencies.py --project-root /path/to/project
    python3 scripts/validate_dependencies.py --verbose
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "data")
REPORT_FILENAME = "dependency_report.json"

# Mapping of pip package names to import names (where they differ)
_PACKAGE_TO_IMPORT: Dict[str, str] = {
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "pyyaml": "yaml",
    "pycryptodome": "Crypto",
    "pillow": "PIL",
    "python-dateutil": "dateutil",
    "opencv-python": "cv2",
    "pytest-cov": "pytest_cov",
    "pytest-asyncio": "pytest_asyncio",
    "lxml": "lxml",
    "aioquic": "aioquic",
    "dpkt": "dpkt",
    "dnspython": "dns",
}

log = logging.getLogger("validate_dependencies")


# ---------------------------------------------------------------------------
# Python dependency validation
# ---------------------------------------------------------------------------

def _parse_requirements_txt(filepath: str) -> List[Dict[str, Any]]:
    """Parse requirements.txt and return list of requirement dicts."""
    requirements: List[Dict[str, Any]] = []
    try:
        content = Path(filepath).read_text(encoding="utf-8")
    except OSError as exc:
        log.error("Cannot read %s: %s", filepath, exc)
        return requirements

    for line_no, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        # Skip empty, comments, and options
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle line continuations (already handled by simple parser)
        # Handle environment markers (e.g., ; python_version >= "3.8")
        req_part = line.split(";")[0].strip()
        if not req_part:
            continue

        # Parse: package_name[extras]>=version,<version ...
        match = re.match(
            r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)"
            r"(\[.*?\])?"
            r"(.*)$",
            req_part,
        )
        if not match:
            log.warning("Cannot parse requirement line %d: %s", line_no, line)
            continue

        pkg_name = match.group(1).lower()
        extras = match.group(3) or ""
        version_spec = match.group(4).strip()

        # Parse version specifiers
        version_constraints: List[Dict[str, str]] = []
        if version_spec:
            for spec_match in re.finditer(
                r"(>=|<=|!=|==|~=|>|<)\s*([0-9][0-9A-Za-z.*+-]*)", version_spec
            ):
                version_constraints.append({
                    "op": spec_match.group(1),
                    "version": spec_match.group(2),
                })

        requirements.append({
            "name": pkg_name,
            "extras": extras,
            "version_spec": version_spec,
            "version_constraints": version_constraints,
            "line": line_no,
            "raw": line,
        })

    return requirements


def _check_python_package(req: Dict[str, Any]) -> Dict[str, Any]:
    """Check if a Python package is importable and optionally check versions."""
    pkg_name = req["name"]
    import_name = _PACKAGE_TO_IMPORT.get(pkg_name, pkg_name.replace("-", "_"))

    result: Dict[str, Any] = {
        "name": pkg_name,
        "import_name": import_name,
        "importable": False,
        "installed_version": None,
        "version_compatible": None,
        "issues": [],
    }

    # Try to import
    try:
        mod = importlib.import_module(import_name)
        result["importable"] = True

        # Try to get version
        version = None
        for attr in ("__version__", "VERSION", "version"):
            if hasattr(mod, attr):
                version = getattr(mod, attr)
                break
        # Try importlib.metadata as fallback
        if version is None:
            try:
                from importlib.metadata import version as meta_version
                version = meta_version(pkg_name)
            except Exception:
                pass

        if version:
            result["installed_version"] = str(version)

            # Check version constraints
            if req["version_constraints"]:
                compatible = _check_version_constraints(
                    str(version), req["version_constraints"]
                )
                result["version_compatible"] = compatible
                if not compatible:
                    result["issues"].append(
                        f"Version {version} does not satisfy {req['version_spec']}"
                    )
    except ImportError:
        result["importable"] = False
        result["issues"].append(f"Package {pkg_name} (import as {import_name}) is not installed")

    return result


def _check_version_constraints(
    installed: str, constraints: List[Dict[str, str]]
) -> bool:
    """Check if installed version satisfies all constraints."""
    try:
        installed_parts = _parse_version(installed)
    except (ValueError, IndexError):
        # Can't parse version — skip check
        return True

    for constraint in constraints:
        op = constraint["op"]
        required = constraint["version"]
        try:
            required_parts = _parse_version(required)
        except (ValueError, IndexError):
            continue

        if op == ">=" and installed_parts < required_parts:
            return False
        elif op == "<=" and installed_parts > required_parts:
            return False
        elif op == ">" and installed_parts <= required_parts:
            return False
        elif op == "<" and installed_parts >= required_parts:
            return False
        elif op == "==" and installed_parts[: len(required_parts)] != required_parts:
            return False
        elif op == "!=" and installed_parts[: len(required_parts)] == required_parts:
            return False
        elif op == "~=":
            # Compatible release: ~=1.4 means >=1.4, <2.0
            if installed_parts < required_parts:
                return False
            compat = list(required_parts[:-1])
            if compat:
                compat[-1] += 1
                if installed_parts[: len(compat)] >= tuple(compat):
                    return False

    return True


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a tuple of ints for comparison."""
    # Strip leading v and take only numeric parts
    v = version_str.lstrip("v")
    parts: List[int] = []
    for part in re.split(r"[.\-+]", v):
        # Extract leading digits
        m = re.match(r"(\d+)", part)
        if m:
            parts.append(int(m.group(1)))
        else:
            break
    if not parts:
        raise ValueError(f"Cannot parse version: {version_str}")
    return tuple(parts)


def validate_python_deps(project_root: str) -> Dict[str, Any]:
    """Validate Python dependencies from requirements.txt."""
    result: Dict[str, Any] = {
        "language": "python",
        "files_checked": [],
        "packages": [],
        "summary": {
            "total": 0,
            "importable": 0,
            "not_importable": 0,
            "version_mismatches": 0,
        },
    }

    # Find all requirements files
    req_files = []
    for name in ("requirements.txt", "requirements-dev.txt", "requirements-dev.in"):
        path = os.path.join(project_root, name)
        if os.path.isfile(path):
            req_files.append(path)

    # Also check subdirectories
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]
        for f in files:
            if f.startswith("requirements") and f.endswith(".txt"):
                full = os.path.join(root, f)
                if full not in req_files:
                    req_files.append(full)

    for req_file in req_files:
        rel = os.path.relpath(req_file, project_root)
        result["files_checked"].append(rel)
        log.info("Parsing %s...", rel)

        requirements = _parse_requirements_txt(req_file)
        for req in requirements:
            check = _check_python_package(req)
            check["source_file"] = rel
            check["source_line"] = req["line"]
            result["packages"].append(check)

    # Summary
    result["summary"]["total"] = len(result["packages"])
    result["summary"]["importable"] = sum(
        1 for p in result["packages"] if p["importable"]
    )
    result["summary"]["not_importable"] = sum(
        1 for p in result["packages"] if not p["importable"]
    )
    result["summary"]["version_mismatches"] = sum(
        1 for p in result["packages"] if p["version_compatible"] is False
    )

    return result


# ---------------------------------------------------------------------------
# Go dependency validation
# ---------------------------------------------------------------------------

def validate_go_deps(project_root: str) -> Dict[str, Any]:
    """Validate Go dependencies from go.mod files."""
    result: Dict[str, Any] = {
        "language": "go",
        "files_checked": [],
        "modules": [],
        "summary": {
            "total": 0,
            "valid_path": 0,
            "invalid_path": 0,
            "missing_dependencies": 0,
        },
    }

    # Find all go.mod files
    go_mod_files = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "vendor"]
        if "go.mod" in files:
            go_mod_files.append(os.path.join(root, "go.mod"))

    for mod_file in go_mod_files:
        rel = os.path.relpath(mod_file, project_root)
        result["files_checked"].append(rel)
        log.info("Parsing %s...", rel)

        try:
            content = Path(mod_file).read_text(encoding="utf-8")
        except OSError as exc:
            log.error("Cannot read %s: %s", rel, exc)
            continue

        module_path = None
        go_version = None
        require_deps: List[Dict[str, Any]] = []

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("module "):
                module_path = stripped.split(" ", 1)[1].strip()
            elif stripped.startswith("go "):
                go_version = stripped.split(" ", 1)[1].strip()
            elif stripped.startswith("require "):
                # Single-line require
                parts = stripped[len("require "):].strip()
                if "// indirect" in parts:
                    parts = parts.split("//")[0].strip()
                dep_parts = parts.split()
                if len(dep_parts) >= 2:
                    require_deps.append({
                        "path": dep_parts[0],
                        "version": dep_parts[1],
                        "indirect": "// indirect" in line,
                    })

        # Validate module path
        is_valid_path = False
        if module_path:
            # Valid patterns: github.com/..., gitlab.com/..., etc.
            is_valid_path = bool(
                re.match(
                    r"^[a-z0-9][a-z0-9.-]+\.[a-z]{2,}/.+", module_path
                )
            )

        result["modules"].append({
            "file": rel,
            "module_path": module_path,
            "go_version": go_version,
            "path_valid": is_valid_path,
            "dependencies": require_deps,
            "issues": [] if is_valid_path else [f"Invalid module path: {module_path}"],
        })

    result["summary"]["total"] = len(result["modules"])
    result["summary"]["valid_path"] = sum(
        1 for m in result["modules"] if m["path_valid"]
    )
    result["summary"]["invalid_path"] = sum(
        1 for m in result["modules"] if not m["path_valid"]
    )

    return result


# ---------------------------------------------------------------------------
# Rust dependency validation
# ---------------------------------------------------------------------------

def _parse_cargo_toml(filepath: str) -> Dict[str, Any]:
    """Parse a Cargo.toml file (basic parser, no toml library needed)."""
    result: Dict[str, Any] = {
        "file": filepath,
        "package": {},
        "dependencies": [],
        "issues": [],
    }

    try:
        content = Path(filepath).read_text(encoding="utf-8")
    except OSError as exc:
        result["issues"].append(f"Cannot read file: {exc}")
        return result

    current_section = None
    for line in content.splitlines():
        stripped = line.strip()

        # Skip comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        # Section headers
        section_match = re.match(r"^\[([^\]]+)\]", stripped)
        if section_match:
            current_section = section_match.group(1).strip()
            continue

        # Parse key = value
        kv_match = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$", stripped)
        if kv_match:
            key = kv_match.group(1)
            value = kv_match.group(2).strip()

            if current_section == "package":
                result["package"][key] = value.strip('"')

            elif current_section == "dependencies":
                dep = _parse_cargo_dep(key, value)
                result["dependencies"].append(dep)

            elif current_section and current_section.startswith("dependencies."):
                # Feature-specific dependency
                dep = _parse_cargo_dep(key, value)
                dep["target"] = current_section.split(".", 1)[1]
                result["dependencies"].append(dep)

    return result


def _parse_cargo_dep(name: str, value: str) -> Dict[str, Any]:
    """Parse a single Cargo.toml dependency entry."""
    dep: Dict[str, Any] = {
        "name": name,
        "version": None,
        "features": [],
        "optional": False,
        "issues": [],
    }

    # Simple version string: name = "1.0"
    if value.startswith('"') and value.endswith('"'):
        dep["version"] = value.strip('"')
        return dep

    # Version constraint: name = ">=1.0, <2.0"
    if re.match(r'^"[^"]+"$', value):
        dep["version"] = value.strip('"')
        return dep

    # Table form: name = { version = "1", features = ["full"] }
    table_match = re.match(r"^\{(.+)\}$", value)
    if table_match:
        table_content = table_match.group(1)
        # Parse version
        ver_match = re.search(r'version\s*=\s*"([^"]+)"', table_content)
        if ver_match:
            dep["version"] = ver_match.group(1)
        # Parse features
        feat_match = re.search(r'features\s*=\s*\[([^\]]+)\]', table_content)
        if feat_match:
            features = re.findall(r'"([^"]+)"', feat_match.group(1))
            dep["features"] = features
        # Check optional
        if "optional" in table_content:
            opt_match = re.search(r'optional\s*=\s*(true|false)', table_content)
            if opt_match:
                dep["optional"] = opt_match.group(1) == "true"

    return dep


def validate_rust_deps(project_root: str) -> Dict[str, Any]:
    """Validate Rust dependencies from Cargo.toml files."""
    result: Dict[str, Any] = {
        "language": "rust",
        "files_checked": [],
        "packages": [],
        "summary": {
            "total": 0,
            "with_version": 0,
            "without_version": 0,
            "issues": 0,
        },
    }

    # Find all Cargo.toml files
    cargo_files = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "target"]
        if "Cargo.toml" in files:
            cargo_files.append(os.path.join(root, "Cargo.toml"))

    for cargo_file in cargo_files:
        rel = os.path.relpath(cargo_file, project_root)
        result["files_checked"].append(rel)
        log.info("Parsing %s...", rel)

        parsed = _parse_cargo_toml(cargo_file)
        result["packages"].append({
            "file": rel,
            "package": parsed["package"],
            "dependencies": parsed["dependencies"],
            "issues": parsed["issues"],
        })

        # Validate each dependency
        for dep in parsed["dependencies"]:
            if not dep["version"]:
                result["summary"]["issues"] += 1
                dep["issues"].append(f"Dependency {dep['name']} has no version specified")
            else:
                # Validate version format
                ver = dep["version"]
                if not re.match(r"^[0-9]", ver) and not ver.startswith(">") and not ver.startswith("<") and not ver.startswith("=") and not ver.startswith("~") and not ver.startswith("^"):
                    dep["issues"].append(f"Unusual version specifier: {ver}")
                    result["summary"]["issues"] += 1

    result["summary"]["total"] = sum(
        len(p["dependencies"]) for p in result["packages"]
    )
    result["summary"]["with_version"] = sum(
        1 for p in result["packages"]
        for d in p["dependencies"]
        if d["version"]
    )
    result["summary"]["without_version"] = sum(
        1 for p in result["packages"]
        for d in p["dependencies"]
        if not d["version"]
    )

    return result


# ---------------------------------------------------------------------------
# Zig dependency validation
# ---------------------------------------------------------------------------

def validate_zig_deps(project_root: str) -> Dict[str, Any]:
    """Validate Zig dependencies from build.zig files."""
    result: Dict[str, Any] = {
        "language": "zig",
        "files_checked": [],
        "packages": [],
        "summary": {
            "total": 0,
            "has_dependencies": 0,
            "issues": 0,
        },
    }

    # Find all build.zig files
    zig_files = []
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "zig-cache" and d != "zig-out"]
        if "build.zig" in files:
            zig_files.append(os.path.join(root, "build.zig"))

    for zig_file in zig_files:
        rel = os.path.relpath(zig_file, project_root)
        result["files_checked"].append(rel)
        log.info("Parsing %s...", rel)

        try:
            content = Path(zig_file).read_text(encoding="utf-8")
        except OSError as exc:
            log.error("Cannot read %s: %s", rel, exc)
            continue

        # Look for dependency patterns in build.zig
        dependencies: List[Dict[str, Any]] = []
        issues: List[str] = []

        # Check for dependency() calls
        dep_matches = re.findall(
            r'b\.dependency\s*\(\s*"([^"]+)"', content
        )
        for dep_name in dep_matches:
            dependencies.append({"name": dep_name})

        # Check for addModule / @import patterns
        import_matches = re.findall(
            r'@import\s*\(\s*"([^"]+)"\s*\)', content
        )
        for imp in import_matches:
            if imp != "std" and not imp.startswith("."):
                dependencies.append({"name": imp, "type": "import"})

        # Check for build(zig) function
        has_build_fn = bool(re.search(r'pub\s+fn\s+build\s*\(', content))

        if not has_build_fn:
            issues.append("No pub fn build() found — invalid build.zig")

        # Check for linkLibC
        has_libc = "linkLibC" in content

        result["packages"].append({
            "file": rel,
            "has_build_function": has_build_fn,
            "links_libc": has_libc,
            "dependencies": dependencies,
            "issues": issues,
        })

    result["summary"]["total"] = len(result["packages"])
    result["summary"]["has_dependencies"] = sum(
        1 for p in result["packages"] if p["dependencies"]
    )
    result["summary"]["issues"] = sum(
        len(p["issues"]) for p in result["packages"]
    )

    return result


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

def run_validation(project_root: str, verbose: bool = False) -> Dict[str, Any]:
    """Run full dependency validation across all languages."""
    log.info("Validating dependencies for project at: %s", project_root)

    python_result = validate_python_deps(project_root)
    go_result = validate_go_deps(project_root)
    rust_result = validate_rust_deps(project_root)
    zig_result = validate_zig_deps(project_root)

    # Build overall summary
    total_issues = (
        python_result["summary"]["not_importable"]
        + python_result["summary"]["version_mismatches"]
        + go_result["summary"]["invalid_path"]
        + rust_result["summary"]["issues"]
        + zig_result["summary"]["issues"]
    )

    report = {
        "python": python_result,
        "go": go_result,
        "rust": rust_result,
        "zig": zig_result,
        "overall_summary": {
            "total_issues": total_issues,
            "python_packages_total": python_result["summary"]["total"],
            "python_packages_importable": python_result["summary"]["importable"],
            "python_packages_missing": python_result["summary"]["not_importable"],
            "python_version_mismatches": python_result["summary"]["version_mismatches"],
            "go_modules_valid": go_result["summary"]["valid_path"],
            "go_modules_invalid": go_result["summary"]["invalid_path"],
            "rust_deps_with_version": rust_result["summary"]["with_version"],
            "rust_deps_no_version": rust_result["summary"]["without_version"],
            "zig_packages_checked": zig_result["summary"]["total"],
        },
    }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dependency validation for Tor-Bridges-Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Exit codes:
              0 — validation completed successfully
              1 — fatal error or missing critical dependencies
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
    parser.add_argument(
        "--language",
        choices=["python", "go", "rust", "zig", "all"],
        default="all",
        help="Only validate dependencies for the specified language (default: all)",
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
        report = run_validation(project_root, verbose=args.verbose)

        # If a specific language was requested, only include that
        if args.language != "all":
            report = {args.language: report.get(args.language, {})}
    except Exception:
        log.exception("Fatal error during validation")
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
    ov = report.get("overall_summary", {})
    log.info("─── Dependency Validation Summary ───")
    if "python" in report:
        py = report["python"]["summary"]
        log.info("  Python: %d/%d importable, %d missing, %d version mismatches",
                 py["importable"], py["total"], py["not_importable"],
                 py["version_mismatches"])
    if "go" in report:
        go = report["go"]["summary"]
        log.info("  Go: %d valid modules, %d invalid", go["valid_path"], go["invalid_path"])
    if "rust" in report:
        rs = report["rust"]["summary"]
        log.info("  Rust: %d deps (%d with version, %d without)",
                 rs["total"], rs["with_version"], rs["without_version"])
    if "zig" in report:
        zg = report["zig"]["summary"]
        log.info("  Zig: %d packages checked, %d issues", zg["total"], zg["issues"])

    total_issues = ov.get("total_issues", 0)
    if total_issues > 0:
        log.warning("Total issues found: %d", total_issues)
    else:
        log.info("No dependency issues found.")

    # Return 1 if critical packages are missing
    py_missing = report.get("python", {}).get("summary", {}).get("not_importable", 0)
    if py_missing > 0:
        log.error("%d Python packages are not importable!", py_missing)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
