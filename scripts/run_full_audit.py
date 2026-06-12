#!/usr/bin/env python3
"""
run_full_audit.py — Master audit orchestrator for the Tor-Bridges-Collector project.

Runs all sub-audits plus additional checks:
  1. Syntax check — compile all .py files
  2. Dead code audit (audit_dead_code.py)
  3. Security scan (security_scan.py)
  4. Dependency validation (validate_dependencies.py)
  5. YAML validation
  6. Test runner with coverage (pytest)

Generates a comprehensive master report to data/full_audit_report.json
with timestamp, environment info, and summary statistics.

Usage:
    python3 scripts/run_full_audit.py
    python3 scripts/run_full_audit.py --skip-tests
    python3 scripts/run_full_audit.py --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "data")
REPORT_FILENAME = "full_audit_report.json"

log = logging.getLogger("full_audit")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _timestamp() -> str:
    """Return ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _env_info() -> Dict[str, Any]:
    """Collect environment information."""
    info: Dict[str, Any] = {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "architecture": platform.architecture(),
        "processor": platform.processor(),
        "hostname": platform.node(),
        "os_name": os.name,
        "cwd": os.getcwd(),
    }

    # Git info
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            info["git_commit"] = result.stdout.strip()
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            info["git_branch"] = result.stdout.strip()
    except Exception:
        pass

    try:
        result = subprocess.run(
            ["git", "diff", "--stat"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            info["git_dirty"] = bool(result.stdout.strip())
    except Exception:
        pass

    return info


# ---------------------------------------------------------------------------
# Step 1: Syntax check
# ---------------------------------------------------------------------------

def run_syntax_check(project_root: str) -> Dict[str, Any]:
    """Compile-check all Python files."""
    log.info("━━ Step 1: Syntax check ━━")
    results: Dict[str, Any] = {
        "status": "ok",
        "total_files": 0,
        "syntax_errors": [],
    }

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d != "__pycache__" and d != "node_modules"
        ]
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            filepath = os.path.join(root, f)
            rel = os.path.relpath(filepath, project_root)
            results["total_files"] += 1

            try:
                source = Path(filepath).read_text(encoding="utf-8", errors="replace")
                compile(source, filepath, "exec")
            except SyntaxError as exc:
                results["syntax_errors"].append({
                    "file": rel,
                    "line": exc.lineno,
                    "message": str(exc.msg),
                })
                log.warning("  ✗ %s:%s — %s", rel, exc.lineno, exc.msg)

    if results["syntax_errors"]:
        results["status"] = "failed"
        log.error("  Syntax errors: %d / %d files", len(results["syntax_errors"]), results["total_files"])
    else:
        log.info("  All %d Python files pass syntax check ✓", results["total_files"])

    return results


# ---------------------------------------------------------------------------
# Step 2: Dead code audit
# ---------------------------------------------------------------------------

def run_dead_code_audit(project_root: str) -> Dict[str, Any]:
    """Run the dead code audit script."""
    log.info("━━ Step 2: Dead code audit ━━")
    script = os.path.join(os.path.dirname(__file__), "audit_dead_code.py")
    report_path = os.path.join(project_root, "data", "dead_code_report.json")

    if not os.path.isfile(script):
        log.error("  audit_dead_code.py not found at %s", script)
        return {"status": "skipped", "reason": "script not found"}

    try:
        result = subprocess.run(
            [sys.executable, script, "--project-root", project_root],
            capture_output=True, text=True, timeout=300,
        )
        if os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as fp:
                report = json.load(fp)
            report["status"] = "ok" if result.returncode == 0 else "warning"
            summary = report.get("summary", {})
            log.info(
                "  Unused imports: %d | Unused vars: %d | Unreachable: %d | Unused funcs: %d | Duplicates: %d",
                summary.get("unused_imports", 0),
                summary.get("unused_variables", 0),
                summary.get("unreachable_code_blocks", 0),
                summary.get("unused_functions", 0),
                summary.get("duplicate_code_blocks", 0),
            )
            return report
        else:
            log.error("  Dead code report not generated")
            return {
                "status": "error",
                "returncode": result.returncode,
                "stderr": result.stderr[-500:] if result.stderr else "",
            }
    except subprocess.TimeoutExpired:
        log.error("  Dead code audit timed out")
        return {"status": "timeout"}
    except Exception as exc:
        log.error("  Dead code audit failed: %s", exc)
        return {"status": "error", "reason": str(exc)}


# ---------------------------------------------------------------------------
# Step 3: Security scan
# ---------------------------------------------------------------------------

def run_security_scan(project_root: str) -> Dict[str, Any]:
    """Run the security scan script."""
    log.info("━━ Step 3: Security scan ━━")
    script = os.path.join(os.path.dirname(__file__), "security_scan.py")
    report_path = os.path.join(project_root, "data", "security_report.json")

    if not os.path.isfile(script):
        log.error("  security_scan.py not found at %s", script)
        return {"status": "skipped", "reason": "script not found"}

    try:
        result = subprocess.run(
            [sys.executable, script, "--project-root", project_root],
            capture_output=True, text=True, timeout=300,
        )
        if os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as fp:
                report = json.load(fp)
            report["status"] = "ok" if result.returncode == 0 else "warning"
            summary = report.get("summary", {})
            sev = summary.get("severity_counts", {})
            log.info(
                "  Critical: %d | High: %d | Medium: %d | Low: %d",
                sev.get("critical", 0), sev.get("high", 0),
                sev.get("medium", 0), sev.get("low", 0),
            )
            return report
        else:
            log.error("  Security report not generated")
            return {
                "status": "error",
                "returncode": result.returncode,
                "stderr": result.stderr[-500:] if result.stderr else "",
            }
    except subprocess.TimeoutExpired:
        log.error("  Security scan timed out")
        return {"status": "timeout"}
    except Exception as exc:
        log.error("  Security scan failed: %s", exc)
        return {"status": "error", "reason": str(exc)}


# ---------------------------------------------------------------------------
# Step 4: Dependency validation
# ---------------------------------------------------------------------------

def run_dependency_validation(project_root: str) -> Dict[str, Any]:
    """Run the dependency validation script."""
    log.info("━━ Step 4: Dependency validation ━━")
    script = os.path.join(os.path.dirname(__file__), "validate_dependencies.py")
    report_path = os.path.join(project_root, "data", "dependency_report.json")

    if not os.path.isfile(script):
        log.error("  validate_dependencies.py not found at %s", script)
        return {"status": "skipped", "reason": "script not found"}

    try:
        result = subprocess.run(
            [sys.executable, script, "--project-root", project_root],
            capture_output=True, text=True, timeout=120,
        )
        if os.path.isfile(report_path):
            with open(report_path, "r", encoding="utf-8") as fp:
                report = json.load(fp)
            report["status"] = "ok" if result.returncode == 0 else "warning"
            ov = report.get("overall_summary", {})
            log.info(
                "  Python: %d/%d importable | Go: %d valid | Rust: %d deps | Zig: %d pkgs",
                ov.get("python_packages_importable", 0),
                ov.get("python_packages_total", 0),
                ov.get("go_modules_valid", 0),
                ov.get("rust_deps_with_version", 0),
                ov.get("zig_packages_checked", 0),
            )
            return report
        else:
            log.error("  Dependency report not generated")
            return {
                "status": "error",
                "returncode": result.returncode,
                "stderr": result.stderr[-500:] if result.stderr else "",
            }
    except subprocess.TimeoutExpired:
        log.error("  Dependency validation timed out")
        return {"status": "timeout"}
    except Exception as exc:
        log.error("  Dependency validation failed: %s", exc)
        return {"status": "error", "reason": str(exc)}


# ---------------------------------------------------------------------------
# Step 5: YAML validation
# ---------------------------------------------------------------------------

def run_yaml_validation(project_root: str) -> Dict[str, Any]:
    """Validate all YAML files in the project."""
    log.info("━━ Step 5: YAML validation ━━")
    results: Dict[str, Any] = {
        "status": "ok",
        "total_files": 0,
        "errors": [],
    }

    # Try to import yaml
    try:
        import yaml
    except ImportError:
        # Fall back to basic structural check
        log.warning("  PyYAML not installed — using basic YAML validation")
        yaml = None

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d != "__pycache__" and d != "node_modules"
        ]
        for f in sorted(files):
            if not f.endswith((".yml", ".yaml")):
                continue
            filepath = os.path.join(root, f)
            rel = os.path.relpath(filepath, project_root)
            results["total_files"] += 1

            try:
                content = Path(filepath).read_text(encoding="utf-8", errors="replace")
                if yaml:
                    yaml.safe_load(content)
                else:
                    # Basic check: look for common YAML errors
                    _basic_yaml_check(content, rel, results)
            except yaml.YAMLError as exc:
                results["errors"].append({
                    "file": rel,
                    "message": str(exc),
                })
                log.warning("  ✗ %s — %s", rel, exc)
            except OSError as exc:
                results["errors"].append({
                    "file": rel,
                    "message": f"Cannot read: {exc}",
                })

    if results["errors"]:
        results["status"] = "failed"
        log.error("  YAML errors: %d / %d files", len(results["errors"]), results["total_files"])
    else:
        log.info("  All %d YAML files valid ✓", results["total_files"])

    return results


def _basic_yaml_check(content: str, rel: str, results: Dict[str, Any]) -> None:
    """Basic YAML structural checks without PyYAML."""
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        # Check for tabs (YAML forbids tabs for indentation)
        if line.startswith("\t") or (line.startswith(" ") and "\t" in line[: len(line) - len(line.lstrip())]):
            results["errors"].append({
                "file": rel,
                "line": i,
                "message": "YAML forbids tabs for indentation",
            })
            break


# ---------------------------------------------------------------------------
# Step 6: Test runner with coverage
# ---------------------------------------------------------------------------

def run_tests(project_root: str) -> Dict[str, Any]:
    """Run pytest with coverage if available."""
    log.info("━━ Step 6: Test runner ━━")
    results: Dict[str, Any] = {
        "status": "skipped",
        "tests_run": 0,
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "coverage_percent": None,
    }

    # Check if pytest is available
    try:
        version_result = subprocess.run(
            [sys.executable, "-m", "pytest", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        if version_result.returncode != 0:
            log.warning("  pytest not available")
            return results
    except Exception:
        log.warning("  pytest not available")
        return results

    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest",
        "--tb=short",
        "-q",
    ]

    # Try coverage
    try:
        cov_check = subprocess.run(
            [sys.executable, "-c", "import pytest_cov"],
            capture_output=True, timeout=5,
        )
        if cov_check.returncode == 0:
            cmd.extend(["--cov=" + project_root, "--cov-report=term-missing", "--cov-report=json"])
    except Exception:
        pass

    log.info("  Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True, text=True, timeout=600,
        )

        results["returncode"] = result.returncode
        results["stdout"] = result.stdout[-2000:] if result.stdout else ""
        results["stderr"] = result.stderr[-2000:] if result.stderr else ""

        # Parse pytest output for summary
        output = result.stdout + result.stderr

        # Look for summary line: "X passed, Y failed, Z errors"
        summary_match = __import__("re").search(
            r"(\d+) passed(?:, (\d+) failed)?(?:, (\d+) errors)?", output
        )
        if summary_match:
            results["passed"] = int(summary_match.group(1) or 0)
            results["failed"] = int(summary_match.group(2) or 0)
            results["errors"] = int(summary_match.group(3) or 0)
            results["tests_run"] = results["passed"] + results["failed"] + results["errors"]

        # Look for coverage percentage
        cov_match = __import__("re").search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", output)
        if cov_match:
            results["coverage_percent"] = int(cov_match.group(1))

        # Check for coverage JSON file
        cov_json = os.path.join(project_root, "coverage.json")
        if os.path.isfile(cov_json):
            try:
                with open(cov_json, "r") as fp:
                    cov_data = json.load(fp)
                totals = cov_data.get("totals", {})
                if "percent_covered" in totals:
                    results["coverage_percent"] = round(totals["percent_covered"], 1)
            except Exception:
                pass

        if result.returncode == 0:
            results["status"] = "ok"
            log.info("  Tests: %d passed ✓", results["passed"])
        else:
            results["status"] = "failed"
            log.error("  Tests: %d passed, %d failed, %d errors",
                      results["passed"], results["failed"], results["errors"])

        if results["coverage_percent"] is not None:
            log.info("  Coverage: %s%%", results["coverage_percent"])

    except subprocess.TimeoutExpired:
        log.error("  Test runner timed out")
        results["status"] = "timeout"
    except Exception as exc:
        log.error("  Test runner failed: %s", exc)
        results["status"] = "error"
        results["reason"] = str(exc)

    return results


# ---------------------------------------------------------------------------
# Master audit
# ---------------------------------------------------------------------------

def run_full_audit(
    project_root: str,
    skip_tests: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Run the full audit pipeline."""
    start_time = time.monotonic()

    log.info("=" * 60)
    log.info("Tor-Bridges-Collector — Full Audit")
    log.info("Project root: %s", project_root)
    log.info("Timestamp: %s", _timestamp())
    log.info("=" * 60)

    # Ensure data directory exists
    data_dir = os.path.join(project_root, "data")
    os.makedirs(data_dir, exist_ok=True)

    # Run each step
    syntax_result = run_syntax_check(project_root)
    dead_code_result = run_dead_code_audit(project_root)
    security_result = run_security_scan(project_root)
    dependency_result = run_dependency_validation(project_root)
    yaml_result = run_yaml_validation(project_root)
    test_result = {"status": "skipped"} if skip_tests else run_tests(project_root)

    elapsed = time.monotonic() - start_time

    # Build summary
    steps = {
        "syntax_check": syntax_result.get("status", "unknown"),
        "dead_code_audit": dead_code_result.get("status", "unknown"),
        "security_scan": security_result.get("status", "unknown"),
        "dependency_validation": dependency_result.get("status", "unknown"),
        "yaml_validation": yaml_result.get("status", "unknown"),
        "test_runner": test_result.get("status", "unknown"),
    }

    # Determine overall status
    failed_steps = [k for k, v in steps.items() if v in ("failed", "error", "timeout")]
    warning_steps = [k for k, v in steps.items() if v == "warning"]
    overall_status = "ok"
    if failed_steps:
        overall_status = "failed"
    elif warning_steps:
        overall_status = "warning"

    # Aggregate statistics
    summary_stats = {
        "syntax_errors": len(syntax_result.get("syntax_errors", [])),
        "python_files_checked": syntax_result.get("total_files", 0),
        "dead_code": {
            "unused_imports": dead_code_result.get("summary", {}).get("unused_imports", 0),
            "unused_variables": dead_code_result.get("summary", {}).get("unused_variables", 0),
            "unreachable_code": dead_code_result.get("summary", {}).get("unreachable_code_blocks", 0),
            "unused_functions": dead_code_result.get("summary", {}).get("unused_functions", 0),
            "duplicate_code": dead_code_result.get("summary", {}).get("duplicate_code_blocks", 0),
        },
        "security": {
            "total_issues": security_result.get("summary", {}).get("total_issues", 0),
            "critical": security_result.get("summary", {}).get("severity_counts", {}).get("critical", 0),
            "high": security_result.get("summary", {}).get("severity_counts", {}).get("high", 0),
            "medium": security_result.get("summary", {}).get("severity_counts", {}).get("medium", 0),
            "low": security_result.get("summary", {}).get("severity_counts", {}).get("low", 0),
        },
        "dependencies": {
            "python_missing": dependency_result.get("overall_summary", {}).get("python_packages_missing", 0),
            "python_version_mismatches": dependency_result.get("overall_summary", {}).get("python_version_mismatches", 0),
        },
        "yaml_errors": len(yaml_result.get("errors", [])),
        "tests": {
            "run": test_result.get("tests_run", 0),
            "passed": test_result.get("passed", 0),
            "failed": test_result.get("failed", 0),
            "coverage_percent": test_result.get("coverage_percent"),
        },
    }

    report = {
        "audit_timestamp": _timestamp(),
        "elapsed_seconds": round(elapsed, 2),
        "overall_status": overall_status,
        "environment": _env_info(),
        "steps": steps,
        "summary_statistics": summary_stats,
        "results": {
            "syntax_check": syntax_result,
            "dead_code_audit": dead_code_result,
            "security_scan": security_result,
            "dependency_validation": dependency_result,
            "yaml_validation": yaml_result,
            "test_runner": test_result,
        },
    }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Master audit orchestrator for Tor-Bridges-Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Exit codes:
              0 — audit completed, no critical issues
              1 — audit completed with critical issues or fatal error

            Individual sub-audit reports are saved alongside the master report
            in the data/ directory.
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
        "--skip-tests",
        action="store_true",
        help="Skip the pytest step (useful when tests are slow or broken)",
    )
    parser.add_argument(
        "--step",
        choices=["syntax", "dead-code", "security", "deps", "yaml", "tests"],
        action="append",
        help="Run only specific step(s); may be repeated. Default: all steps",
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
        report = run_full_audit(
            project_root,
            skip_tests=args.skip_tests or (args.step is not None and "tests" not in (args.step or [])),
            verbose=args.verbose,
        )
    except Exception:
        log.exception("Fatal error during full audit")
        return 1

    # Write report
    try:
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2, ensure_ascii=False)
        log.info("Master report written to: %s", output_path)
    except OSError as exc:
        log.error("Cannot write master report: %s", exc)
        return 1

    # Final summary
    log.info("=" * 60)
    log.info("FULL AUDIT COMPLETE")
    log.info("  Overall status : %s", report["overall_status"].upper())
    log.info("  Elapsed        : %.2f seconds", report["elapsed_seconds"])
    log.info("  ── Steps ──")
    for step_name, step_status in report["steps"].items():
        icon = "✓" if step_status == "ok" else ("⚠" if step_status in ("warning", "skipped") else "✗")
        log.info("    %s  %-25s %s", icon, step_name, step_status)

    stats = report["summary_statistics"]
    log.info("  ── Key Findings ──")
    log.info("    Syntax errors       : %d", stats["syntax_errors"])
    log.info("    Unused imports      : %d", stats["dead_code"]["unused_imports"])
    log.info("    Unused functions    : %d", stats["dead_code"]["unused_functions"])
    log.info("    Duplicate code      : %d", stats["dead_code"]["duplicate_code"])
    log.info("    Security critical   : %d", stats["security"]["critical"])
    log.info("    Security high       : %d", stats["security"]["high"])
    log.info("    Missing Python deps : %d", stats["dependencies"]["python_missing"])
    log.info("    YAML errors         : %d", stats["yaml_errors"])
    if stats["tests"]["run"] > 0:
        log.info("    Tests passed/total  : %d/%d", stats["tests"]["passed"], stats["tests"]["run"])
        if stats["tests"]["coverage_percent"] is not None:
            log.info("    Coverage            : %s%%", stats["tests"]["coverage_percent"])

    log.info("=" * 60)

    # Return code
    if report["overall_status"] == "failed":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
