#!/usr/bin/env python3
"""
security_scan.py — Security scanning for the Tor-Bridges-Collector project.

Checks for:
  - Hardcoded secrets / API keys / tokens
  - eval() / exec() usage
  - subprocess with shell=True
  - pickle.loads / pickle.load usage
  - yaml.load without SafeLoader
  - SQL injection patterns
  - Weak cryptographic algorithms
  - Insecure file permission patterns
  - Known vulnerable patterns (assert in production, etc.)

Output: JSON report to data/security_report.json

Usage:
    python3 scripts/security_scan.py
    python3 scripts/security_scan.py --project-root /path/to/project
    python3 scripts/security_scan.py --verbose
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import re
import stat
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_DATA_DIR = os.path.join(DEFAULT_PROJECT_ROOT, "data")
REPORT_FILENAME = "security_report.json"

# Severity levels
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "info"

log = logging.getLogger("security_scan")


# ---------------------------------------------------------------------------
# Pattern Definitions
# ---------------------------------------------------------------------------

# Secret patterns — look for assignments that resemble credentials
_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "hardcoded_password",
        "pattern": re.compile(
            r"""(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{3,}['"]"""
        ),
        "severity": SEVERITY_CRITICAL,
        "description": "Hardcoded password detected",
    },
    {
        "name": "hardcoded_api_key",
        "pattern": re.compile(
            r"""(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][^'"]{8,}['"]"""
        ),
        "severity": SEVERITY_CRITICAL,
        "description": "Hardcoded API key detected",
    },
    {
        "name": "hardcoded_token",
        "pattern": re.compile(
            r"""(?i)(secret[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*['"][^'"]{8,}['"]"""
        ),
        "severity": SEVERITY_CRITICAL,
        "description": "Hardcoded secret token detected",
    },
    {
        "name": "aws_key",
        "pattern": re.compile(
            r"""AKIA[0-9A-Z]{16}"""
        ),
        "severity": SEVERITY_CRITICAL,
        "description": "AWS access key ID detected",
    },
    {
        "name": "private_key_block",
        "pattern": re.compile(
            r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"""
        ),
        "severity": SEVERITY_CRITICAL,
        "description": "Private key found in source code",
    },
    {
        "name": "generic_secret_assignment",
        "pattern": re.compile(
            r"""(?i)(secret|token|key|credential)\s*[=:]\s*['"][A-Za-z0-9+/=_-]{20,}['"]"""
        ),
        "severity": SEVERITY_HIGH,
        "description": "Possible hardcoded secret (generic pattern)",
    },
]

# Dangerous function patterns (AST-based)
_DANGEROUS_AST_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "eval_usage",
        "function_names": {"eval"},
        "severity": SEVERITY_HIGH,
        "description": "Use of eval() — potential code injection risk",
    },
    {
        "name": "exec_usage",
        "function_names": {"exec"},
        "severity": SEVERITY_HIGH,
        "description": "Use of exec() — potential code injection risk",
    },
    {
        "name": "pickle_load",
        "function_names": {"loads", "load"},
        "module_patterns": {"pickle", "cPickle", "pickle5"},
        "severity": SEVERITY_HIGH,
        "description": "Use of pickle.load/loads — deserialization vulnerability",
    },
]

# Subprocess shell=True (AST-based)
_SUBPROCESS_CALLS = {"call", "run", "Popen", "check_call", "check_output"}

# Weak crypto patterns (regex on source)
_WEAK_CRYPTO_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "md5_usage",
        "pattern": re.compile(r"\bhashlib\.md5\b|\bMD5\b"),
        "severity": SEVERITY_MEDIUM,
        "description": "MD5 is cryptographically broken — avoid for security purposes",
    },
    {
        "name": "sha1_usage",
        "pattern": re.compile(r"\bhashlib\.sha1\b|\bSHA1\b"),
        "severity": SEVERITY_MEDIUM,
        "description": "SHA-1 is cryptographically weak — prefer SHA-256+",
    },
    {
        "name": "des_usage",
        "pattern": re.compile(r"\bDES\b|\bdes\b.*encrypt"),
        "severity": SEVERITY_HIGH,
        "description": "DES is insecure — use AES-256 or stronger",
    },
    {
        "name": "rc4_usage",
        "pattern": re.compile(r"\bRC4\b|\brc4\b|\bARC4\b"),
        "severity": SEVERITY_HIGH,
        "description": "RC4 is insecure — use AES-256 or stronger",
    },
    {
        "name": "ecb_mode",
        "pattern": re.compile(r"\bMODE_ECB\b"),
        "severity": SEVERITY_HIGH,
        "description": "ECB mode is insecure — use CBC, GCM, or CTR",
    },
]

# SQL injection patterns
_SQL_INJECTION_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "raw_sql_format",
        "pattern": re.compile(
            r"""(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.+?%[s]"""
        ),
        "severity": SEVERITY_HIGH,
        "description": "Possible SQL injection via string formatting",
    },
    {
        "name": "raw_sql_fstring",
        "pattern": re.compile(
            r"""(?i)(?:f['"])(?:.*)(SELECT|INSERT|UPDATE|DELETE|DROP)"""
        ),
        "severity": SEVERITY_HIGH,
        "description": "Possible SQL injection via f-string",
    },
    {
        "name": "raw_sql_concat",
        "pattern": re.compile(
            r"""(?i)(SELECT|INSERT|UPDATE|DELETE|DROP).+\+\s*['"\w]"""
        ),
        "severity": SEVERITY_MEDIUM,
        "description": "Possible SQL injection via string concatenation",
    },
]

# Other vulnerable patterns
_OTHER_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "assert_in_production",
        "pattern": re.compile(r"^\s*assert\s+", re.MULTILINE),
        "severity": SEVERITY_LOW,
        "description": "assert statements are stripped with -O flag — avoid for security checks",
    },
    {
        "name": "insecure_temp_file",
        "pattern": re.compile(
            r"""open\s*\(\s*['"]/tmp/|tempfile\.mktemp\b"""
        ),
        "severity": SEVERITY_MEDIUM,
        "description": "Insecure temporary file creation — use tempfile.mkstemp()",
    },
    {
        "name": "http_url",
        "pattern": re.compile(r"""http://[^\s'"]+"""),
        "severity": SEVERITY_LOW,
        "description": "HTTP URL found — verify HTTPS is used for sensitive data",
    },
    {
        "name": "broad_exception",
        "pattern": re.compile(r"""\bexcept\s*:"""),
        "severity": SEVERITY_LOW,
        "description": "Bare except clause — may catch unexpected exceptions",
    },
    {
        "name": "yaml_unsafe_load",
        "pattern": re.compile(r"""yaml\.load\s*\("""),
        "severity": SEVERITY_HIGH,
        "description": "yaml.load() without SafeLoader — use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
    },
]


# ---------------------------------------------------------------------------
# AST-based Security Checks
# ---------------------------------------------------------------------------

class SecurityASTVisitor(ast.NodeVisitor):
    """Walk the AST to find dangerous function calls."""

    def __init__(self, filepath: str) -> None:
        self.filepath = filepath
        self.issues: List[Dict[str, Any]] = []

    def visit_Call(self, node: ast.Call) -> None:
        self._check_eval_exec(node)
        self._check_pickle(node)
        self._check_subprocess_shell(node)
        self._check_yaml_load(node)
        self.generic_visit(node)

    def _check_eval_exec(self, node: ast.Call) -> None:
        """Check for eval() and exec() calls."""
        func_name = self._get_call_name(node)
        if func_name in ("eval", "exec"):
            self.issues.append({
                "type": func_name + "_usage",
                "file": self.filepath,
                "line": node.lineno,
                "severity": SEVERITY_HIGH,
                "description": f"Use of {func_name}() — potential code injection risk",
            })

    def _check_pickle(self, node: ast.Call) -> None:
        """Check for pickle.load/loads calls."""
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in ("load", "loads"):
                obj_name = self._get_attribute_root(node.func)
                if obj_name in ("pickle", "cPickle", "pickle5"):
                    self.issues.append({
                        "type": "pickle_load",
                        "file": self.filepath,
                        "line": node.lineno,
                        "severity": SEVERITY_HIGH,
                        "description": f"Use of {obj_name}.{method}() — deserialization vulnerability",
                    })

    def _check_subprocess_shell(self, node: ast.Call) -> None:
        """Check for subprocess calls with shell=True."""
        func_name = self._get_call_name(node)
        if func_name in _SUBPROCESS_CALLS or self._is_subprocess_call(node):
            for keyword in node.keywords:
                if keyword.arg == "shell":
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.issues.append({
                            "type": "subprocess_shell_true",
                            "file": self.filepath,
                            "line": node.lineno,
                            "severity": SEVERITY_HIGH,
                            "description": f"subprocess.{func_name or 'call'} with shell=True — shell injection risk",
                        })

    def _check_yaml_load(self, node: ast.Call) -> None:
        """Check for yaml.load() without SafeLoader."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "load":
                obj_name = self._get_attribute_root(node.func)
                if obj_name == "yaml":
                    # Check if Loader=yaml.SafeLoader is specified
                    has_safe_loader = False
                    for keyword in node.keywords:
                        if keyword.arg == "Loader":
                            loader_str = ast.dump(keyword.value)
                            if "SafeLoader" in loader_str or "FullLoader" in loader_str:
                                has_safe_loader = True
                    if not has_safe_loader:
                        self.issues.append({
                            "type": "yaml_unsafe_load",
                            "file": self.filepath,
                            "line": node.lineno,
                            "severity": SEVERITY_HIGH,
                            "description": "yaml.load() without SafeLoader — use yaml.safe_load()",
                        })

    def _is_subprocess_call(self, node: ast.Call) -> bool:
        """Check if a call is subprocess.call/run/etc."""
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in _SUBPROCESS_CALLS:
                root = self._get_attribute_root(node.func)
                if root == "subprocess":
                    return True
        return False

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        """Get the simple name of a call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return ""

    @staticmethod
    def _get_attribute_root(node: ast.Attribute) -> str:
        """Get the root name of an attribute chain (e.g. 'pickle' from 'pickle.loads')."""
        root = node
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name):
            return root.id
        return ""


# ---------------------------------------------------------------------------
# Regex-based Security Checks
# ---------------------------------------------------------------------------

def _scan_source_regex(
    source: str, filepath: str, patterns: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Scan source code with regex patterns."""
    issues: List[Dict[str, Any]] = []
    for pdef in patterns:
        for match in pdef["pattern"].finditer(source):
            lineno = source[:match.start()].count("\n") + 1
            issues.append({
                "type": pdef["name"],
                "file": filepath,
                "line": lineno,
                "severity": pdef["severity"],
                "description": pdef["description"],
                "match": match.group(0)[:120],
            })
    return issues


# ---------------------------------------------------------------------------
# File Permission Checks
# ---------------------------------------------------------------------------

def _check_file_permissions(filepath: str) -> List[Dict[str, Any]]:
    """Check for insecure file permissions."""
    issues: List[Dict[str, Any]] = []
    try:
        st = os.stat(filepath)
        mode = stat.filemode(st.st_mode)
        # Check for world-writable
        if st.st_mode & stat.S_IWOTH:
            issues.append({
                "type": "world_writable_file",
                "file": filepath,
                "severity": SEVERITY_MEDIUM,
                "description": f"File is world-writable ({mode})",
            })
        # Check for setuid/setgid
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            issues.append({
                "type": "setuid_setgid",
                "file": filepath,
                "severity": SEVERITY_HIGH,
                "description": f"File has setuid/setgid bit set ({mode})",
            })
    except OSError:
        pass
    return issues


# ---------------------------------------------------------------------------
# Shell Script Security Checks
# ---------------------------------------------------------------------------

def _check_shell_script(filepath: str, source: str) -> List[Dict[str, Any]]:
    """Basic security checks for shell scripts."""
    issues: List[Dict[str, Any]] = []

    # Check for sudo usage without specific user
    for i, line in enumerate(source.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        if re.search(r"\bsudo\s+rm\s+-rf\s+/", stripped):
            issues.append({
                "type": "dangerous_sudo_rm",
                "file": filepath,
                "line": i,
                "severity": SEVERITY_CRITICAL,
                "description": "Dangerous sudo rm -rf / pattern in shell script",
            })

        if re.search(r"\bchmod\s+777\b", stripped):
            issues.append({
                "type": "chmod_777",
                "file": filepath,
                "line": i,
                "severity": SEVERITY_MEDIUM,
                "description": "chmod 777 grants overly permissive access",
            })

        if re.search(r"\bcurl\s+.*\|\s*(ba)?sh", stripped):
            issues.append({
                "type": "curl_pipe_sh",
                "file": filepath,
                "line": i,
                "severity": SEVERITY_HIGH,
                "description": "Piping curl output to shell — potential code injection",
            })

    return issues


# ---------------------------------------------------------------------------
# Main Scanning Logic
# ---------------------------------------------------------------------------

def _find_source_files(project_root: str) -> Dict[str, List[str]]:
    """Find all source files grouped by type."""
    result: Dict[str, List[str]] = {
        "python": [],
        "shell": [],
        "go": [],
        "rust": [],
        "zig": [],
        "yaml": [],
        "other": [],
    }
    for root, dirs, files in os.walk(project_root):
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".") and d != "__pycache__"
            and d != "node_modules" and d != ".git"
        ]
        for f in sorted(files):
            full = os.path.join(root, f)
            if f.endswith(".py"):
                result["python"].append(full)
            elif f.endswith(".sh"):
                result["shell"].append(full)
            elif f.endswith(".go"):
                result["go"].append(full)
            elif f.endswith(".rs"):
                result["rust"].append(full)
            elif f.endswith(".zig"):
                result["zig"].append(full)
            elif f.endswith((".yml", ".yaml")):
                result["yaml"].append(full)
            # Skip binary / large files
            elif not f.endswith((".png", ".jpg", ".gif", ".tar.gz", ".zip", ".pdf")):
                if os.path.getsize(full) < 500_000:
                    result["other"].append(full)
    return result


def run_scan(project_root: str, verbose: bool = False) -> Dict[str, Any]:
    """Run the full security scan and return the report dict."""
    log.info("Scanning project at: %s", project_root)

    source_files = _find_source_files(project_root)
    all_issues: List[Dict[str, Any]] = []

    # ── Scan Python files ──────────────────────────────────────────────────
    py_files = source_files["python"]
    log.info("Scanning %d Python files...", len(py_files))

    for filepath in py_files:
        rel = os.path.relpath(filepath, project_root)
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("Cannot read %s: %s", rel, exc)
            continue

        # AST-based checks
        try:
            tree = ast.parse(source, filename=filepath)
            visitor = SecurityASTVisitor(rel)
            visitor.visit(tree)
            all_issues.extend(visitor.issues)
        except SyntaxError as exc:
            log.warning("Syntax error in %s: %s", rel, exc)

        # Regex-based secret patterns
        secret_issues = _scan_source_regex(source, rel, _SECRET_PATTERNS)
        all_issues.extend(secret_issues)

        # Weak crypto patterns
        crypto_issues = _scan_source_regex(source, rel, _WEAK_CRYPTO_PATTERNS)
        all_issues.extend(crypto_issues)

        # SQL injection patterns
        sql_issues = _scan_source_regex(source, rel, _SQL_INJECTION_PATTERNS)
        all_issues.extend(sql_issues)

        # Other vulnerable patterns
        other_issues = _scan_source_regex(source, rel, _OTHER_PATTERNS)
        all_issues.extend(other_issues)

        # File permission checks
        perm_issues = _check_file_permissions(filepath)
        for iss in perm_issues:
            iss["file"] = rel
        all_issues.extend(perm_issues)

    # ── Scan Shell scripts ─────────────────────────────────────────────────
    sh_files = source_files["shell"]
    log.info("Scanning %d shell scripts...", len(sh_files))

    for filepath in sh_files:
        rel = os.path.relpath(filepath, project_root)
        try:
            source = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        shell_issues = _check_shell_script(rel, source)
        all_issues.extend(shell_issues)
        perm_issues = _check_file_permissions(filepath)
        for iss in perm_issues:
            iss["file"] = rel
        all_issues.extend(perm_issues)

    # ── Scan Go/Rust/Zig for dangerous patterns ────────────────────────────
    for lang, ext in [("go", ".go"), ("rust", ".rs"), ("zig", ".zig")]:
        files = source_files.get(lang, [])
        if not files:
            continue
        log.info("Scanning %d %s files for generic patterns...", len(files), lang.upper())
        for filepath in files:
            rel = os.path.relpath(filepath, project_root)
            try:
                source = Path(filepath).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Check for hardcoded secrets in non-Python files
            secret_issues = _scan_source_regex(source, rel, _SECRET_PATTERNS)
            all_issues.extend(secret_issues)

    # ── Build summary ──────────────────────────────────────────────────────
    severity_counts: Dict[str, int] = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 0,
        SEVERITY_MEDIUM: 0,
        SEVERITY_LOW: 0,
        SEVERITY_INFO: 0,
    }
    type_counts: Dict[str, int] = {}
    for issue in all_issues:
        sev = issue.get("severity", SEVERITY_INFO)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        itype = issue.get("type", "unknown")
        type_counts[itype] = type_counts.get(itype, 0) + 1

    # Sort by severity
    severity_order = {
        SEVERITY_CRITICAL: 0,
        SEVERITY_HIGH: 1,
        SEVERITY_MEDIUM: 2,
        SEVERITY_LOW: 3,
        SEVERITY_INFO: 4,
    }
    all_issues.sort(key=lambda x: severity_order.get(x.get("severity", ""), 99))

    report = {
        "summary": {
            "total_issues": len(all_issues),
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "files_scanned": {
                "python": len(py_files),
                "shell": len(sh_files),
                "go": len(source_files["go"]),
                "rust": len(source_files["rust"]),
                "zig": len(source_files["zig"]),
                "yaml": len(source_files["yaml"]),
            },
        },
        "issues": all_issues,
    }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Security scanning for Tor-Bridges-Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Exit codes:
              0 — scan completed successfully (issues may still exist)
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
    parser.add_argument(
        "--fail-on-severity",
        choices=["critical", "high", "medium", "low"],
        default=None,
        help="Return exit code 1 if any issue at or above this severity is found",
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
        report = run_scan(project_root, verbose=args.verbose)
    except Exception:
        log.exception("Fatal error during scan")
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
    log.info("─── Security Scan Summary ───")
    log.info("  Total issues: %d", s["total_issues"])
    for sev in (SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO):
        count = s["severity_counts"].get(sev, 0)
        if count:
            log.info("  %-10s: %d", sev.upper(), count)

    # Fail on severity threshold
    if args.fail_on_severity:
        threshold = severity_order.get(args.fail_on_severity, 99)
        failing = [
            i for i in report["issues"]
            if severity_order.get(i.get("severity", ""), 99) <= threshold
        ]
        if failing:
            log.error(
                "Failing: %d issues at or above '%s' severity",
                len(failing), args.fail_on_severity,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
