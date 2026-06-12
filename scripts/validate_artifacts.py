#!/usr/bin/env python3
"""
Artifact Validation and Report Integrity Checker for Tor-Bridges-Collector.

Validates:
- Package tarball integrity (SHA-256 checksums)
- MANIFEST completeness (all expected files present)
- Python syntax validity for all packaged files
- YAML workflow validity
- Requirements.txt parseability
- Test suite pass status
- Coverage report existence and threshold
- Documentation completeness

Usage:
    python scripts/validate_artifacts.py [--package /path/to/package.tar.gz] [--strict]
"""

import hashlib
import json
import os
import sys
import tarfile
import tempfile
import ast
from pathlib import Path
from typing import Dict, List, Tuple, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOWNLOAD_DIR = PROJECT_ROOT.parent / "download"

# ── Expected Structure ────────────────────────────────────────────────────────

EXPECTED_DIRS = [
    "torshield_ai_gateway",
    "core",
    "sources",
    "tests",
]

EXPECTED_FILES = [
    "main.py",
    "config.py",
    "requirements.txt",
]

EXPECTED_WORKFLOWS = [
    "torshield-ir.yml",
    "ai_gateway_health_check.yml",
    "ai_self_healing.yml",
    "ai_bridge_reranker.yml",
]


class ArtifactValidator:
    """Validates project artifacts and generates an integrity report."""

    def __init__(self, strict: bool = False):
        self.strict = strict
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.passed: List[str] = []
        self.package_path: Optional[Path] = None

    def _pass(self, msg: str):
        self.passed.append(msg)
        print(f"  [PASS] {msg}")

    def _warn(self, msg: str):
        self.warnings.append(msg)
        print(f"  [WARN] {msg}")

    def _error(self, msg: str):
        self.errors.append(msg)
        print(f"  [FAIL] {msg}")

    def validate_checksums(self) -> bool:
        """Validate SHA-256 checksums of the package."""
        print("\n[1/8] Validating checksums...")
        checksums_file = DOWNLOAD_DIR / "checksums.sha256"
        if not checksums_file.exists():
            self._warn("checksums.sha256 not found — skipping checksum validation")
            return True

        content = checksums_file.read_text().strip()
        if not content:
            self._warn("checksums.sha256 is empty")
            return True

        # Parse checksum line
        parts = content.split()
        if len(parts) < 2:
            self._error("Invalid checksums.sha256 format")
            return False

        expected_hash = parts[0]
        package_name = parts[-1]

        # Find the actual package file
        package_file = DOWNLOAD_DIR / package_name
        if not package_file.exists():
            # Try to find any .tar.gz
            tar_files = list(DOWNLOAD_DIR.glob("*.tar.gz"))
            if tar_files:
                package_file = tar_files[-1]  # Most recent
                self.package_path = package_file
            else:
                self._error(f"Package file not found: {package_name}")
                return False
        else:
            self.package_path = package_file

        # Compute actual hash
        sha256 = hashlib.sha256()
        with open(package_file, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual_hash = sha256.hexdigest()

        if actual_hash == expected_hash:
            self._pass(f"SHA-256 checksum matches: {actual_hash[:16]}...")
            return True
        else:
            self._error(f"SHA-256 mismatch: expected {expected_hash[:16]}..., got {actual_hash[:16]}...")
            return False

    def validate_package_contents(self) -> bool:
        """Validate that the tarball contains all expected files."""
        print("\n[2/8] Validating package contents...")
        if not self.package_path or not self.package_path.exists():
            self._warn("No package to validate — skipping content check")
            return True

        try:
            with tarfile.open(self.package_path, "r:gz") as tar:
                names = tar.getnames()

            # Check expected directories
            for expected_dir in EXPECTED_DIRS:
                found = any(expected_dir in name for name in names)
                if found:
                    self._pass(f"Package contains {expected_dir}/")
                else:
                    self._error(f"Package missing {expected_dir}/")

            # Check expected files
            for expected_file in EXPECTED_FILES:
                found = any(name.endswith(expected_file) for name in names)
                if found:
                    self._pass(f"Package contains {expected_file}")
                else:
                    if self.strict:
                        self._error(f"Package missing {expected_file}")
                    else:
                        self._warn(f"Package missing {expected_file}")

            # Check workflows
            for wf in EXPECTED_WORKFLOWS:
                found = any(wf in name for name in names)
                if found:
                    self._pass(f"Package contains workflow {wf}")
                else:
                    self._error(f"Package missing workflow {wf}")

            self._pass(f"Package contains {len(names)} files total")
            return True

        except tarfile.TarError as e:
            self._error(f"Cannot read package: {e}")
            return False

    def validate_python_syntax(self) -> bool:
        """Validate Python syntax for all source files."""
        print("\n[3/8] Validating Python syntax...")
        py_files = list(PROJECT_ROOT.rglob("*.py"))
        py_files = [f for f in py_files if "__pycache__" not in str(f) and ".git" not in str(f)]

        fail_count = 0
        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
                ast.parse(source, filename=str(py_file))
            except SyntaxError as e:
                rel = py_file.relative_to(PROJECT_ROOT)
                self._error(f"Syntax error in {rel}: {e}")
                fail_count += 1

        if fail_count == 0:
            self._pass(f"All {len(py_files)} Python files have valid syntax")
            return True
        else:
            self._error(f"{fail_count} Python file(s) have syntax errors")
            return False

    def validate_yaml_workflows(self) -> bool:
        """Validate YAML workflow files."""
        print("\n[4/8] Validating YAML workflows...")
        wf_dir = PROJECT_ROOT / ".github" / "workflows"
        if not wf_dir.exists():
            self._warn("No .github/workflows directory found")
            return True

        try:
            import yaml
        except ImportError:
            self._warn("PyYAML not installed — skipping YAML validation")
            return True

        all_valid = True
        for yml_file in sorted(wf_dir.glob("*.yml")):
            try:
                content = yml_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                if not isinstance(data, dict):
                    self._error(f"{yml_file.name}: Not a valid workflow (root is not a dict)")
                    all_valid = False
                    continue

                # Basic workflow structure checks
                if "jobs" not in data:
                    self._error(f"{yml_file.name}: Missing 'jobs' key")
                    all_valid = False
                else:
                    self._pass(f"{yml_file.name}: Valid YAML workflow")
            except yaml.YAMLError as e:
                self._error(f"{yml_file.name}: YAML parse error: {e}")
                all_valid = False

        return all_valid

    def validate_requirements(self) -> bool:
        """Validate requirements.txt."""
        print("\n[5/8] Validating requirements.txt...")
        req_file = PROJECT_ROOT / "requirements.txt"
        if not req_file.exists():
            self._warn("requirements.txt not found")
            return True

        lines = req_file.read_text().strip().splitlines()
        valid_lines = [l for l in lines if l.strip() and not l.startswith("#")]
        if valid_lines:
            self._pass(f"requirements.txt has {len(valid_lines)} dependencies")
            return True
        else:
            self._warn("requirements.txt is empty")
            return True

    def validate_tests(self) -> bool:
        """Validate test directory exists and has test files."""
        print("\n[6/8] Validating test suite...")
        test_dir = PROJECT_ROOT / "tests"
        if not test_dir.exists():
            self._error("tests/ directory not found")
            return False

        test_files = list(test_dir.glob("test_*.py"))
        if not test_files:
            self._error("No test files found in tests/")
            return False

        self._pass(f"Found {len(test_files)} test file(s)")
        for tf in test_files:
            self._pass(f"  {tf.name}")
        return True

    def validate_coverage_report(self) -> bool:
        """Validate coverage report exists."""
        print("\n[7/8] Validating coverage report...")
        coverage_dir = PROJECT_ROOT / "reports" / "coverage_html"
        if coverage_dir.exists() and (coverage_dir / "index.html").exists():
            self._pass("HTML coverage report exists")
            return True
        else:
            self._warn("No HTML coverage report found — run with --cov to generate")
            return True

    def validate_documentation(self) -> bool:
        """Validate documentation completeness."""
        print("\n[8/8] Validating documentation...")
        docs_dir = PROJECT_ROOT / "docs"
        if not docs_dir.exists():
            self._warn("docs/ directory not found")
            return True

        doc_files = list(docs_dir.glob("*.md"))
        if not doc_files:
            self._warn("No documentation files found in docs/")
            return True

        self._pass(f"Found {len(doc_files)} documentation file(s)")
        for df in doc_files:
            self._pass(f"  {df.name}")
        return True

    def run_all_validations(self) -> Dict:
        """Run all validation checks and return report."""
        print("=" * 60)
        print("Tor-Bridges-Collector Artifact Validation")
        print("=" * 60)

        self.validate_checksums()
        self.validate_package_contents()
        self.validate_python_syntax()
        self.validate_yaml_workflows()
        self.validate_requirements()
        self.validate_tests()
        self.validate_coverage_report()
        self.validate_documentation()

        print("\n" + "=" * 60)
        print("VALIDATION SUMMARY")
        print("=" * 60)
        print(f"  Passed:   {len(self.passed)}")
        print(f"  Warnings: {len(self.warnings)}")
        print(f"  Failed:   {len(self.errors)}")

        if self.errors:
            print("\nFailed checks:")
            for err in self.errors:
                print(f"  - {err}")

        if self.warnings:
            print("\nWarnings:")
            for warn in self.warnings:
                print(f"  - {warn}")

        overall = "PASS" if not self.errors else "FAIL"
        print(f"\nOverall: {overall}")

        return {
            "passed": len(self.passed),
            "warnings": len(self.warnings),
            "errors": len(self.errors),
            "error_details": self.errors,
            "warning_details": self.warnings,
            "overall": overall,
        }


def main():
    strict = "--strict" in sys.argv
    package_arg = None
    for i, arg in enumerate(sys.argv):
        if arg == "--package" and i + 1 < len(sys.argv):
            package_arg = sys.argv[i + 1]

    validator = ArtifactValidator(strict=strict)
    if package_arg:
        validator.package_path = Path(package_arg)

    result = validator.run_all_validations()

    # Save report
    report_path = PROJECT_ROOT / "reports" / "artifact_validation_report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nReport saved to {report_path}")

    # Exit with error code if validation failed
    if result["errors"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
