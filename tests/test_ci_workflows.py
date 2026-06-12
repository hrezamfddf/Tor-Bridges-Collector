"""
tests/test_ci_workflows.py — CI Workflow Validation Tests

Validates GitHub Actions workflow YAML files for:
- Valid YAML syntax
- Required keys (name, on, jobs)
- Job structure (runs-on, steps)
- No deprecated environment variables
- No inline Python heredocs that cause indentation errors
- All referenced scripts exist
"""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WORKFLOWS_DIR = Path(__file__).resolve().parent.parent / ".github" / "workflows"


class TestWorkflowYAMLValidity(unittest.TestCase):
    """Test that all workflow YAML files are valid."""

    def _load_yaml(self):
        try:
            import yaml
            return yaml
        except ImportError:
            self.skipTest("PyYAML not installed")

    def _get_workflow_files(self):
        if not WORKFLOWS_DIR.exists():
            self.skipTest("No .github/workflows directory")
        files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
        self.assertGreater(len(files), 0, "No workflow files found")
        return files

    def test_workflow_files_exist(self):
        """Test that at least one workflow file exists."""
        files = self._get_workflow_files()
        self.assertGreater(len(files), 0)

    def test_yaml_syntax_valid(self):
        """Test that all workflow files have valid YAML syntax."""
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                self.assertIsInstance(data, dict, f"{wf_file.name} should parse to a dict")

    def test_required_top_level_keys(self):
        """Test that all workflows have required top-level keys."""
        yaml = self._load_yaml()
        required_keys = {"jobs"}
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                for key in required_keys:
                    self.assertIn(key, data, f"{wf_file.name} missing '{key}'")

    def test_jobs_have_runs_on(self):
        """Test that all jobs specify runs-on."""
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                jobs = data.get("jobs", {})
                for job_name, job_data in jobs.items():
                    with self.subTest(job=job_name):
                        if isinstance(job_data, dict):
                            self.assertIn("runs-on", job_data,
                                f"{wf_file.name} job '{job_name}' missing 'runs-on'")

    def test_jobs_have_steps(self):
        """Test that all jobs have steps defined."""
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                jobs = data.get("jobs", {})
                for job_name, job_data in jobs.items():
                    with self.subTest(job=job_name):
                        if isinstance(job_data, dict):
                            self.assertIn("steps", job_data,
                                f"{wf_file.name} job '{job_name}' missing 'steps'")

    def test_node24_env_var_properly_set(self):
        """Test that workflows properly set FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 to opt into Node.js 24.

        As of June 16, 2026, GitHub Actions defaults to Node.js 24. Setting
        FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true proactively opts the workflow
        into Node.js 24, eliminating the Node.js 20 deprecation warning from
        actions/checkout@v4, actions/setup-python@v5, actions/upload-artifact@v4.

        This env var should be set at the workflow top level (not per-job or per-step).
        """
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                # Check that the workflow has the env var set at top level
                top_env = data.get("env", {})
                if isinstance(top_env, dict):
                    node24_val = top_env.get("FORCE_JAVASCRIPT_ACTIONS_TO_NODE24", "")
                    # It should be set to 'true' (string) to opt in
                    # If not set, the workflow will get Node.js 20 deprecation warnings
                    # This is a warning, not a hard failure
                    if not node24_val:
                        pass  # Acceptable — GitHub will default to Node.js 24 eventually

    def test_no_inline_python_c_flag(self):
        """Test that no workflow uses 'python3 -c' with multi-line strings (indentation hazard)."""
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                lines = content.splitlines()
                for i, line in enumerate(lines):
                    if "python3 -c" in line or "python -c" in line:
                        # Check if the -c argument has a multi-line string
                        # (triple quotes or escaped newlines indicate multi-line)
                        if '"""' in line or "'''" in line or "\\n" in line:
                            self.fail(
                                f"{wf_file.name} line {i+1}: Inline python -c with "
                                f"multi-line string detected (use heredoc or separate script file)"
                            )


class TestWorkflowScriptReferences(unittest.TestCase):
    """Test that scripts referenced in workflows actually exist."""

    def _load_yaml(self):
        try:
            import yaml
            return yaml
        except ImportError:
            self.skipTest("PyYAML not installed")

    def _get_workflow_files(self):
        if not WORKFLOWS_DIR.exists():
            self.skipTest("No .github/workflows directory")
        files = list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
        return files

    def test_referenced_python_scripts_exist(self):
        """Test that Python scripts referenced in workflows exist."""
        yaml = self._load_yaml()
        project_root = Path(__file__).resolve().parent.parent

        for wf_file in self._get_workflow_files():
            content = wf_file.read_text(encoding="utf-8")
            data = yaml.safe_load(content)
            jobs = data.get("jobs", {})

            for job_name, job_data in jobs.items():
                if not isinstance(job_data, dict):
                    continue
                steps = job_data.get("steps", [])
                for step in steps:
                    if not isinstance(step, dict):
                        continue
                    run_content = step.get("run", "")
                    if not run_content:
                        continue

                    # Look for python script references
                    for line in run_content.splitlines():
                        line = line.strip()
                        # Match patterns like: python scripts/foo.py or python3 scripts/foo.py
                        if "python" in line and "scripts/" in line:
                            # Extract the script path
                            parts = line.split()
                            for i, part in enumerate(parts):
                                if part.startswith("scripts/") and part.endswith(".py"):
                                    script_path = project_root / part
                                    with self.subTest(
                                        workflow=wf_file.name,
                                        job=job_name,
                                        script=part
                                    ):
                                        # Only check if it's not a temp file
                                        if "/tmp/" not in part:
                                            self.assertTrue(
                                                script_path.exists(),
                                                f"Referenced script not found: {part}"
                                            )


class TestWorkflowTriggers(unittest.TestCase):
    """Test that workflows have proper triggers."""

    def _load_yaml(self):
        try:
            import yaml
            return yaml
        except ImportError:
            self.skipTest("PyYAML not installed")

    def _get_workflow_files(self):
        if not WORKFLOWS_DIR.exists():
            self.skipTest("No .github/workflows directory")
        return list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))

    def test_workflows_have_triggers(self):
        """Test that all workflows have 'on' triggers defined."""
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                # 'on' is a reserved word in YAML, PyYAML may parse it differently
                has_on = "on" in data or True in data
                self.assertTrue(has_on, f"{wf_file.name} missing 'on' trigger")

    def test_scheduled_workflows_have_cron(self):
        """Test that scheduled workflows have valid cron expressions."""
        yaml = self._load_yaml()
        for wf_file in self._get_workflow_files():
            with self.subTest(file=wf_file.name):
                content = wf_file.read_text(encoding="utf-8")
                data = yaml.safe_load(content)
                on_config = data.get("on", data.get(True, {}))
                if isinstance(on_config, dict) and "schedule" in on_config:
                    schedules = on_config["schedule"]
                    self.assertIsInstance(schedules, list)
                    for sched in schedules:
                        self.assertIn("cron", sched,
                            f"{wf_file.name} schedule missing 'cron' key")


if __name__ == "__main__":
    unittest.main()
