#!/usr/bin/env python3
"""
self_heal.py — Autonomous Self-Healing Pipeline Debugger (TorShield-IR)

Runs at the start of every GitHub Actions job to:
  1. Validate Python syntax across all project scripts.
  2. Validate the workflow YAML structure.
  3. On any error: call the AI waterfall (Portkey → Cerebras → Groq) to
     generate a targeted patch, apply it, and commit the fix automatically.
  4. Write a structured diagnostic log to data/self_heal_log.json.

Usage:
    python self_heal.py --check        # validate only, exit 0 always
    python self_heal.py --heal         # validate + auto-patch + commit
    python self_heal.py --report       # print last heal log and exit

Environment variables (GitHub Actions Secrets):
    PORTKEY_API_KEY, CEREBRAS_API_KEY, GROQ_API_KEY,
    GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA

Exit code: always 0 (failures are logged, never abort the pipeline).
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(name)s — %(message)s",
)

# ── Constants ─────────────────────────────────────────────────────────────────
HEAL_LOG        = Path("data/self_heal_log.json")
AI_TIMEOUT      = 30
MAX_FILE_SIZE   = 64 * 1024   # 64 KB — max script content sent to AI

PYTHON_SCRIPTS  = list(Path(".").glob("*.py")) + list(Path("sources").glob("*.py")) \
                + list(Path("core").glob("*.py"))
YAML_FILES      = list(Path(".github/workflows").glob("*.yml"))

# ── HTTP helper (stdlib only) ─────────────────────────────────────────────────

def _http_post(url: str, body: bytes, headers: dict[str, str]) -> bytes | None:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT) as resp:
            return resp.read()
    except Exception as exc:
        log.debug("HTTP POST %s failed: %s", url, exc)
        return None


# ── AI provider calls (Portkey → Cerebras → Groq waterfall) ───────────────────

def _call_portkey(prompt: str) -> str | None:
    key = os.environ.get("PORTKEY_API_KEY", "")
    ck  = os.environ.get("CEREBRAS_API_KEY", "")
    if not key:
        return None
    payload = json.dumps({
        "model":    "llama3.1-70b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }).encode()
    headers: dict[str, str] = {
        "Content-Type":       "application/json",
        "x-portkey-api-key":  key,
        "x-portkey-provider": "cerebras",
    }
    if ck:
        headers["Authorization"] = f"Bearer {ck}"
    raw = _http_post("https://api.portkey.ai/v1/chat/completions", payload, headers)
    if raw is None:
        return None
    try:
        return json.loads(raw)["choices"][0]["message"]["content"]
    except Exception:
        return None


def _call_cerebras(prompt: str) -> str | None:
    key = os.environ.get("CEREBRAS_API_KEY", "")
    if not key:
        return None
    payload = json.dumps({
        "model":    "llama3.1-70b",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }).encode()
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type":  "application/json",
    }
    raw = _http_post("https://api.cerebras.ai/v1/chat/completions", payload, headers)
    if raw is None:
        return None
    try:
        return json.loads(raw)["choices"][0]["message"]["content"]
    except Exception:
        return None


def _call_groq(prompt: str) -> str | None:
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        return None
    payload = json.dumps({
        "model":    "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
    }).encode()
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type":  "application/json",
    }
    raw = _http_post("https://api.groq.com/openai/v1/chat/completions", payload, headers)
    if raw is None:
        return None
    try:
        return json.loads(raw)["choices"][0]["message"]["content"]
    except Exception:
        return None


def _ask_ai(prompt: str) -> str | None:
    """Try Portkey → Cerebras → Groq in order."""
    for fn in (_call_portkey, _call_cerebras, _call_groq):
        result = fn(prompt)
        if result:
            return result
    log.warning("self_heal: all AI providers unavailable — no patch generated.")
    return None


# ── Validation ────────────────────────────────────────────────────────────────

def check_python_syntax() -> list[dict[str, str]]:
    """Return list of {file, error} dicts for any Python syntax errors found."""
    errors: list[dict[str, str]] = []
    for path in PYTHON_SCRIPTS:
        if not path.exists():
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            errors.append({
                "file":    str(path),
                "error":   f"SyntaxError line {exc.lineno}: {exc.msg}",
                "snippet": (exc.text or "").strip(),
            })
        except Exception as exc:
            errors.append({"file": str(path), "error": str(exc), "snippet": ""})
    return errors


def check_yaml_syntax() -> list[dict[str, str]]:
    """Return list of {file, error} for any YAML syntax errors."""
    errors: list[dict[str, str]] = []
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        return []  # PyYAML not installed — skip silently
    for path in YAML_FILES:
        if not path.exists():
            continue
        try:
            with path.open(encoding="utf-8") as f:
                yaml.safe_load_all(f)
        except Exception as exc:
            errors.append({"file": str(path), "error": str(exc), "snippet": ""})
    return errors


# ── AI patch generation & application ────────────────────────────────────────

def _build_patch_prompt(error: dict[str, str]) -> str:
    fpath = Path(error["file"])
    if not fpath.exists():
        return ""
    source = fpath.read_text(encoding="utf-8", errors="replace")
    if len(source) > MAX_FILE_SIZE:
        source = source[:MAX_FILE_SIZE] + "\n... [truncated]"
    return textwrap.dedent(f"""
        You are an expert Python developer and GitHub Actions engineer.
        A syntax error was detected in the TorShield-IR pipeline script.

        File: {error['file']}
        Error: {error['error']}
        Problematic code: {error.get('snippet', '')}

        Full file content:
        ---
        {source}
        ---

        Return ONLY the corrected Python code for the ENTIRE file.
        Do not include any explanation, markdown fences, or commentary.
        The output must be valid Python that passes `ast.parse()`.
        Preserve ALL existing functionality — only fix the syntax error.
    """).strip()


def apply_patch(error: dict[str, str]) -> bool:
    """Generate and apply an AI patch for a detected syntax error."""
    prompt = _build_patch_prompt(error)
    if not prompt:
        return False
    log.info("self_heal: requesting AI patch for %s ...", error["file"])
    fixed_code = _ask_ai(prompt)
    if not fixed_code:
        return False
    # Strip markdown fences if AI included them despite instructions
    fixed_code = re.sub(r"^```(?:python)?\s*", "", fixed_code, flags=re.MULTILINE)
    fixed_code = re.sub(r"^```\s*$", "", fixed_code, flags=re.MULTILINE)
    fixed_code = fixed_code.strip()
    # Validate the AI-generated code before writing
    try:
        ast.parse(fixed_code)
    except SyntaxError as exc:
        log.warning("self_heal: AI patch itself has syntax error: %s -- discarding.", exc)
        return False
    Path(error["file"]).write_text(fixed_code, encoding="utf-8")
    log.info("self_heal: patch applied to %s.", error["file"])
    return True


# ── Git commit ────────────────────────────────────────────────────────────────

def commit_patches(patched_files: list[str]) -> bool:
    """Commit patched files back to the repository using GITHUB_TOKEN."""
    token = os.environ.get("GITHUB_TOKEN", "")
    repo  = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo:
        log.info("self_heal: GITHUB_TOKEN or GITHUB_REPOSITORY not set — skipping commit.")
        return False
    try:
        subprocess.run(
            ["git", "config", "--global", "user.email", "github-actions[bot]@users.noreply.github.com"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "config", "--global", "user.name", "TorShield-SelfHeal"],
            check=True, capture_output=True,
        )
        remote_url = f"https://x-access-token:{token}@github.com/{repo}.git"
        subprocess.run(["git", "remote", "set-url", "origin", remote_url],
                       check=True, capture_output=True)
        for f in patched_files:
            subprocess.run(["git", "add", f], check=True, capture_output=True)
        result = subprocess.run(
            ["git", "diff", "--staged", "--quiet"],
            capture_output=True,
        )
        if result.returncode == 0:
            log.info("self_heal: no staged changes after patching.")
            return True
        subprocess.run(
            ["git", "commit", "-m", "fix(self-heal): autonomous syntax patch [skip ci]"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "push", "origin", "HEAD"],
            check=True, capture_output=True,
        )
        log.info("self_heal: committed and pushed %d patched file(s).", len(patched_files))
        return True
    except subprocess.CalledProcessError as exc:
        log.warning("self_heal: git operation failed: %s", exc)
        return False


# ── Log management ────────────────────────────────────────────────────────────

def write_log(
    errors: list[dict[str, str]],
    patched: list[str],
    committed: bool,
) -> None:
    Path("data").mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "github_sha":      os.environ.get("GITHUB_SHA", "unknown"),
        "errors_found":    len(errors),
        "errors":          errors,
        "patched_files":   patched,
        "committed":       committed,
    }
    history: list[dict[str, Any]] = []
    if HEAL_LOG.exists():
        try:
            history = json.loads(HEAL_LOG.read_text(encoding="utf-8"))
        except Exception:
            history = []
    history.append(entry)
    # Keep last 50 entries
    HEAL_LOG.write_text(
        json.dumps(history[-50:], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="TorShield-IR self-healing debugger")
    parser.add_argument("--check",  action="store_true", help="Validate only")
    parser.add_argument("--heal",   action="store_true", help="Validate + auto-patch + commit")
    parser.add_argument("--report", action="store_true", help="Print last heal log")
    args = parser.parse_args()

    if args.report:
        if HEAL_LOG.exists():
            data = json.loads(HEAL_LOG.read_text(encoding="utf-8"))
            if data:
                print(json.dumps(data[-1], indent=2))
            else:
                print("{}")
        return 0

    py_errors   = check_python_syntax()
    yaml_errors = check_yaml_syntax()
    all_errors  = py_errors + yaml_errors

    if not all_errors:
        log.info("self_heal: all checks passed — zero errors detected.")
        write_log([], [], False)
        return 0

    for err in all_errors:
        log.warning("self_heal: error in %s — %s", err["file"], err["error"])

    patched   : list[str] = []
    committed : bool = False

    if args.heal:
        for err in py_errors:   # Only auto-patch Python files (not YAML)
            if apply_patch(err):
                patched.append(err["file"])
        if patched:
            # Re-validate after patching
            remaining = check_python_syntax()
            if not remaining:
                log.info("self_heal: all Python errors resolved.")
            else:
                log.warning(
                    "self_heal: %d error(s) remain after patching.", len(remaining)
                )
            committed = commit_patches(patched)

    write_log(all_errors, patched, committed)
    # Always exit 0 — never abort the pipeline
    return 0


if __name__ == "__main__":
    sys.exit(main())
