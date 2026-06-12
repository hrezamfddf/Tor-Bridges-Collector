"""
AutoDebugEngine -- GitHub Actions self-healing system.
1. Fetch failed workflow logs via GitHub API.
2. Send to IranIntelligenceLayer.analyze_workflow_failure().
3. Apply generated patch (additive only -- never shorter than original).
4. Commit + push via GH_PAT_AUTOFIX.
5. Pipeline re-runs on next push.
"""

import os
import sys
import json
import base64
import logging
import urllib.request
import urllib.error
from typing import Optional
from .iran_intelligence import IranIntelligenceLayer

logger = logging.getLogger("torshield.autodebug")


class AutoDebugEngine:
    def __init__(self):
        self.token = os.environ["GH_PAT_AUTOFIX"]
        self.owner = os.environ["GH_REPO_OWNER"]
        self.repo  = os.environ["GH_REPO_NAME"]
        self.base  = f"https://api.github.com/repos/{self.owner}/{self.repo}"
        self.intel = IranIntelligenceLayer()

    def _gh_get(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def _gh_put(self, url: str, body: dict) -> dict:
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method="PUT", headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())

    def fetch_failed_run_logs(self, run_id: str) -> str:
        url = f"{self.base}/actions/runs/{run_id}/logs"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
        })
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                content = r.read()
                if content[:2] == b"PK":
                    import zipfile, io
                    with zipfile.ZipFile(io.BytesIO(content)) as z:
                        texts = []
                        for name in z.namelist():
                            if name.endswith(".txt"):
                                texts.append(
                                    z.read(name).decode("utf-8", errors="replace")
                                )
                        return "\n\n".join(texts)[-10000:]
                return content.decode("utf-8", errors="replace")[-10000:]
        except urllib.error.HTTPError as e:
            return f"[AutoDebug] Could not fetch logs: HTTP {e.code}"

    def apply_patch_to_repo(
        self, file_path: str, new_content: str, commit_message: str
    ) -> bool:
        """
        Update a file via GitHub API.
        SAFETY: New content must be at least as long as existing (additive policy).
        """
        try:
            existing = self._gh_get(f"{self.base}/contents/{file_path}")
            old_content = base64.b64decode(existing["content"]).decode(
                "utf-8", errors="replace"
            )
            old_sha = existing["sha"]
            if len(new_content) < len(old_content):
                logger.error(
                    f"[AutoDebug] BLOCKED: patch shortens {file_path} -- additive-only"
                )
                return False
        except urllib.error.HTTPError:
            old_sha = None  # new file

        encoded = base64.b64encode(new_content.encode("utf-8")).decode()
        body: dict = {
            "message": commit_message,
            "content": encoded,
            "branch": os.environ.get("GITHUB_REF_NAME", "main"),
        }
        if old_sha:
            body["sha"] = old_sha

        self._gh_put(f"{self.base}/contents/{file_path}", body)
        logger.info(f"[AutoDebug] Patched {file_path}")
        return True

    def run(self, workflow_name: str, run_id: str) -> None:
        logger.info(f"[AutoDebug] Analysing: {workflow_name} run #{run_id}")
        logs     = self.fetch_failed_run_logs(run_id)
        analysis = self.intel.analyze_workflow_failure(workflow_name, logs)

        logger.info(f"[AutoDebug] Root cause: {analysis.get('root_cause','unknown')}")
        logger.info(f"[AutoDebug] Fix type:   {analysis.get('fix_type','unknown')}")
        logger.info(f"[AutoDebug] Confidence: {float(analysis.get('confidence',0)):.0%}")

        patch      = analysis.get("patch", "")
        fix_type   = analysis.get("fix_type", "manual")
        confidence = float(analysis.get("confidence", 0.0))

        if not patch or confidence < 0.7:
            logger.warning("[AutoDebug] Low confidence or no patch -- skipping")
            return

        target_file = None
        if fix_type == "yaml_patch":
            target_file = f".github/workflows/{workflow_name}.yml"
        elif fix_type == "python_patch":
            for line in patch.splitlines():
                if line.startswith("# TARGET:"):
                    target_file = line.replace("# TARGET:", "").strip()
                    break
        elif fix_type == "shell_fix":
            target_file = "scripts/autofix_entrypoint.sh"

        if not target_file:
            logger.warning(f"[AutoDebug] No target file for fix_type={fix_type}")
            return

        commit_msg = (
            f"[AutoDebug] AI fix for {workflow_name}\n\n"
            f"Root cause: {analysis.get('root_cause','')[:200]}\n"
            f"Confidence: {confidence:.0%}\n"
            f"Additive-only: {analysis.get('additive_only', True)}"
        )
        self.apply_patch_to_repo(target_file, patch, commit_msg)
        logger.info("[AutoDebug] Patch applied.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    if len(sys.argv) < 3:
        print("Usage: python -m torshield_ai_gateway.auto_debug <workflow_name> <run_id>")
        sys.exit(1)
    AutoDebugEngine().run(sys.argv[1], sys.argv[2])
