"""
core/notifier.py — Telegram notification and file uploader.

Sends a formatted statistics message and the ZIP archive to a
Telegram channel/chat after each collection run.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from core.dt_utils import utc_now
from typing import Any, Dict, Optional

import requests

import config

log = logging.getLogger(__name__)


class TelegramNotifier:

    def __init__(self):
        self._token = config.TELEGRAM_BOT_TOKEN
        self._chat  = config.TELEGRAM_CHAT_ID

    def _enabled(self) -> bool:
        if not self._token or not self._chat:
            log.debug("Telegram credentials not set — skipping notification.")
            return False
        return True

    def _api(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self._token}/{method}"

    def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        if not self._enabled():
            return False
        try:
            r = requests.post(
                self._api("sendMessage"),
                json={"chat_id": self._chat, "text": text, "parse_mode": parse_mode},
                timeout=30,
            )
            if r.status_code == 200:
                log.info("Telegram message sent.")
                return True
            log.warning(f"Telegram sendMessage HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log.error(f"Telegram sendMessage error: {e}")
        return False

    def send_document(self, file_path: str, caption: str = "") -> bool:
        if not self._enabled():
            return False
        if not os.path.exists(file_path):
            log.warning(f"Telegram upload: file not found: {file_path}")
            return False
        try:
            with open(file_path, "rb") as fh:
                r = requests.post(
                    self._api("sendDocument"),
                    data={"chat_id": self._chat, "caption": caption[:1024], "parse_mode": "Markdown"},
                    files={"document": fh},
                    timeout=120,
                )
            if r.status_code == 200:
                log.info(f"Telegram document sent: {os.path.basename(file_path)}")
                return True
            log.warning(f"Telegram sendDocument HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            log.error(f"Telegram sendDocument error: {e}")
        return False

    def build_caption(self, stats: Dict[str, Any]) -> str:
        ts   = utc_now().strftime("%Y-%m-%d %H:%M UTC")
        bt   = stats.get("by_transport", {})
        rh   = config.RECENT_HOURS

        def cnt(key: str) -> str:
            return str(stats.get(key, 0))

        lines = [
            "*🌐 Tor Bridges Ultra — Iran Optimised*",
            f"_Updated: {ts}_",
            "",
            "*📦 Full Archive:*",
            f"• obfs4: `{bt.get('obfs4', 0)}`  |  WebTunnel: `{bt.get('webtunnel', 0)}`",
            f"• Snowflake: `{bt.get('snowflake', 0)}`  |  meek-lite: `{bt.get('meek_lite', 0)}`",
            f"• Vanilla: `{bt.get('vanilla', 0)}`",
            "",
            "*✅ Tested & Reachable:*",
            f"• Total passing: `{stats.get('passing', 0)}` / `{stats.get('tested', 0)}` tested",
            "",
            "*⚡ Iran Packs:*",
            "• `export/iran_pack.txt` — Top scored for Iran",
            "• `export/iran_cut_pack.txt` — Internet cut survival",
            "",
            "*📊 Transport Guide:*",
            "Snowflake ➔ WebTunnel ➔ obfs4 ➔ meek ➔ Vanilla",
            "_(best for Iran DPI → least effective)_",
            "",
            "━━━━━━━━━━━━━━━━━━━━━",
            "_ZIP contains: Full Archive / Fresh 72h / Tested / Iran Optimised_",
        ]
        return "\n".join(lines)

    def notify(self, stats: Dict[str, Any], zip_path: Optional[str] = None) -> None:
        """Send stats message and optionally upload the ZIP archive."""
        caption = self.build_caption(stats)
        if zip_path and os.path.exists(zip_path):
            self.send_document(zip_path, caption=caption)
        else:
            self.send_message(caption)
