"""Configuration for MikroTik MCP Server."""

import json
import logging
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

CREDS_PATH = Path.home() / ".config" / "mikrotik" / "credentials.json"


class Settings(BaseSettings):
    """Settings loaded from credentials file or environment variables.

    Priority order:
    1. ~/.config/mikrotik/credentials.json
    2. Environment variables (MIKROTIK_USERNAME, MIKROTIK_PASSWORD, MIKROTIK_SSH_KEY) - override
    """

    mikrotik_username: str = ""
    mikrotik_password: str = ""
    mikrotik_ssh_key: str = ""  # Path to SSH private key (optional)
    mikrotik_transport: str = "stdio"
    mikrotik_log_level: str = "INFO"

    model_config = {"env_prefix": ""}

    def load_credentials(self) -> dict[str, Any]:
        """Load credentials with config-file-first, env-override pattern.

        Returns:
            Dict with username, password, and optional ssh_key.
        """
        creds: dict[str, Any] = {}

        # 1. FIRST: Load from environment variables (base/fallback)
        if self.mikrotik_username:
            creds["username"] = self.mikrotik_username
        if self.mikrotik_password:
            creds["password"] = self.mikrotik_password
        if self.mikrotik_ssh_key:
            creds["ssh_key"] = self.mikrotik_ssh_key

        # 2. THEN: Override with credentials.json file (takes priority)
        if CREDS_PATH.exists():
            try:
                file_creds: dict[str, Any] = json.loads(CREDS_PATH.read_text())

                if "username" in file_creds:
                    creds["username"] = file_creds["username"]
                if "password" in file_creds:
                    creds["password"] = file_creds["password"]
                if "ssh_key" in file_creds:
                    creds["ssh_key"] = file_creds["ssh_key"]
                if "devices" in file_creds:
                    creds["devices"] = file_creds["devices"]

                logger.info(f"Loaded MikroTik credentials from {CREDS_PATH}")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to load {CREDS_PATH}: {e}")

        creds.setdefault("devices", {})

        if not (creds.get("username") and (creds.get("password") or creds.get("ssh_key"))):
            if not creds["devices"]:
                logger.warning(
                    "No MikroTik credentials configured. Set MIKROTIK_USERNAME and "
                    "(MIKROTIK_PASSWORD or MIKROTIK_SSH_KEY) env vars or create "
                    f"{CREDS_PATH}"
                )

        return creds
