"""REST and SSH clients for MikroTik RouterOS devices."""

import logging
import socket
from typing import Any

import httpx
import paramiko

logger = logging.getLogger(__name__)


class RouterOSClient:
    """MikroTik RouterOS REST API + SSH client.

    REST API is preferred (structured JSON). SSH is fallback for commands
    not available via REST (bridge host table, print stats, export, etc.).
    """

    def __init__(
        self,
        username: str = "",
        password: str = "",
        ssh_key: str = "",
        devices: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.devices = devices or {}

    def _get_auth(self, host: str) -> tuple[str, str]:
        """Return (username, password) for a specific host."""
        device_creds = self.devices.get(host, {})
        username = device_creds.get("username", self.username)
        password = device_creds.get("password", self.password)
        return username, password

    def _port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            return False

    def _get_base_url(self, host: str) -> str:
        """Probe HTTPS then HTTP, return base URL."""
        if self._port_open(host, 443):
            return f"https://{host}"
        if self._port_open(host, 80):
            return f"http://{host}"
        raise ConnectionError(f"Cannot connect to {host} (ports 443 and 80 closed)")

    def rest_get(
        self,
        host: str,
        path: str,
        filters: dict[str, str] | None = None,
        proplist: str | None = None,
    ) -> Any:
        """GET request to RouterOS REST API.

        Args:
            host: Device IP or hostname.
            path: API path (e.g. "/ip/arp").
            filters: Key-value filter params.
            proplist: Comma-separated property list.

        Returns parsed JSON response.
        """
        base_url = self._get_base_url(host)
        username, password = self._get_auth(host)
        params = dict(filters or {})
        if proplist:
            params[".proplist"] = proplist

        with httpx.Client(
            base_url=base_url,
            auth=(username, password),
            verify=False,
            timeout=30.0,
        ) as client:
            resp = client.get(f"/rest{path}", params=params)
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_post(
        self,
        host: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        """POST request to RouterOS REST API (for add/put operations).

        Args:
            host: Device IP or hostname.
            path: API path.
            body: JSON body.

        Returns parsed JSON response.
        """
        base_url = self._get_base_url(host)
        username, password = self._get_auth(host)
        with httpx.Client(
            base_url=base_url,
            auth=(username, password),
            verify=False,
            timeout=30.0,
        ) as client:
            resp = client.post(f"/rest{path}", json=body or {})
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_put(self, host: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """PUT request to RouterOS REST API."""
        base_url = self._get_base_url(host)
        username, password = self._get_auth(host)
        with httpx.Client(
            base_url=base_url,
            auth=(username, password),
            verify=False,
            timeout=30.0,
        ) as client:
            resp = client.put(f"/rest{path}", json=body or {})
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_delete(self, host: str, path: str) -> Any:
        """DELETE request to RouterOS REST API."""
        base_url = self._get_base_url(host)
        username, password = self._get_auth(host)
        with httpx.Client(
            base_url=base_url,
            auth=(username, password),
            verify=False,
            timeout=30.0,
        ) as client:
            resp = client.delete(f"/rest{path}")
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def ssh_command(self, host: str, command: str, timeout: float = 30.0) -> str:
        """Execute a command via SSH on a RouterOS device.

        Uses password auth with MikroTik login modifiers (+cet) for clean output.

        Args:
            host: Device IP or hostname.
            command: RouterOS CLI command.
            timeout: SSH timeout in seconds.

        Returns command output as string.
        """
        username, password = self._get_auth(host)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # MikroTik +cet login modifiers: c=no color, e=no echo, t=no terminal
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": 22,
                "username": f"{username}+cet",
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }
            if self.ssh_key:
                connect_kwargs["key_filename"] = self.ssh_key
            else:
                connect_kwargs["password"] = password

            client.connect(**connect_kwargs)
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            output = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err:
                output += f"\n{err}"
            return output.strip()
        finally:
            client.close()
