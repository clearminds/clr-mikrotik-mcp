"""REST and SSH clients for MikroTik RouterOS devices."""

import ipaddress
import logging
import socket
import ssl
from typing import Any

import httpx
import paramiko

logger = logging.getLogger(__name__)


class RouterOSClient:
    """MikroTik RouterOS REST API + SSH client.

    REST API is preferred (structured JSON). SSH is fallback for commands
    not available via REST (bridge host table, print stats, export, etc.).

    Attributes:
        username: Default username for device authentication.
        password: Default password for device authentication.
        ssh_key: Path to SSH private key file, or empty string if unused.
        devices: Per-device credential overrides keyed by hostname/IP. An
            entry may also carry ``tls_name``, the DNS name its certificate
            is issued for.
        ca_bundle: Path to a PEM CA bundle. When set, the REST API is only
            reached over verified HTTPS; when empty, certificates are not
            verified and plain HTTP is used as a fallback (legacy behaviour).
        tls_names: Host/IP -> certificate DNS name, used when callers address
            a router by IP. A per-device ``tls_name`` takes precedence.
    """

    def __init__(
        self,
        username: str = "",
        password: str = "",
        ssh_key: str = "",
        devices: dict[str, dict[str, str]] | None = None,
        ca_bundle: str = "",
        tls_names: dict[str, str] | None = None,
    ) -> None:
        self.username = username
        self.password = password
        self.ssh_key = ssh_key
        self.devices = devices or {}
        self.ca_bundle = ca_bundle
        self.tls_names = tls_names or {}
        self._ssl_context: ssl.SSLContext | None = None
        self._warned_unverified = False
        if ca_bundle:
            # Built once (fails fast on a missing/invalid file); contexts are
            # safe to share between connections.
            self._ssl_context = ssl.create_default_context(cafile=ca_bundle)
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED

    def _get_auth(self, host: str) -> tuple[str, str]:
        """Return (username, password) for a specific host.

        Args:
            host: Device IP or hostname to look up credentials for.

        Returns:
            A tuple of (username, password), using per-device overrides
            if configured, otherwise falling back to the default credentials.
        """
        device_creds = self.devices.get(host, {})
        username = device_creds.get("username", self.username)
        password = device_creds.get("password", self.password)
        return username, password

    def _port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open.

        Args:
            host: Device IP or hostname to probe.
            port: TCP port number to check.
            timeout: Connection timeout in seconds.

        Returns:
            True if a TCP connection could be established, False otherwise.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (OSError, TimeoutError):
            return False

    def _get_base_url(self, host: str) -> str:
        """Probe HTTPS then HTTP, return base URL.

        With a CA bundle configured only HTTPS is tried: falling back to
        http:80 would silently downgrade a verified connection to cleartext.

        Args:
            host: Device IP or hostname.

        Returns:
            The base URL string (e.g. ``https://192.168.88.1``).

        Raises:
            ConnectionError: If no permitted port is reachable.
        """
        if self._port_open(host, 443):
            return f"https://{host}"
        if self._ssl_context is not None:
            raise ConnectionError(
                f"Cannot connect to {host} on port 443; not falling back to "
                "plain HTTP because MIKROTIK_CA_BUNDLE is set"
            )
        if self._port_open(host, 80):
            return f"http://{host}"
        raise ConnectionError(f"Cannot connect to {host} (ports 443 and 80 closed)")

    def _tls_name(self, host: str) -> str | None:
        """Return the DNS name to verify ``host``'s certificate against.

        Per-device ``tls_name`` wins over ``tls_names``; a host that is not an
        IP address is its own name.

        Args:
            host: Device IP or hostname as passed by the caller.

        Returns:
            The certificate name, or None for an IP with no known name.
        """
        name = self.devices.get(host, {}).get("tls_name") or self.tls_names.get(host)
        if name:
            return name
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return host
        return None

    def _client_kwargs(self, host: str) -> dict[str, Any]:
        """Build the ``httpx.Client`` kwargs for a REST call to ``host``.

        With a CA bundle, the connection always goes to ``host`` as given (no
        DNS lookup of the certificate name is needed, so this keeps working
        when internal DNS is down or a name resolves to a different address),
        while TLS verification, SNI and the Host header use the certificate
        name. The name is applied through httpx's ``sni_hostname`` request
        extension, which httpcore passes as ``server_hostname`` to the SSL
        context, so ``check_hostname`` validates against it.

        Args:
            host: Device IP or hostname.

        Returns:
            Keyword arguments for ``httpx.Client``.

        Raises:
            ConnectionError: If the CA bundle is set and ``host`` is an IP
                with no known certificate name (verification would be
                impossible, and skipping it silently is not acceptable).
        """
        if self._ssl_context is None:
            if not self._warned_unverified:
                logger.warning(
                    "MIKROTIK_CA_BUNDLE is not set: RouterOS TLS certificates are "
                    "NOT verified and plain HTTP is used if HTTPS is unreachable"
                )
                self._warned_unverified = True
            return {
                "base_url": self._get_base_url(host),
                "auth": self._get_auth(host),
                "verify": False,
                "timeout": 30.0,
            }

        name = self._tls_name(host)
        if name is None:
            raise ConnectionError(
                f"{host} is an IP address with no known TLS name, so its certificate "
                "cannot be verified. Use the router's DNS name, or map the IP in "
                'MIKROTIK_TLS_NAMES (or a "tls_name" in credentials.json devices).'
            )
        kwargs: dict[str, Any] = {
            "base_url": self._get_base_url(host),
            "auth": self._get_auth(host),
            "verify": self._ssl_context,
            "timeout": 30.0,
        }
        if name != host:
            kwargs["headers"] = {"Host": name}

            def _set_sni(request: httpx.Request) -> None:
                request.extensions["sni_hostname"] = name

            kwargs["event_hooks"] = {"request": [_set_sni]}
        return kwargs

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

        Returns:
            Parsed JSON response, or None if the response body is empty.
        """
        params = dict(filters or {})
        if proplist:
            params[".proplist"] = proplist

        with httpx.Client(**self._client_kwargs(host)) as client:
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

        Returns:
            Parsed JSON response, or None if the response body is empty.
        """
        with httpx.Client(**self._client_kwargs(host)) as client:
            resp = client.post(f"/rest{path}", json=body or {})
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_put(self, host: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send a PUT request to the RouterOS REST API.

        Args:
            host: Device IP or hostname.
            path: API path.
            body: JSON body for the update.

        Returns:
            Parsed JSON response, or None if the response body is empty.
        """
        with httpx.Client(**self._client_kwargs(host)) as client:
            resp = client.put(f"/rest{path}", json=body or {})
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_patch(self, host: str, path: str, body: dict[str, Any] | None = None) -> Any:
        """Send a PATCH request to the RouterOS REST API.

        RouterOS distinguishes these: ``PUT /rest/<path>`` ADDS an item, while
        ``PATCH /rest/<path>/<id>`` UPDATES an existing one. Routing PATCH
        through :meth:`rest_put` therefore turns an intended update into a
        create, which is why it has its own method.

        Args:
            host: Device IP or hostname.
            path: API path including the item id (e.g. "/user/*8").
            body: JSON body of properties to change.

        Returns:
            Parsed JSON response, or None if the response body is empty.
        """
        with httpx.Client(**self._client_kwargs(host)) as client:
            resp = client.patch(f"/rest{path}", json=body or {})
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def rest_delete(self, host: str, path: str) -> Any:
        """Send a DELETE request to the RouterOS REST API.

        Args:
            host: Device IP or hostname.
            path: API path identifying the resource to remove.

        Returns:
            Parsed JSON response, or None if the response body is empty.
        """
        with httpx.Client(**self._client_kwargs(host)) as client:
            resp = client.delete(f"/rest{path}")
            resp.raise_for_status()
            if not resp.content:
                return None
            return resp.json()

    def sftp_upload(self, host: str, filename: str, content: str, timeout: float = 30.0) -> None:
        """Upload a string as a file to a RouterOS device via SFTP.

        Args:
            host: Device IP or hostname.
            filename: Remote filename (placed in device root).
            content: File content as a string.
            timeout: Connection timeout in seconds.
        """
        username, password = self._get_auth(host)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            connect_kwargs: dict[str, Any] = {
                "hostname": host,
                "port": 22,
                "username": username,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }
            if self.ssh_key:
                connect_kwargs["key_filename"] = self.ssh_key
            else:
                connect_kwargs["password"] = password

            client.connect(**connect_kwargs)
            sftp = client.open_sftp()
            try:
                with sftp.file(filename, "w") as f:
                    f.write(content)
            finally:
                sftp.close()
        finally:
            client.close()

    def ssh_command(self, host: str, command: str, timeout: float = 30.0) -> str:
        """Execute a command via SSH on a RouterOS device.

        Uses password auth with MikroTik login modifiers (+cet) for clean output.

        Args:
            host: Device IP or hostname.
            command: RouterOS CLI command.
            timeout: SSH timeout in seconds.

        Returns:
            Command output as a string, with stderr appended if present.
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
