"""MikroTik MCP Server — FastMCP tools for RouterOS management."""

import argparse
import json
import logging
import logging.config
import sys
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from clr_mikrotik_mcp.config import Settings
from clr_mikrotik_mcp.routeros_client import RouterOSClient
from clr_mikrotik_mcp.middleware import ToolValidationMiddleware

mcp = FastMCP("MikroTik")
mcp.add_middleware(ToolValidationMiddleware())

# Imported here (not at the top) on purpose: annotations.py needs ``mcp`` from
# this module, so importing it before the ``mcp = FastMCP(...)`` line above
# would be a circular import. Do not move.
from clr_mikrotik_mcp.annotations import (  # noqa: E402
    destructive_tool,
    read_tool,
    remove_non_read_tools,
    write_tool,
)
from clr_mikrotik_mcp._verbs import (  # noqa: E402
    reject_delete_method,
    reject_destructive_ssh,
    require_destructive_ssh,
    require_read_only_ssh,
)

_client: RouterOSClient | None = None

_VALID_SSH_KEY_PREFIXES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-", "sk-ssh-")


# ── System tools ─────────────────────────────────────────────────────


@read_tool
def identity(host: str) -> dict[str, Any]:
    """Get device identity (hostname).

    Args:
        host: Device IP or hostname (e.g. "192.168.88.1").

    Returns:
        A dictionary containing the device identity.
    """
    return _client.rest_get(host, "/system/identity")


@read_tool
def version(host: str) -> dict[str, Any]:
    """Get RouterOS version, CPU, memory, and uptime.

    Args:
        host: Device IP or hostname.

    Returns:
        A dictionary containing system resource information.
    """
    return _client.rest_get(
        host,
        "/system/resource",
        proplist="version,board-name,cpu,cpu-count,free-memory,total-memory,uptime,architecture-name",
    )


@read_tool
def health(host: str) -> Any:
    """Get device health sensors (voltage, temperature, fan speed).

    Args:
        host: Device IP or hostname.

    Returns:
        Health sensor data from the device.
    """
    return _client.rest_get(host, "/system/health")


# ── Interface tools ──────────────────────────────────────────────────


@read_tool
def interfaces(
    host: str,
    interface_type: str | None = None,
) -> list[dict[str, Any]]:
    """List interfaces, optionally filtered by type.

    Args:
        host: Device IP or hostname.
        interface_type: Filter by type (e.g. "ether", "vlan", "bridge", "bonding").

    Returns:
        A list of interface dictionaries.
    """
    filters = {}
    if interface_type:
        filters["type"] = interface_type
    return _client.rest_get(
        host,
        "/interface",
        filters=filters,
        proplist="name,type,running,disabled,mac-address,comment",
    )


@read_tool
def addresses(host: str) -> list[dict[str, Any]]:
    """List all IP addresses on the device.

    Args:
        host: Device IP or hostname.

    Returns:
        A list of IP address dictionaries.
    """
    return _client.rest_get(
        host,
        "/ip/address",
        proplist="address,network,interface,disabled,comment",
    )


# ── L2/L3 tools ─────────────────────────────────────────────────────


@read_tool
def arp(
    host: str,
    interface: str | None = None,
) -> list[dict[str, Any]]:
    """List ARP table entries, optionally filtered by interface.

    Args:
        host: Device IP or hostname.
        interface: Filter by interface name (e.g. "bridge-nn-16").

    Returns:
        A list of ARP entry dictionaries.
    """
    filters = {}
    if interface:
        filters["interface"] = interface
    return _client.rest_get(
        host,
        "/ip/arp",
        filters=filters,
        proplist="address,mac-address,interface,status,dynamic",
    )


@read_tool
def dhcp_leases(
    host: str,
    server: str | None = None,
) -> list[dict[str, Any]]:
    """List DHCP leases, optionally filtered by DHCP server name.

    Args:
        host: Device IP or hostname.
        server: Filter by DHCP server name (e.g. "nn-16").

    Returns:
        A list of DHCP lease dictionaries.
    """
    filters = {}
    if server:
        filters["server"] = server
    return _client.rest_get(
        host,
        "/ip/dhcp-server/lease",
        filters=filters,
        proplist="address,mac-address,host-name,server,status,expires-after,dynamic",
    )


@read_tool
def routes(
    host: str,
    dst: str | None = None,
) -> list[dict[str, Any]]:
    """List routing table entries, optionally filtered by destination.

    Args:
        host: Device IP or hostname.
        dst: Filter by destination prefix (e.g. "10.20.22.0/24").

    Returns:
        A list of route entry dictionaries.
    """
    filters = {}
    if dst:
        filters["dst-address"] = dst
    return _client.rest_get(
        host,
        "/ip/route",
        filters=filters,
        proplist="dst-address,gateway,distance,routing-table,active,dynamic",
    )


@read_tool
def neighbors(host: str) -> list[dict[str, Any]]:
    """List discovered neighbors (LLDP/CDP/MNDP).

    Args:
        host: Device IP or hostname.

    Returns:
        A list of neighbor entry dictionaries.
    """
    return _client.rest_get(
        host,
        "/ip/neighbor",
        proplist="address,mac-address,identity,platform,interface",
    )


# ── Firewall tools ───────────────────────────────────────────────────


@read_tool
def firewall(
    host: str,
    chain: str | None = None,
) -> list[dict[str, Any]]:
    """List firewall filter rules, optionally filtered by chain.

    Args:
        host: Device IP or hostname.
        chain: Filter by chain (e.g. "input", "forward", "output").

    Returns:
        A list of firewall filter rule dictionaries.
    """
    filters = {}
    if chain:
        filters["chain"] = chain
    return _client.rest_get(
        host,
        "/ip/firewall/filter",
        filters=filters,
        proplist="chain,action,src-address,dst-address,protocol,dst-port,in-interface,comment,disabled",
    )


@read_tool
def nat(host: str) -> list[dict[str, Any]]:
    """List NAT rules.

    Args:
        host: Device IP or hostname.

    Returns:
        A list of NAT rule dictionaries.
    """
    return _client.rest_get(
        host,
        "/ip/firewall/nat",
        proplist="chain,action,src-address,dst-address,protocol,dst-port,to-addresses,to-ports,comment,disabled",
    )


# ── User & service tools ────────────────────────────────────────────


@read_tool
def users(host: str) -> list[dict[str, Any]]:
    """List all user accounts on the device.

    Args:
        host: Device IP or hostname.

    Returns:
        A list of user account dictionaries.
    """
    return _client.rest_get(
        host,
        "/user",
        proplist="name,group,address,disabled,comment",
    )


@read_tool
def ssh_keys(host: str, user: str | None = None) -> list[dict[str, Any]]:
    """List imported SSH public keys, optionally filtered by user.

    Args:
        host: Device IP or hostname.
        user: Filter by username.

    Returns:
        A list of SSH key dictionaries.
    """
    filters = {}
    if user:
        filters["user"] = user
    return _client.rest_get(
        host,
        "/user/ssh-keys",
        filters=filters,
        proplist="user,key-owner",
    )


@read_tool
def services(host: str) -> list[dict[str, Any]]:
    """List IP services (SSH, www, api, winbox, etc.) with status.

    Args:
        host: Device IP or hostname.

    Returns:
        A list of IP service dictionaries.
    """
    return _client.rest_get(
        host,
        "/ip/service",
        proplist="name,port,address,disabled",
    )


@write_tool
def user_add(
    host: str,
    name: str,
    group: str,
    password: str,
    address: str = "",
    comment: str = "",
) -> dict[str, Any]:
    """Create a new user account on the device.

    Safety: refuses to create a user if one with the same name already exists,
    and refuses names matching the currently authenticated user.

    Args:
        host: Device IP or hostname.
        name: Username for the new account.
        group: Permission group (e.g. "read", "write", "full"). Required.
        password: Password for the new account.
        address: Source IP restriction (e.g. "192.168.88.0/24"). Empty = any.
        comment: Optional comment for the user account.

    Returns:
        The REST API response (created user resource).
    """
    auth_user, _ = _client._get_auth(host)
    if name == auth_user:
        return {"error": f"Refusing to create user '{name}': matches the authenticated user"}

    existing = _client.rest_get(host, "/user", filters={"name": name}, proplist="name")
    if existing:
        return {"error": f"User '{name}' already exists on {host}"}

    body: dict[str, Any] = {"name": name, "group": group, "password": password}
    if address:
        body["address"] = address
    if comment:
        body["comment"] = comment
    return _client.rest_post(host, "/user", body)


@write_tool
def ssh_key_import(
    host: str,
    user: str,
    public_key: str,
) -> str:
    """Import an SSH public key for a user.

    Uploads the key via SFTP, imports it via CLI, and cleans up the temp file.
    The user must already exist on the device.

    Args:
        host: Device IP or hostname.
        user: Username to import the key for (must already exist).
        public_key: SSH public key string (e.g. "ssh-ed25519 AAAA... comment").

    Returns:
        CLI output from the import command.
    """
    if not any(public_key.startswith(prefix) for prefix in _VALID_SSH_KEY_PREFIXES):
        return f"Error: key must start with one of: {', '.join(_VALID_SSH_KEY_PREFIXES)}"

    existing = _client.rest_get(host, "/user", filters={"name": user}, proplist="name")
    if not existing:
        return f"Error: user '{user}' does not exist on {host}"

    filename = f"tmp-key-{user}.pub"
    _client.sftp_upload(host, filename, public_key)
    try:
        result = _client.ssh_command(
            host,
            f"/user/ssh-keys/import public-key-file={filename} user={user}",
        )
    finally:
        try:
            _client.ssh_command(host, f"/file/remove {filename}")
        except Exception:
            pass
    return result


def _coerce_body(body: Any) -> dict[str, Any] | None:
    """Accept a JSON object, or a JSON string, as a request body.

    MCP clients differ in how they serialize nested arguments: some send a
    real object, some send the same thing as a string. Rejecting the string
    form makes the tool intermittently unusable for no good reason, so parse
    it here instead.

    NOTE: this function is only reached if the tool SIGNATURE admits ``str``.
    FastMCP validates arguments against the annotation before the body runs,
    so a coercion helper behind a ``dict``-only annotation never executes —
    the call is rejected with "Input should be a valid dictionary" first.
    That is exactly how the first attempt at this fix failed.
    """
    if body is None or isinstance(body, dict):
        return body
    if isinstance(body, str):
        text = body.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ToolError(f"body is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ToolError(f"body must be a JSON object, got {type(parsed).__name__}")
        return parsed
    raise ToolError(f"body must be an object or JSON string, got {type(body).__name__}")


# ── Raw tools ────────────────────────────────────────────────────────


@write_tool
def api(
    host: str,
    path: str,
    method: str = "GET",
    body: dict[str, Any] | str | None = None,
    proplist: str | None = None,
) -> Any:
    """Execute a raw RouterOS REST API call.

    Covers all 401+ RouterOS API endpoints. Path must start with /.

    Args:
        host: Device IP or hostname.
        path: REST API path (e.g. "/interface/bridge/vlan", "/ip/pool").
        method: HTTP method, using RouterOS REST semantics —
            GET (read), PUT (add), PATCH (set/update an existing item by id),
            POST (invoke a command such as /move), DELETE (remove).
            Note PUT adds and PATCH updates; they are not interchangeable.
        body: JSON body for PUT/PATCH/POST (e.g. {"address": "10.0.0.1/24", "interface": "ether1"}).
            Accepts a JSON object, or a JSON string for clients that serialize
            nested arguments.
        proplist: Comma-separated properties to return (e.g. "name,address,interface").

    Returns:
        Parsed JSON from the device, or an error dictionary for unsupported methods.
    """
    reject_delete_method(method)
    body = _coerce_body(body)
    if method.upper() == "GET":
        return _client.rest_get(host, path, proplist=proplist)
    elif method.upper() == "POST":
        return _client.rest_post(host, path, body)
    elif method.upper() == "PUT":
        return _client.rest_put(host, path, body)
    elif method.upper() == "PATCH":
        # NOT rest_put: RouterOS treats PUT as add and PATCH as update, so
        # sending a PATCH as PUT silently creates instead of updating.
        return _client.rest_patch(host, path, body)
    elif method.upper() == "DELETE":
        return _client.rest_delete(host, path)
    else:
        return {"error": f"Unsupported method: {method}"}


@write_tool
def ssh(
    host: str,
    command: str,
) -> str:
    """Execute a RouterOS CLI command via SSH.

    Use for commands not available via REST API:
    - /interface/bridge/host (FDB table on CRS switches)
    - print count-only, print stats
    - /export (full config export)
    - interactive monitoring commands

    Always append 'without-paging' for list commands.

    Args:
        host: Device IP or hostname.
        command: RouterOS CLI command (e.g. "/interface/bridge/host/print without-paging").

    Returns:
        Command output as text.
    """
    reject_destructive_ssh(command)
    return _client.ssh_command(host, command)


@read_tool
def api_read(
    host: str,
    path: str,
    proplist: str | None = None,
) -> Any:
    """Read-only RouterOS REST API call (GET).

    Use ``api`` for non-destructive writes (POST/PUT/PATCH)
    and ``api_destructive`` for DELETE.

    Args:
        host: Device IP or hostname.
        path: REST API path starting with /.
        proplist: Comma-separated properties to return.

    Returns:
        Parsed JSON from the device.
    """
    return _client.rest_get(host, path, proplist=proplist)


@destructive_tool
def api_destructive(
    host: str,
    path: str,
) -> Any:
    """Destructive RouterOS REST API call (DELETE).

    Use ``api_read`` for GET and ``api`` for non-destructive
    writes (POST/PUT/PATCH).

    Args:
        host: Device IP or hostname.
        path: REST API path of the resource to delete.

    Returns:
        Parsed JSON from the device.
    """
    return _client.rest_delete(host, path)


@read_tool
def ssh_read(host: str, command: str) -> str:
    """Read-only RouterOS CLI command via SSH.

    Allowed verbs: print, get, getall, find, monitor, export.
    Use ``ssh`` for write commands or
    ``ssh_destructive`` for remove/reset/reboot/shutdown.

    Args:
        host: Device IP or hostname.
        command: RouterOS CLI command (e.g. "/interface/bridge/host/print").

    Returns:
        Command output as text.
    """
    require_read_only_ssh(command)
    return _client.ssh_command(host, command)


@destructive_tool
def ssh_destructive(host: str, command: str) -> str:
    """Destructive RouterOS CLI command via SSH.

    Allowed verbs: remove, reset-configuration, reboot, shutdown.

    Args:
        host: Device IP or hostname.
        command: RouterOS CLI command (e.g. "/system reboot").

    Returns:
        Command output as text.
    """
    require_destructive_ssh(command)
    return _client.ssh_command(host, command)


# ── Main entry point ─────────────────────────────────────────────────


def main() -> None:
    """Main entry point for the MikroTik MCP server."""
    global _client

    settings = Settings()

    parser = argparse.ArgumentParser(description="MikroTik MCP Server")
    parser.add_argument(
        "--transport", type=str, choices=["stdio", "http"], default=None
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument(
        "--read-only",
        action="store_true",
        default=None,
        help="Run in read-only mode (hide write tools)",
    )
    args = parser.parse_args()

    transport = args.transport or settings.mikrotik_transport
    log_level = args.log_level or settings.mikrotik_log_level

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "console": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "console",
                    "stream": "ext://sys.stderr",
                }
            },
            "root": {"level": log_level, "handlers": ["console"]},
        }
    )

    logger = logging.getLogger(__name__)

    creds = settings.load_credentials()

    logger.info("Starting MikroTik MCP Server (user: %s)", creds.get("username", ""))
    _client = RouterOSClient(
        username=creds.get("username", ""),
        password=creds.get("password", ""),
        ssh_key=creds.get("ssh_key", ""),
        devices=creds.get("devices", {}),
    )

    read_only = args.read_only if args.read_only is not None else settings.mikrotik_read_only
    if read_only:
        removed = remove_non_read_tools(mcp)
        logger.info("Read-only mode: %d non-read tools removed", removed)

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.run(transport="http", host=args.host, port=args.port)
    except Exception as e:
        logger.error("Failed to start MCP server: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
