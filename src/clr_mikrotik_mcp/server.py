"""MikroTik MCP Server — FastMCP tools for RouterOS management."""

import argparse
import logging
import logging.config
import sys
from typing import Any

from fastmcp import FastMCP

from clr_mikrotik_mcp.config import Settings
from clr_mikrotik_mcp.routeros_client import RouterOSClient
from clr_mikrotik_mcp.middleware import ToolValidationMiddleware

mcp = FastMCP("MikroTik")
mcp.add_middleware(ToolValidationMiddleware())
_client: RouterOSClient | None = None

WRITE_TOOLS = ["mikrotik_ssh", "mikrotik_user_add", "mikrotik_ssh_key_import"]

_VALID_SSH_KEY_PREFIXES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-", "sk-ssh-")


# ── System tools ─────────────────────────────────────────────────────


@mcp.tool
def mikrotik_identity(host: str) -> dict[str, Any]:
    """Get device identity (hostname).

    Args:
        host: Device IP or hostname (e.g. "10.20.10.1").

    Returns:
        A dictionary containing the device identity.
    """
    return _client.rest_get(host, "/system/identity")


@mcp.tool
def mikrotik_version(host: str) -> dict[str, Any]:
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


@mcp.tool
def mikrotik_health(host: str) -> Any:
    """Get device health sensors (voltage, temperature, fan speed).

    Args:
        host: Device IP or hostname.

    Returns:
        Health sensor data from the device.
    """
    return _client.rest_get(host, "/system/health")


# ── Interface tools ──────────────────────────────────────────────────


@mcp.tool
def mikrotik_interfaces(
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


@mcp.tool
def mikrotik_addresses(host: str) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_arp(
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


@mcp.tool
def mikrotik_dhcp_leases(
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


@mcp.tool
def mikrotik_routes(
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


@mcp.tool
def mikrotik_neighbors(host: str) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_firewall(
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


@mcp.tool
def mikrotik_nat(host: str) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_users(host: str) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_ssh_keys(host: str, user: str | None = None) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_services(host: str) -> list[dict[str, Any]]:
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


@mcp.tool
def mikrotik_user_add(
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
        address: Source IP restriction (e.g. "10.20.10.0/24"). Empty = any.
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


@mcp.tool
def mikrotik_ssh_key_import(
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


# ── Raw tools ────────────────────────────────────────────────────────


@mcp.tool
def mikrotik_api(
    host: str,
    path: str,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    proplist: str | None = None,
) -> Any:
    """Execute a raw RouterOS REST API call.

    Covers all 401+ RouterOS API endpoints. Path must start with /.

    Args:
        host: Device IP or hostname.
        path: REST API path (e.g. "/interface/bridge/vlan", "/ip/pool").
        method: HTTP method — GET, POST (add), PUT (set), PATCH, DELETE (remove).
        body: JSON body for POST/PUT/PATCH (e.g. {"address": "10.0.0.1/24", "interface": "ether1"}).
        proplist: Comma-separated properties to return (e.g. "name,address,interface").

    Returns:
        Parsed JSON from the device, or an error dictionary for unsupported methods.
    """
    if method.upper() == "GET":
        return _client.rest_get(host, path, proplist=proplist)
    elif method.upper() == "POST":
        return _client.rest_post(host, path, body)
    elif method.upper() in ("PUT", "PATCH"):
        return _client.rest_put(host, path, body)
    elif method.upper() == "DELETE":
        return _client.rest_delete(host, path)
    else:
        return {"error": f"Unsupported method: {method}"}


@mcp.tool
def mikrotik_ssh(
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
    if read_only and WRITE_TOOLS:
        for name in WRITE_TOOLS:
            mcp.remove_tool(name)
        logger.info("Read-only mode: %d write tools removed", len(WRITE_TOOLS))

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
