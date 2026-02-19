"""MikroTik MCP Server — FastMCP tools for RouterOS management."""

import argparse
import logging
import logging.config
import sys
from typing import Any

from fastmcp import FastMCP

from clr_mikrotik_mcp.config import Settings
from clr_mikrotik_mcp.routeros_client import RouterOSClient

mcp = FastMCP("MikroTik")
_client: RouterOSClient | None = None



# ── System tools ─────────────────────────────────────────────────────


@mcp.tool
def mikrotik_identity(host: str) -> dict[str, Any]:
    """Get device identity (hostname).

    Args:
        host: Device IP or hostname (e.g. "10.20.10.1").
    """
    return _client.rest_get(host, "/system/identity")


@mcp.tool
def mikrotik_version(host: str) -> dict[str, Any]:
    """Get RouterOS version, CPU, memory, and uptime.

    Args:
        host: Device IP or hostname.
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
    """
    return _client.rest_get(
        host,
        "/ip/firewall/nat",
        proplist="chain,action,src-address,dst-address,protocol,dst-port,to-addresses,to-ports,comment,disabled",
    )


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

    Returns parsed JSON from the device.
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

    Returns command output as text.
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
