"""Tests for mikrotik verb-guard helpers."""

from __future__ import annotations

import pytest
from fastmcp.exceptions import ToolError

from clr_mikrotik_mcp._verbs import (
    _segment_verbs,
    reject_delete_method,
    reject_destructive_ssh,
    require_delete_method,
    require_destructive_ssh,
    require_get_method,
    require_read_only_ssh,
)


def test_segment_verbs_skips_path_tokens() -> None:
    assert _segment_verbs("/interface print") == ["print"]
    assert _segment_verbs("/system reboot") == ["reboot"]
    assert _segment_verbs("/ip address print; /system reboot") == ["print", "reboot"]


@pytest.mark.parametrize("cmd", [
    "/interface print",
    "/ip address print",
    "/ip dhcp-server lease print",
    "/system identity get",
    "/system routerboard print; /system health print",
    "/export",
])
def test_require_read_only_ssh_accepts(cmd: str) -> None:
    require_read_only_ssh(cmd)  # should not raise


@pytest.mark.parametrize("cmd", [
    "/system reboot",
    "/system reset-configuration",
    "/ip address remove [find]",
    "/interface set ether1 disabled=yes",
])
def test_require_read_only_ssh_rejects(cmd: str) -> None:
    with pytest.raises(ToolError):
        require_read_only_ssh(cmd)


def test_reject_destructive_ssh() -> None:
    reject_destructive_ssh("/interface set ether1 mtu=1500")  # ok
    with pytest.raises(ToolError):
        reject_destructive_ssh("/system reboot")


def test_method_guards() -> None:
    require_get_method("GET")
    with pytest.raises(ToolError):
        require_get_method("POST")

    require_delete_method("DELETE")
    with pytest.raises(ToolError):
        require_delete_method("GET")

    reject_delete_method("GET")
    with pytest.raises(ToolError):
        reject_delete_method("DELETE")
