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


# --- Regression: quoted arguments must not swallow the verb -----------------
#
# str.split() tore `comment="Allow Odoo CRM - web"` into five tokens, four of
# which looked like bare identifiers, so the verb resolved to `web"` and the
# guards rejected an ordinary command. Observed against a live router.


def test_segment_verbs_handles_quoted_arguments() -> None:
    assert _segment_verbs(
        '/ipv6/firewall/filter/add comment="Allow Odoo CRM - web" chain=forward'
    ) == ["add"]
    assert _segment_verbs('/system/identity/set name="a b c"') == ["set"]


def test_segment_verbs_handles_slash_form_paths() -> None:
    # RouterOS accepts the verb as the final path segment, not only as a
    # trailing word. Previously this fell through to the fallback and produced
    # the whole path as the "verb".
    assert _segment_verbs("/ipv6/firewall/filter/move numbers=*38 destination=*1C") == ["move"]
    assert _segment_verbs("/ip/firewall/filter/print") == ["print"]


def test_segment_verbs_ignores_script_block_contents() -> None:
    assert _segment_verbs(
        '/ip/firewall/filter/add comment="x y" place-before=[find comment="Drop rest"]'
    ) == ["add"]


def test_quoted_add_is_accepted_by_the_write_guard() -> None:
    # add is neither read nor destructive: mikrotik_ssh must accept it.
    reject_destructive_ssh('/ipv6/firewall/filter/add comment="Allow Odoo CRM - web"')


def test_quoted_remove_is_still_classified_destructive() -> None:
    with pytest.raises(ToolError):
        reject_destructive_ssh('/ip/firewall/filter/remove [find comment="x y"]')
    require_destructive_ssh('/ip/firewall/filter/remove [find comment="x y"]')
