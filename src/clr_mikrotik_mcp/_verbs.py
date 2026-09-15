"""Verb-guard helpers for ssh / api splits."""

from __future__ import annotations

import re
import shlex

from fastmcp.exceptions import ToolError

_READ_VERBS = frozenset({"print", "get", "getall", "find", "monitor", "export"})
_DESTRUCTIVE_VERBS = frozenset({"remove", "reset-configuration", "reboot", "shutdown"})


def _tokenize(segment: str) -> list[str]:
    """Split a segment into tokens, keeping quoted spans together.

    ``str.split()`` tears ``comment="Allow Odoo CRM - web"`` into five tokens,
    four of which look like bare identifiers. That made the verb resolve to
    ``web"`` and rejected a perfectly ordinary command.
    """
    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        # Unbalanced quotes — fall back rather than refuse to classify.
        return segment.split()


def _segment_verbs(command: str) -> list[str]:
    """Extract the verb of each ``;``- or newline-separated segment.

    RouterOS accepts the verb either as the last word of a space-separated
    path (``/ip address print``) or as the final element of a slash path
    (``/ip/address/print``). Both are handled.

    The verb always appears BEFORE the first argument, so tokens from the
    first argument onward are never considered. An argument is ``key=value``
    or a ``[...]`` script block.

    Examples::

        "/interface print"                     -> ["print"]
        "/system identity get"                 -> ["get"]
        "/system reboot"                       -> ["reboot"]
        "/export"                              -> ["export"]
        "/ip address remove [find]"            -> ["remove"]
        "/ipv6/firewall/filter/add comment=\"a b\"" -> ["add"]
        "/ipv6/firewall/filter/move numbers=1" -> ["move"]
        "/interface set ether1 d=y"            -> ["ether1"]  (positional; the
                                                   read-guard rejects it, which
                                                   is the intended behaviour)
    """
    verbs: list[str] = []
    for raw in re.split(r"[\n;]", command):
        seg = raw.strip()
        if not seg:
            continue
        # The verb precedes the first argument; stop there.
        head: list[str] = []
        for tok in _tokenize(seg):
            if "=" in tok or tok.startswith("["):
                break
            head.append(tok)
        verb = ""
        for tok in reversed(head):
            if tok.startswith(":"):
                continue
            if tok.startswith("/"):
                # Slash form: the verb is the final path segment.
                tail = tok.rstrip("/").rsplit("/", 1)[-1]
                if tail and not tail.startswith(":"):
                    verb = tail.lower()
                break
            verb = tok.lower()
            break
        if verb:
            verbs.append(verb)
    return verbs


def require_read_only_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment of ``command`` is not a read verb."""
    for v in _segment_verbs(command):
        if v not in _READ_VERBS:
            raise ToolError(
                f"Verb {v!r} not allowed in ssh_read; "
                f"use ssh or ssh_destructive instead."
            )


def require_destructive_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment is not a destructive verb."""
    for v in _segment_verbs(command):
        if v not in _DESTRUCTIVE_VERBS:
            raise ToolError(
                f"Verb {v!r} is not destructive; "
                f"use ssh or ssh_read instead."
            )


def reject_destructive_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment is a destructive verb."""
    for v in _segment_verbs(command):
        if v in _DESTRUCTIVE_VERBS:
            raise ToolError(
                f"Verb {v!r} is destructive; "
                f"use ssh_destructive instead."
            )


def require_get_method(method: str) -> None:
    """For api_read: only GET allowed."""
    if method.upper() != "GET":
        raise ToolError(
            f"method={method!r} not allowed in api_read; "
            f"use api or api_destructive instead."
        )


def require_delete_method(method: str) -> None:
    """For api_destructive: only DELETE allowed."""
    if method.upper() != "DELETE":
        raise ToolError(
            f"method={method!r} is not destructive; "
            f"use api or api_read instead."
        )


def reject_delete_method(method: str) -> None:
    """For api: refuse DELETE (use destructive variant)."""
    if method.upper() == "DELETE":
        raise ToolError(
            "method=DELETE is destructive; use api_destructive instead."
        )
