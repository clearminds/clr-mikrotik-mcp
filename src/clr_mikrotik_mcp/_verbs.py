"""Verb-guard helpers for mikrotik_ssh / mikrotik_api splits."""

from __future__ import annotations

import re

from fastmcp.exceptions import ToolError

_READ_VERBS = frozenset({"print", "get", "getall", "find", "monitor", "export"})
_DESTRUCTIVE_VERBS = frozenset({"remove", "reset-configuration", "reboot", "shutdown"})


def _segment_verbs(command: str) -> list[str]:
    """Extract the verb of each ``;``- or newline-separated segment.

    RouterOS CLI verbs sit at the end of the path-and-verb prefix and before
    any arguments. We tokenize the segment, drop arg-like tokens (containing
    ``=`` or starting with ``[``), then take the last "bare" identifier
    (one that does not start with ``/`` or ``:``).

    Examples::

        "/interface print"            -> ["print"]
        "/ip address print"           -> ["print"]
        "/system identity get"        -> ["get"]
        "/system reboot"              -> ["reboot"]
        "/export"                     -> ["export"]   (fallback: strip leading /)
        "/ip address remove [find]"   -> ["remove"]
        "/interface set ether1 d=y"   -> ["ether1"]   (set takes a positional;
                                                       the last bare token is
                                                       the positional, which is
                                                       not a known read verb,
                                                       so the read-guard rejects)
    """
    verbs: list[str] = []
    for raw in re.split(r"[\n;]", command):
        seg = raw.strip()
        if not seg:
            continue
        # Drop arg-like tokens: foo=bar (kwargs) and [find ...] (script blocks).
        toks = [t for t in seg.split() if "=" not in t and not t.startswith("[")]
        # Verb = last bare identifier (not a /path or :directive).
        verb = ""
        for t in reversed(toks):
            if not t.startswith("/") and not t.startswith(":"):
                verb = t.lower()
                break
        # Fallback for verb-only segments like "/export": strip leading slashes
        # from the last token so "/export" -> "export".
        if not verb and toks:
            tail = toks[-1].lstrip("/")
            if tail and not tail.startswith(":"):
                verb = tail.lower()
        if verb:
            verbs.append(verb)
    return verbs


def require_read_only_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment of ``command`` is not a read verb."""
    for v in _segment_verbs(command):
        if v not in _READ_VERBS:
            raise ToolError(
                f"Verb {v!r} not allowed in mikrotik_ssh_read; "
                f"use mikrotik_ssh or mikrotik_ssh_destructive instead."
            )


def require_destructive_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment is not a destructive verb."""
    for v in _segment_verbs(command):
        if v not in _DESTRUCTIVE_VERBS:
            raise ToolError(
                f"Verb {v!r} is not destructive; "
                f"use mikrotik_ssh or mikrotik_ssh_read instead."
            )


def reject_destructive_ssh(command: str) -> None:
    """Raise ``ToolError`` if any segment is a destructive verb."""
    for v in _segment_verbs(command):
        if v in _DESTRUCTIVE_VERBS:
            raise ToolError(
                f"Verb {v!r} is destructive; "
                f"use mikrotik_ssh_destructive instead."
            )


def require_get_method(method: str) -> None:
    """For mikrotik_api_read: only GET allowed."""
    if method.upper() != "GET":
        raise ToolError(
            f"method={method!r} not allowed in mikrotik_api_read; "
            f"use mikrotik_api or mikrotik_api_destructive instead."
        )


def require_delete_method(method: str) -> None:
    """For mikrotik_api_destructive: only DELETE allowed."""
    if method.upper() != "DELETE":
        raise ToolError(
            f"method={method!r} is not destructive; "
            f"use mikrotik_api or mikrotik_api_read instead."
        )


def reject_delete_method(method: str) -> None:
    """For mikrotik_api: refuse DELETE (use destructive variant)."""
    if method.upper() == "DELETE":
        raise ToolError(
            "method=DELETE is destructive; use mikrotik_api_destructive instead."
        )
