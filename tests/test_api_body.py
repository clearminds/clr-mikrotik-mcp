"""Tests for mikrotik_api's `body` argument.

The first attempt at accepting a JSON-string body added a coercion helper but
left the annotation as ``dict[str, Any] | None``. FastMCP validates arguments
against the annotation BEFORE the function body runs, so the helper never
executed and the call was still rejected with:

    body: Input should be a valid dictionary

Testing the helper alone would not have caught that — the bug lived in the
generated schema. These tests assert both halves.
"""

from __future__ import annotations

import asyncio

import pytest
from fastmcp.exceptions import ToolError

from clr_mikrotik_mcp.server import _coerce_body, mcp


def _body_schema() -> dict:
    async def get() -> dict:
        tools = await mcp.get_tools()
        return tools["mikrotik_api"].parameters["properties"]["body"]

    return asyncio.run(get())


def test_schema_accepts_a_json_string() -> None:
    """The contract must admit a string, or the coercion below is unreachable."""
    types = {opt.get("type") for opt in _body_schema()["anyOf"]}
    assert "string" in types, (
        "mikrotik_api.body must accept a string: clients that serialize nested "
        "arguments are otherwise rejected before _coerce_body can parse them"
    )


def test_schema_still_accepts_an_object_and_null() -> None:
    types = {opt.get("type") for opt in _body_schema()["anyOf"]}
    assert "object" in types
    assert "null" in types


def test_coerce_body_passes_objects_through() -> None:
    assert _coerce_body({"address": "10.0.0.1/24"}) == {"address": "10.0.0.1/24"}
    assert _coerce_body(None) is None


def test_coerce_body_parses_a_json_string() -> None:
    assert _coerce_body('{"address": "10.0.0.1/24"}') == {"address": "10.0.0.1/24"}


def test_coerce_body_treats_blank_as_absent() -> None:
    assert _coerce_body("   ") is None


def test_coerce_body_rejects_non_objects() -> None:
    with pytest.raises(ToolError):
        _coerce_body("[1, 2, 3]")
    with pytest.raises(ToolError):
        _coerce_body("{not json")
