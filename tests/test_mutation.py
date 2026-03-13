"""Tests for baseline/mutation helpers."""

import json

import pytest

from mcp_security_scanner.discovery import ToolDefinition
from mcp_security_scanner.mutation import (
    BASELINE_SCHEMA_VERSION,
    build_baseline_document,
    build_tool_snapshot,
    canonical_json,
    compare_tool_snapshots,
    hash_payload,
    index_tool_snapshots,
    validate_baseline_document,
)


def _tool(name: str, description: str, input_schema: dict[str, object]) -> ToolDefinition:
    """Build a ToolDefinition for mutation tests."""
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=input_schema,
    )


class TestMutationHelpers:
    """Mutation module behavior tests."""

    def test_canonical_json_is_deterministic(self):
        """Canonical serialization should sort keys deterministically."""
        value = {"b": 2, "a": 1}
        assert canonical_json(value) == '{"a":1,"b":2}'

    def test_hash_payload_is_stable_for_equivalent_dicts(self):
        """Equivalent dicts with different key order should hash the same."""
        left = {"a": {"x": 1, "y": 2}, "b": [1, 2]}
        right = {"b": [1, 2], "a": {"y": 2, "x": 1}}
        assert hash_payload(left) == hash_payload(right)

    def test_build_tool_snapshot_contains_hashes_and_metadata(self):
        """Tool snapshot should include per-field and overall hashes."""
        snapshot = build_tool_snapshot(
            _tool(
                "safe_echo",
                "Echo input safely",
                {"type": "object", "properties": {"value": {"type": "string"}}},
            )
        )

        assert snapshot["name"] == "safe_echo"
        assert snapshot["description_hash"]
        assert snapshot["input_schema_hash"]
        assert snapshot["overall_hash"]
        assert snapshot["output_schema_hash"] is None
        assert snapshot["metadata"]["description"] == "Echo input safely"

    def test_build_baseline_document_includes_schema_and_sorted_tools(self):
        """Baseline document should be baseline-v1 and sort tool names."""
        tools = [
            _tool("z_tool", "z desc", {"type": "object"}),
            _tool("a_tool", "a desc", {"type": "object"}),
        ]

        baseline = build_baseline_document(
            scanner_version="0.1.0",
            server_name="demo",
            command="python demo.py",
            tools=tools,
        )

        assert baseline["schema_version"] == BASELINE_SCHEMA_VERSION
        assert baseline["server"]["name"] == "demo"
        assert baseline["server"]["command"] == "python demo.py"
        assert [item["name"] for item in baseline["tools"]] == ["a_tool", "z_tool"]
        assert baseline["created_at"].endswith("Z")

    @pytest.mark.parametrize(
        ("payload", "message"),
        [
            ([], "must be a JSON object"),
            ({}, "Unsupported baseline schema_version"),
            ({"schema_version": BASELINE_SCHEMA_VERSION, "tools": {}}, "'tools' field must be a list"),
            (
                {"schema_version": BASELINE_SCHEMA_VERSION, "tools": [1]},
                "tool entry must be an object",
            ),
            (
                {"schema_version": BASELINE_SCHEMA_VERSION, "tools": [{"name": "", "overall_hash": "x"}]},
                "must contain non-empty 'name'",
            ),
            (
                {"schema_version": BASELINE_SCHEMA_VERSION, "tools": [{"name": "x", "overall_hash": ""}]},
                "must contain non-empty 'overall_hash'",
            ),
        ],
    )
    def test_validate_baseline_document_rejects_invalid_shape(self, payload: object, message: str):
        """Validator should reject malformed baseline documents."""
        with pytest.raises(ValueError, match=message):
            validate_baseline_document(payload)

    def test_validate_baseline_document_accepts_valid_payload(self):
        """Validator should return valid baseline payload untouched."""
        payload = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "tools": [{"name": "safe_echo", "overall_hash": "abc123"}],
        }
        assert validate_baseline_document(payload) == payload

    def test_index_tool_snapshots_uses_name_as_key(self):
        """Snapshot indexer should map tool names to entries."""
        snapshots = [
            {"name": "safe_echo", "overall_hash": "a"},
            {"name": "dangerous_exec", "overall_hash": "b"},
        ]
        indexed = index_tool_snapshots(snapshots)
        assert set(indexed.keys()) == {"safe_echo", "dangerous_exec"}
        assert indexed["safe_echo"]["overall_hash"] == "a"

    def test_compare_tool_snapshots_detects_added_removed_changed(self):
        """Comparator should emit all mutation types with changed field details."""
        baseline_tools = index_tool_snapshots(
            [
                build_tool_snapshot(_tool("safe_echo", "Echo safely", {"type": "object"})),
                build_tool_snapshot(_tool("dangerous_exec", "Execute command", {"type": "object"})),
            ]
        )
        current_tools = index_tool_snapshots(
            [
                build_tool_snapshot(
                    _tool(
                        "dangerous_exec",
                        "Execute command with outbound network",
                        {"type": "object", "properties": {"cmd": {"type": "string"}}},
                    )
                ),
                build_tool_snapshot(_tool("new_network_tool", "Calls http APIs", {"type": "object"})),
            ]
        )

        mutations = compare_tool_snapshots(baseline_tools, current_tools)

        assert len(mutations) == 3
        mutation_types = {item["type"] for item in mutations}
        assert mutation_types == {"added", "removed", "changed"}

        changed = next(item for item in mutations if item["type"] == "changed")
        assert changed["tool_name"] == "dangerous_exec"
        assert "overall_hash" in changed["changed_fields"]
        assert "description_hash" in changed["changed_fields"]
        assert "input_schema_hash" in changed["changed_fields"]

    def test_compare_tool_snapshots_returns_empty_when_no_change(self):
        """Comparator should produce no mutations for identical snapshots."""
        snapshot = build_tool_snapshot(_tool("safe_echo", "Echo safely", {"type": "object"}))
        baseline_tools = index_tool_snapshots([json.loads(json.dumps(snapshot))])
        current_tools = index_tool_snapshots([json.loads(json.dumps(snapshot))])

        assert compare_tool_snapshots(baseline_tools, current_tools) == []
