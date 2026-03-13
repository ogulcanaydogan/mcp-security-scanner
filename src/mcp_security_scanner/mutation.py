"""Baseline snapshot and mutation comparison utilities."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from mcp_security_scanner.discovery import ToolDefinition

BASELINE_SCHEMA_VERSION = "baseline-v1"


def canonical_json(value: Any) -> str:
    """Return canonical JSON representation for deterministic hashing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_payload(value: Any) -> str:
    """Hash arbitrary payload using deterministic JSON encoding."""
    serialized = canonical_json(value)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_tool_snapshot(tool: ToolDefinition) -> dict[str, Any]:
    """Build deterministic baseline snapshot entry for a tool definition."""
    description_hash = hash_payload(tool.description)
    input_schema_hash = hash_payload(tool.input_schema)
    output_schema_hash = hash_payload(tool.output_schema) if tool.output_schema is not None else None

    hash_basis = {
        "name": tool.name,
        "description_hash": description_hash,
        "input_schema_hash": input_schema_hash,
        "output_schema_hash": output_schema_hash,
    }

    return {
        "name": tool.name,
        "description_hash": description_hash,
        "input_schema_hash": input_schema_hash,
        "output_schema_hash": output_schema_hash,
        "overall_hash": hash_payload(hash_basis),
        "metadata": {
            "description": tool.description,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
        },
    }


def build_baseline_document(
    scanner_version: str,
    server_name: str,
    command: str,
    tools: list[ToolDefinition],
) -> dict[str, Any]:
    """Create baseline-v1 JSON document from discovered tool definitions."""
    snapshots = [build_tool_snapshot(tool) for tool in tools]
    snapshots.sort(key=lambda item: item["name"])

    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "scanner_version": scanner_version,
        "created_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "server": {
            "name": server_name,
            "command": command,
        },
        "tools": snapshots,
    }


def validate_baseline_document(data: Any) -> dict[str, Any]:
    """Validate baseline-v1 payload and return normalized document."""
    if not isinstance(data, dict):
        raise ValueError("Baseline document must be a JSON object.")

    schema_version = data.get("schema_version")
    if schema_version != BASELINE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported baseline schema_version: {schema_version!r}. "
            f"Expected {BASELINE_SCHEMA_VERSION!r}."
        )

    tools = data.get("tools")
    if not isinstance(tools, list):
        raise ValueError("Baseline document 'tools' field must be a list.")

    for tool in tools:
        if not isinstance(tool, dict):
            raise ValueError("Each baseline tool entry must be an object.")
        if not isinstance(tool.get("name"), str) or not tool["name"].strip():
            raise ValueError("Each baseline tool entry must contain non-empty 'name'.")
        if not isinstance(tool.get("overall_hash"), str) or not tool["overall_hash"].strip():
            raise ValueError("Each baseline tool entry must contain non-empty 'overall_hash'.")

    return data


def index_tool_snapshots(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Index baseline tool snapshots by tool name."""
    indexed: dict[str, dict[str, Any]] = {}
    for tool in tools:
        name = tool["name"]
        indexed[name] = tool
    return indexed


def compare_tool_snapshots(
    baseline_tools: dict[str, dict[str, Any]],
    current_tools: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compare indexed snapshots and return deterministic mutation records."""
    mutations: list[dict[str, Any]] = []

    baseline_names = set(baseline_tools)
    current_names = set(current_tools)

    for name in sorted(current_names - baseline_names):
        mutations.append(
            {
                "type": "added",
                "tool_name": name,
                "baseline": None,
                "current": current_tools[name],
                "changed_fields": [],
            }
        )

    for name in sorted(baseline_names - current_names):
        mutations.append(
            {
                "type": "removed",
                "tool_name": name,
                "baseline": baseline_tools[name],
                "current": None,
                "changed_fields": [],
            }
        )

    comparable_fields = ["description_hash", "input_schema_hash", "output_schema_hash", "overall_hash"]
    for name in sorted(current_names & baseline_names):
        baseline_item = baseline_tools[name]
        current_item = current_tools[name]

        if baseline_item.get("overall_hash") == current_item.get("overall_hash"):
            continue

        changed_fields = [
            field
            for field in comparable_fields
            if baseline_item.get(field) != current_item.get(field)
        ]

        mutations.append(
            {
                "type": "changed",
                "tool_name": name,
                "baseline": baseline_item,
                "current": current_item,
                "changed_fields": changed_fields,
            }
        )

    return mutations
