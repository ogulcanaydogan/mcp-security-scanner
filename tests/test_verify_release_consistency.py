from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_release_consistency_module():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "verify_release_consistency.py"
    spec = importlib.util.spec_from_file_location("verify_release_consistency", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_normalize_retry_output_returns_empty_marker():
    module = _load_release_consistency_module()

    assert module._normalize_retry_output("   \n\t  ") == "<empty>"


def test_normalize_retry_output_masks_hex_addresses():
    module = _load_release_consistency_module()

    raw = "NewConnectionError('<HTTPSConnection object at 0x10b99e5d0>') retrying 0xABCDEF01"
    normalized = module._normalize_retry_output(raw)
    assert "0x10b99e5d0" not in normalized
    assert "0xABCDEF01" not in normalized
    assert normalized.count("0xADDR") == 2


def test_normalize_retry_output_truncates_deterministically():
    module = _load_release_consistency_module()

    normalized = module._normalize_retry_output("x" * 32, limit=10)
    assert normalized == "xxxxxxxxxx...<truncated>"
