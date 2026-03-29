from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest


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


def test_verify_pypi_visibility_logs_retry_then_success_deterministically(monkeypatch, capsys):
    module = _load_release_consistency_module()

    responses = [
        subprocess.CompletedProcess(
            args=["pip", "index", "versions"],
            returncode=1,
            stdout="",
            stderr="NewConnectionError('<HTTPSConnection object at 0x10b99e5d0>')",
        ),
        subprocess.CompletedProcess(
            args=["pip", "index", "versions"],
            returncode=0,
            stdout="demo-pkg (1.0.21)\nAvailable versions: 1.0.21, 1.0.20",
            stderr="",
        ),
    ]
    sleep_calls: list[int] = []

    def fake_run(*args, **kwargs):
        del args, kwargs
        return responses.pop(0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    module._verify_pypi_version_visibility(
        package_name="demo-pkg",
        expected_version="1.0.21",
        index_url="https://pypi.org/simple",
        attempts=2,
        sleep_seconds=7,
        pip_timeout_seconds=15,
    )

    output = capsys.readouterr().out
    assert "[pypi-visibility attempt 1/2] status=lookup_failed" in output
    assert "0xADDR" in output
    assert "0x10b99e5d0" not in output
    assert "[pypi-visibility attempt 1/2] status=retry_wait sleep_seconds=7" in output
    assert "[pypi-visibility attempt 2/2] status=visibility_verified package=demo-pkg version=1.0.21" in output
    assert sleep_calls == [7]


def test_verify_pypi_visibility_failure_uses_normalized_last_output(monkeypatch):
    module = _load_release_consistency_module()
    response = subprocess.CompletedProcess(
        args=["pip", "index", "versions"],
        returncode=1,
        stdout="",
        stderr="temporary failure at 0xABCDEF01",
    )

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: response)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    with pytest.raises(module.ReleaseValidationError) as exc_info:
        module._verify_pypi_version_visibility(
            package_name="demo-pkg",
            expected_version="1.0.21",
            index_url="https://pypi.org/simple",
            attempts=1,
            sleep_seconds=1,
            pip_timeout_seconds=15,
        )

    message = str(exc_info.value)
    assert "Last output: temporary failure at 0xADDR" in message
    assert "0xABCDEF01" not in message
