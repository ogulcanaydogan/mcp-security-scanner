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


def test_strip_ansi_sequences_removes_terminal_codes():
    module = _load_release_consistency_module()

    raw = "\x1b[31mERROR\x1b[0m plain-text"
    assert module._strip_ansi_sequences(raw) == "ERROR plain-text"


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


def test_extract_available_versions_line_strips_ansi_and_whitespace():
    module = _load_release_consistency_module()

    pip_output = "\n demo-pkg (1.0.21)\n  \x1b[32mAvailable versions: 1.0.21, 1.0.20\x1b[0m\n"
    line = module._extract_available_versions_line(pip_output)
    assert line == "Available versions: 1.0.21, 1.0.20"


def test_build_pypi_visibility_pip_command_uses_official_index_no_cache():
    module = _load_release_consistency_module()

    command = module._build_pypi_visibility_pip_command(
        package_name="demo-pkg",
        expected_version="1.0.23",
        index_url="https://pypi.org/simple",
        pip_timeout_seconds=17,
    )

    assert command[:3] == [module.sys.executable, "-m", "pip"]
    assert "--no-cache-dir" in command
    assert "--index-url" in command
    assert "https://pypi.org/simple" in command
    assert "--timeout" in command
    assert "17" in command
    assert command[-1] == "demo-pkg"
    assert "--pre" not in command


def test_build_pypi_visibility_pip_command_adds_pre_for_prerelease():
    module = _load_release_consistency_module()

    command = module._build_pypi_visibility_pip_command(
        package_name="demo-pkg",
        expected_version="1.0.24rc1",
        index_url="https://pypi.org/simple",
        pip_timeout_seconds=15,
    )
    assert "--pre" in command


def test_build_pypi_visibility_pip_env_sets_deterministic_flags():
    module = _load_release_consistency_module()

    pip_env = module._build_pypi_visibility_pip_env("https://pypi.org/simple")
    assert pip_env["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert pip_env["PIP_NO_CACHE_DIR"] == "1"
    assert pip_env["PIP_INDEX_URL"] == "https://pypi.org/simple"


def test_build_pypi_retry_wait_message_includes_next_attempt():
    module = _load_release_consistency_module()

    message = module._build_pypi_retry_wait_message(sleep_seconds=7, next_attempt=3)
    assert message == "sleep_seconds=7 next_attempt=3"


def test_build_pypi_visibility_start_message_is_deterministic():
    module = _load_release_consistency_module()

    message = module._build_pypi_visibility_start_message(
        package_name="demo-pkg",
        expected_version="1.0.29",
        index_url="https://pypi.org/simple",
        attempts=12,
        pip_timeout_seconds=15,
    )
    assert message == "package=demo-pkg expected=1.0.29 index=https://pypi.org/simple attempts=12 timeout=15"


def test_build_pypi_lookup_failed_message_is_deterministic():
    module = _load_release_consistency_module()

    message = module._build_pypi_lookup_failed_message(returncode=1, combined_output="network timeout")
    assert message == "rc=1 output=network timeout"


def test_build_pypi_visibility_failed_message_is_deterministic():
    module = _load_release_consistency_module()

    message = module._build_pypi_visibility_failed_message(
        expected_version="1.0.28",
        last_status="version_not_visible",
        last_output="available=1.0.27",
    )
    assert message == "expected=1.0.28 last_status=version_not_visible last_output=available=1.0.27"


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
    assert (
        "[pypi-visibility attempt 1/2] status=check_start "
        "package=demo-pkg expected=1.0.21 index=https://pypi.org/simple attempts=2 timeout=15"
    ) in output
    assert "[pypi-visibility attempt 1/2] status=lookup_failed" in output
    assert "0xADDR" in output
    assert "0x10b99e5d0" not in output
    assert "[pypi-visibility attempt 1/2] status=retry_wait sleep_seconds=7 next_attempt=2" in output
    assert "[pypi-visibility attempt 2/2] status=visibility_verified package=demo-pkg version=1.0.21" in output
    assert sleep_calls == [7]


def test_verify_pypi_visibility_failure_uses_normalized_last_output(monkeypatch, capsys):
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
    output = capsys.readouterr().out
    assert "[pypi-visibility attempt 1/1] status=visibility_failed expected=1.0.21 last_status=lookup_failed" in output


def test_verify_pypi_visibility_logs_version_not_visible_then_failure(monkeypatch, capsys):
    module = _load_release_consistency_module()

    responses = [
        subprocess.CompletedProcess(
            args=["pip", "index", "versions"],
            returncode=0,
            stdout="demo-pkg (1.0.21)\nAvailable versions: 1.0.20, 1.0.19",
            stderr="",
        ),
        subprocess.CompletedProcess(
            args=["pip", "index", "versions"],
            returncode=0,
            stdout="demo-pkg (1.0.21)\nAvailable versions: 1.0.20",
            stderr="",
        ),
    ]
    sleep_calls: list[int] = []

    def fake_run(*args, **kwargs):
        del args, kwargs
        return responses.pop(0)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    with pytest.raises(module.ReleaseValidationError):
        module._verify_pypi_version_visibility(
            package_name="demo-pkg",
            expected_version="1.0.21",
            index_url="https://pypi.org/simple",
            attempts=2,
            sleep_seconds=3,
            pip_timeout_seconds=15,
        )

    output = capsys.readouterr().out
    assert "[pypi-visibility attempt 1/2] status=version_not_visible expected=1.0.21" in output
    assert "[pypi-visibility attempt 1/2] status=retry_wait sleep_seconds=3 next_attempt=2" in output
    assert (
        "[pypi-visibility attempt 2/2] status=visibility_failed expected=1.0.21 last_status=version_not_visible"
        in output
    )
    assert sleep_calls == [3]


def test_verify_pypi_visibility_missing_versions_line_logs_normalized_output(monkeypatch, capsys):
    module = _load_release_consistency_module()

    response = subprocess.CompletedProcess(
        args=["pip", "index", "versions"],
        returncode=0,
        stdout="\x1b[33mdemo-pkg (1.0.21)\x1b[0m\nNo versions found output",
        stderr="",
    )

    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: response)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)

    with pytest.raises(module.ReleaseValidationError):
        module._verify_pypi_version_visibility(
            package_name="demo-pkg",
            expected_version="1.0.21",
            index_url="https://pypi.org/simple",
            attempts=1,
            sleep_seconds=1,
            pip_timeout_seconds=15,
        )

    output = capsys.readouterr().out
    assert "<missing versions line> output=demo-pkg (1.0.21) No versions found output" in output
