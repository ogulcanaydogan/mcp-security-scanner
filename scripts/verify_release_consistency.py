#!/usr/bin/env python3
"""Verify release-version consistency across source, wheel metadata, and CLI."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path


class ReleaseValidationError(RuntimeError):
    """Raised when release/version consistency checks fail."""


def _normalize_tag_version(raw_tag_version: str) -> str:
    """Normalize Git tag prerelease format (e.g. 1.0.0-rc1 -> 1.0.0rc1)."""
    return re.sub(r"-([ab]|rc)", r"\1", raw_tag_version)


def _read_project_version(pyproject_path: Path) -> str:
    """Read project version from pyproject.toml."""
    payload = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project = payload.get("project")
    if not isinstance(project, dict):
        raise ReleaseValidationError("Invalid pyproject.toml: missing [project] table.")
    version = project.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ReleaseValidationError("Invalid pyproject.toml: missing project.version.")
    return version.strip()


def _read_init_version(init_file: Path) -> str:
    """Extract __version__ from package __init__.py."""
    content = init_file.read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', content, re.MULTILINE)
    if match is None:
        raise ReleaseValidationError(f"Unable to parse __version__ from {init_file}.")
    return match.group(1).strip()


def _read_wheel_version(dist_dir: Path) -> tuple[Path, str]:
    """Read version from built wheel METADATA."""
    wheel_paths = sorted(dist_dir.glob("*.whl"))
    if not wheel_paths:
        raise ReleaseValidationError(f"Missing wheel artifact in {dist_dir}.")
    wheel_path = wheel_paths[0]

    with zipfile.ZipFile(wheel_path) as wheel:
        metadata_candidates = sorted(name for name in wheel.namelist() if name.endswith(".dist-info/METADATA"))
        if not metadata_candidates:
            raise ReleaseValidationError(f"Missing wheel METADATA entry in {wheel_path.name}.")
        metadata = wheel.read(metadata_candidates[0]).decode("utf-8")

    for line in metadata.splitlines():
        if line.startswith("Version: "):
            return wheel_path, line.split(":", 1)[1].strip()
    raise ReleaseValidationError(f"Unable to read Version from wheel METADATA in {wheel_path.name}.")


def _run_command(command: list[str]) -> str:
    """Run a shell command and return stdout or raise with stderr context."""
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        details = stderr or stdout or f"exit={result.returncode}"
        raise ReleaseValidationError(f"Command failed ({' '.join(command)}): {details}")
    return result.stdout.strip()


def _extract_cli_version(cli_output: str) -> str:
    """Extract semantic version from `mcp-scan --version` output."""
    match = re.search(r"version\s+([0-9A-Za-z.+-]+)", cli_output)
    if match is not None:
        return match.group(1).strip()
    tokens = cli_output.strip().split()
    if tokens:
        return tokens[-1].strip()
    raise ReleaseValidationError("Unable to parse CLI version from mcp-scan --version output.")


def _validate_build_and_cli(dist_dir: Path) -> tuple[str, str, str, str]:
    """Validate pyproject/init/wheel/CLI versions are consistent."""
    project_version = _read_project_version(Path("pyproject.toml"))
    init_version = _read_init_version(Path("src/mcp_security_scanner/__init__.py"))
    wheel_path, wheel_version = _read_wheel_version(dist_dir)

    if project_version != init_version:
        raise ReleaseValidationError(
            f"pyproject version ({project_version}) does not match __version__ ({init_version})."
        )
    if project_version != wheel_version:
        raise ReleaseValidationError(
            f"pyproject version ({project_version}) does not match wheel metadata version ({wheel_version})."
        )

    _run_command([sys.executable, "-m", "pip", "install", "--force-reinstall", str(wheel_path)])
    cli_output = _run_command(["mcp-scan", "--version"])
    cli_version = _extract_cli_version(cli_output)
    if cli_version != project_version:
        raise ReleaseValidationError(
            f"Installed CLI version ({cli_version}) does not match project version ({project_version})."
        )

    return project_version, init_version, wheel_version, cli_version


def _validate_publish_artifacts(dist_dir: Path, expected_version: str) -> None:
    """Validate dist artifacts are present and aligned with expected version."""
    if not list(dist_dir.glob("*.tar.gz")):
        raise ReleaseValidationError(f"sdist artifact missing in {dist_dir}.")
    if not list(dist_dir.glob("*.whl")):
        raise ReleaseValidationError(f"wheel artifact missing in {dist_dir}.")
    if not any(expected_version in path.name for path in dist_dir.iterdir() if path.is_file()):
        raise ReleaseValidationError(f"Built artifacts do not include version {expected_version}.")


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("build", "publish"), required=True, help="Validation mode.")
    parser.add_argument(
        "--dist-dir",
        default="dist",
        help="Distribution directory containing wheel/sdist artifacts.",
    )
    parser.add_argument(
        "--tag-version",
        default=None,
        help="Raw tag version without refs/tags/v prefix (required for publish mode).",
    )
    args = parser.parse_args()

    dist_dir = Path(args.dist_dir)
    if not dist_dir.exists() or not dist_dir.is_dir():
        raise ReleaseValidationError(f"Distribution directory does not exist: {dist_dir}")

    project_version, init_version, wheel_version, cli_version = _validate_build_and_cli(dist_dir=dist_dir)

    if args.mode == "publish":
        if not isinstance(args.tag_version, str) or not args.tag_version.strip():
            raise ReleaseValidationError("--tag-version is required in publish mode.")
        tag_version_raw = args.tag_version.strip()
        tag_version = _normalize_tag_version(tag_version_raw)

        if tag_version != project_version:
            raise ReleaseValidationError(
                f"Tag version ({tag_version_raw} -> normalized {tag_version}) does not match "
                f"pyproject version ({project_version})."
            )
        if tag_version != init_version:
            raise ReleaseValidationError(
                f"Tag version ({tag_version_raw} -> normalized {tag_version}) does not match "
                f"__version__ ({init_version})."
            )
        if tag_version != wheel_version:
            raise ReleaseValidationError(
                f"Tag version ({tag_version_raw} -> normalized {tag_version}) does not match "
                f"wheel metadata version ({wheel_version})."
            )
        if tag_version != cli_version:
            raise ReleaseValidationError(
                f"Installed CLI version ({cli_version}) does not match "
                f"tag version ({tag_version_raw} -> normalized {tag_version})."
            )
        _validate_publish_artifacts(dist_dir=dist_dir, expected_version=project_version)

    print(
        "Release consistency verified: "
        f"project={project_version}, init={init_version}, wheel={wheel_version}, cli={cli_version}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseValidationError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
