"""
CLI interface for the MCP Security Scanner.

Provides commands to scan MCP servers, generate reports, and manage baselines.
Uses Click for argument parsing and Rich for formatted output.
"""

import asyncio
import base64
import hashlib
import importlib
import json
import os
import re
import secrets
import shlex
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, parse_qsl, quote, urlencode, urlparse, urlunparse

import click
import httpx
from rich.console import Console

import mcp_security_scanner
from mcp_security_scanner.analyzers.base import Finding, Severity
from mcp_security_scanner.analyzers.cross_tool import CrossToolAnalyzer
from mcp_security_scanner.analyzers.dynamic import DynamicAnalyzer
from mcp_security_scanner.analyzers.escalation import EscalationAnalyzer
from mcp_security_scanner.analyzers.injection import PromptInjectionAnalyzer
from mcp_security_scanner.analyzers.poisoning import ToolPoisoningAnalyzer
from mcp_security_scanner.analyzers.static import StaticAnalyzer
from mcp_security_scanner.discovery import MCPServerConnector, ServerCapabilities
from mcp_security_scanner.mutation import (
    build_baseline_document,
    build_tool_snapshot,
    compare_tool_snapshots,
    index_tool_snapshots,
    validate_baseline_document,
)
from mcp_security_scanner.reporter import ReportGenerator, ScanReport

_OAUTH_TOKEN_CACHE_SKEW_SECONDS = 30.0
_OAUTH_TOKEN_CACHE: dict[str, dict[str, Any]] = {}
_SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = {"client_secret_post", "client_secret_basic", "private_key_jwt"}
_OAUTH_CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
_OAUTH_AUTH_TYPES = {"oauth_client_credentials", "oauth_device_code", "oauth_auth_code_pkce"}
_OAUTH_CACHE_BACKEND_LOCAL = "local"
_OAUTH_CACHE_BACKEND_AWS_SECRETS_MANAGER = "aws_secrets_manager"
_OAUTH_CACHE_BACKEND_AWS_SSM_PARAMETER_STORE = "aws_ssm_parameter_store"
_OAUTH_CACHE_BACKEND_GCP_SECRET_MANAGER = "gcp_secret_manager"
_OAUTH_CACHE_BACKEND_AZURE_KEY_VAULT = "azure_key_vault"
_OAUTH_CACHE_BACKEND_HASHICORP_VAULT = "hashicorp_vault"
_OAUTH_CACHE_BACKEND_KUBERNETES_SECRETS = "kubernetes_secrets"
_OAUTH_CACHE_BACKEND_OCI_VAULT = "oci_vault"
_OAUTH_CACHE_BACKEND_DOPPLER_SECRETS = "doppler_secrets"
_OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT = "onepassword_connect"
_OAUTH_CACHE_BACKEND_BITWARDEN_SECRETS = "bitwarden_secrets"
_OAUTH_CACHE_BACKEND_INFISICAL_SECRETS = "infisical_secrets"
_OAUTH_CACHE_BACKEND_AKEYLESS_SECRETS = "akeyless_secrets"
_OAUTH_CACHE_BACKEND_GITLAB_VARIABLES = "gitlab_variables"
_OAUTH_CACHE_BACKEND_GITLAB_GROUP_VARIABLES = "gitlab_group_variables"
_OAUTH_CACHE_BACKEND_GITLAB_INSTANCE_VARIABLES = "gitlab_instance_variables"
_OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES = "github_actions_variables"
_OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES = "github_environment_variables"
_OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES = "github_organization_variables"
_OAUTH_CACHE_BACKEND_CONSUL_KV = "consul_kv"
_OAUTH_CACHE_BACKEND_REDIS_KV = "redis_kv"
_OAUTH_CACHE_BACKEND_CLOUDFLARE_KV = "cloudflare_kv"
_OAUTH_CACHE_BACKEND_ETCD_KV = "etcd_kv"


@dataclass(frozen=True)
class GitLabOAuthCacheBackendCapability:
    """Canonical capability contract for GitLab OAuth cache backends."""

    path_prefix: str
    identifier_field: str | None
    supports_environment_scope: bool


_GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES: dict[str, GitLabOAuthCacheBackendCapability] = {
    _OAUTH_CACHE_BACKEND_GITLAB_VARIABLES: GitLabOAuthCacheBackendCapability(
        path_prefix="/projects",
        identifier_field="gitlab_project_id",
        supports_environment_scope=True,
    ),
    _OAUTH_CACHE_BACKEND_GITLAB_GROUP_VARIABLES: GitLabOAuthCacheBackendCapability(
        path_prefix="/groups",
        identifier_field="gitlab_group_id",
        supports_environment_scope=True,
    ),
    _OAUTH_CACHE_BACKEND_GITLAB_INSTANCE_VARIABLES: GitLabOAuthCacheBackendCapability(
        path_prefix="/admin/ci",
        identifier_field=None,
        supports_environment_scope=False,
    ),
}
_GITLAB_OAUTH_CACHE_BACKENDS = set(_GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES)

_OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS: dict[str, tuple[str, str]] = {
    _OAUTH_CACHE_BACKEND_AWS_SECRETS_MANAGER: (
        "_load_oauth_persistent_cache_entries_from_aws",
        "_persist_oauth_cache_entry_aws",
    ),
    _OAUTH_CACHE_BACKEND_AWS_SSM_PARAMETER_STORE: (
        "_load_oauth_persistent_cache_entries_from_aws_ssm",
        "_persist_oauth_cache_entry_aws_ssm",
    ),
    _OAUTH_CACHE_BACKEND_GCP_SECRET_MANAGER: (
        "_load_oauth_persistent_cache_entries_from_gcp",
        "_persist_oauth_cache_entry_gcp",
    ),
    _OAUTH_CACHE_BACKEND_AZURE_KEY_VAULT: (
        "_load_oauth_persistent_cache_entries_from_azure",
        "_persist_oauth_cache_entry_azure",
    ),
    _OAUTH_CACHE_BACKEND_HASHICORP_VAULT: (
        "_load_oauth_persistent_cache_entries_from_vault",
        "_persist_oauth_cache_entry_vault",
    ),
    _OAUTH_CACHE_BACKEND_KUBERNETES_SECRETS: (
        "_load_oauth_persistent_cache_entries_from_kubernetes",
        "_persist_oauth_cache_entry_kubernetes",
    ),
    _OAUTH_CACHE_BACKEND_OCI_VAULT: (
        "_load_oauth_persistent_cache_entries_from_oci",
        "_persist_oauth_cache_entry_oci",
    ),
    _OAUTH_CACHE_BACKEND_DOPPLER_SECRETS: (
        "_load_oauth_persistent_cache_entries_from_doppler",
        "_persist_oauth_cache_entry_doppler",
    ),
    _OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT: (
        "_load_oauth_persistent_cache_entries_from_onepassword_connect",
        "_persist_oauth_cache_entry_onepassword_connect",
    ),
    _OAUTH_CACHE_BACKEND_BITWARDEN_SECRETS: (
        "_load_oauth_persistent_cache_entries_from_bitwarden",
        "_persist_oauth_cache_entry_bitwarden",
    ),
    _OAUTH_CACHE_BACKEND_INFISICAL_SECRETS: (
        "_load_oauth_persistent_cache_entries_from_infisical",
        "_persist_oauth_cache_entry_infisical",
    ),
    _OAUTH_CACHE_BACKEND_AKEYLESS_SECRETS: (
        "_load_oauth_persistent_cache_entries_from_akeyless",
        "_persist_oauth_cache_entry_akeyless",
    ),
    _OAUTH_CACHE_BACKEND_GITLAB_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_gitlab",
        "_persist_oauth_cache_entry_gitlab",
    ),
    _OAUTH_CACHE_BACKEND_GITLAB_GROUP_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_gitlab",
        "_persist_oauth_cache_entry_gitlab",
    ),
    _OAUTH_CACHE_BACKEND_GITLAB_INSTANCE_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_gitlab",
        "_persist_oauth_cache_entry_gitlab",
    ),
    _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_github",
        "_persist_oauth_cache_entry_github",
    ),
    _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_github_environment",
        "_persist_oauth_cache_entry_github_environment",
    ),
    _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES: (
        "_load_oauth_persistent_cache_entries_from_github_organization",
        "_persist_oauth_cache_entry_github_organization",
    ),
    _OAUTH_CACHE_BACKEND_CONSUL_KV: (
        "_load_oauth_persistent_cache_entries_from_consul",
        "_persist_oauth_cache_entry_consul",
    ),
    _OAUTH_CACHE_BACKEND_REDIS_KV: (
        "_load_oauth_persistent_cache_entries_from_redis",
        "_persist_oauth_cache_entry_redis",
    ),
    _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV: (
        "_load_oauth_persistent_cache_entries_from_cloudflare",
        "_persist_oauth_cache_entry_cloudflare",
    ),
    _OAUTH_CACHE_BACKEND_ETCD_KV: (
        "_load_oauth_persistent_cache_entries_from_etcd",
        "_persist_oauth_cache_entry_etcd",
    ),
}
_SUPPORTED_OAUTH_CACHE_BACKENDS = {
    _OAUTH_CACHE_BACKEND_LOCAL,
    *_OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.keys(),
}
_OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS = {
    backend: loader_name
    for backend, (loader_name, _persister_name) in _OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
}
_OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS = {
    backend: persister_name
    for backend, (_loader_name, persister_name) in _OAUTH_REMOTE_PERSISTENT_CACHE_BACKEND_SPECS.items()
}
_OAUTH_CACHE_SCHEMA_VERSION_V1 = "v1"
_OAUTH_CACHE_SCHEMA_VERSION_V2 = "v2"
_OAUTH_PERSISTENT_CACHE_FILE = Path.home() / ".cache" / "mcp-security-scanner" / "oauth-cache-v1.json.enc"
_OAUTH_PERSISTENT_CACHE_LOCK_FILE = _OAUTH_PERSISTENT_CACHE_FILE.with_name("oauth-cache-v1.lock")
_OAUTH_PERSISTENT_KEY_FILE = Path.home() / ".config" / "mcp-security-scanner" / "cache.key"
_OAUTH_PERSISTENT_KEYRING_SERVICE = "mcp-security-scanner"
_OAUTH_PERSISTENT_KEYRING_USERNAME = "oauth-cache-key-v1"
_OAUTH_CACHE_LOCK_TIMEOUT_SECONDS = 2.0
_OAUTH_CACHE_LOCK_RETRY_SECONDS = 0.05
_OAUTH_HISTORICAL_KEY_LIMIT = 3
_OAUTH_FORM_REQUEST_MAX_RETRIES = 2
_OAUTH_FORM_REQUEST_BASE_BACKOFF_SECONDS = 0.2
_OAUTH_RETRYABLE_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}
_DOPPLER_DEFAULT_API_URL = "https://api.doppler.com"
_BITWARDEN_DEFAULT_API_URL = "https://api.bitwarden.com"
_INFISICAL_DEFAULT_API_URL = "https://app.infisical.com/api"
_AKEYLESS_DEFAULT_API_URL = "https://api.akeyless.io"
_GITLAB_DEFAULT_API_URL = "https://gitlab.com/api/v4"
_GITHUB_DEFAULT_API_URL = "https://api.github.com"
_CONSUL_DEFAULT_API_URL = "http://127.0.0.1:8500"
_REDIS_DEFAULT_URL = "redis://127.0.0.1:6379/0"
_CLOUDFLARE_DEFAULT_API_URL = "https://api.cloudflare.com/client/v4"
_ETCD_DEFAULT_API_URL = "http://127.0.0.1:2379"


@dataclass(frozen=True)
class OAuthCacheSettings:
    """Optional OAuth cache settings parsed from config auth.cache."""

    persistent: bool = False
    namespace: str = "default"
    backend: str = _OAUTH_CACHE_BACKEND_LOCAL
    aws_secret_id: str | None = None
    aws_ssm_parameter_name: str | None = None
    aws_region: str | None = None
    aws_endpoint_url: str | None = None
    gcp_secret_name: str | None = None
    gcp_endpoint_url: str | None = None
    azure_vault_url: str | None = None
    azure_secret_name: str | None = None
    azure_secret_version: str | None = "latest"
    vault_url: str | None = None
    vault_secret_path: str | None = None
    vault_token_env: str | None = None
    vault_namespace: str | None = None
    k8s_secret_namespace: str | None = None
    k8s_secret_name: str | None = None
    k8s_secret_key: str | None = None
    oci_secret_ocid: str | None = None
    oci_region: str | None = None
    oci_endpoint_url: str | None = None
    doppler_project: str | None = None
    doppler_config: str | None = None
    doppler_secret_name: str | None = None
    doppler_token_env: str | None = None
    doppler_api_url: str | None = None
    op_connect_host: str | None = None
    op_vault_id: str | None = None
    op_item_id: str | None = None
    op_field_label: str | None = None
    op_connect_token_env: str | None = None
    bw_secret_id: str | None = None
    bw_access_token_env: str | None = None
    bw_api_url: str | None = None
    infisical_project_id: str | None = None
    infisical_environment: str | None = None
    infisical_secret_name: str | None = None
    infisical_token_env: str | None = None
    infisical_api_url: str | None = None
    akeyless_secret_name: str | None = None
    akeyless_token_env: str | None = None
    akeyless_api_url: str | None = None
    gitlab_project_id: str | None = None
    gitlab_group_id: str | None = None
    gitlab_variable_key: str | None = None
    gitlab_environment_scope: str | None = None
    gitlab_token_env: str | None = None
    gitlab_api_url: str | None = None
    github_repository: str | None = None
    github_organization: str | None = None
    github_environment_name: str | None = None
    github_variable_name: str | None = None
    github_token_env: str | None = None
    github_api_url: str | None = None
    consul_key_path: str | None = None
    consul_token_env: str | None = None
    consul_api_url: str | None = None
    redis_key: str | None = None
    redis_url: str | None = None
    redis_password_env: str | None = None
    cf_account_id: str | None = None
    cf_namespace_id: str | None = None
    cf_kv_key: str | None = None
    cf_api_token_env: str | None = None
    cf_api_url: str | None = None
    etcd_key: str | None = None
    etcd_api_url: str | None = None
    etcd_token_env: str | None = None


@dataclass(frozen=True)
class OAuthCacheKeyMaterial:
    """Resolved OAuth cache encryption key metadata."""

    key_id: str
    fernet_key: bytes
    source: str


@dataclass(frozen=True)
class OAuthCacheKeySet:
    """Resolved OAuth cache key set with active and historical keys."""

    active: OAuthCacheKeyMaterial
    historical: tuple[OAuthCacheKeyMaterial, ...] = ()
    source: str = "unknown"


@dataclass(frozen=True)
class OAuthMTLSConfig:
    """Optional mTLS config used only for OAuth token endpoint requests."""

    cert_file: str
    key_file: str
    ca_bundle_file: str | None = None


@dataclass(frozen=True)
class OAuthPrivateKeyJWTSigner:
    """Private-key material used to sign OAuth private_key_jwt client assertions."""

    private_key_pem: str | None = None
    kid: str | None = None
    signing_source: str = "pem"
    kms_key_id: str | None = None
    kms_region: str | None = None
    kms_endpoint_url: str | None = None


@dataclass(frozen=True)
class URLTargetOptions:
    """Optional auth/mTLS options for URL positional targets."""

    headers_json: str | None = None
    auth_json: str | None = None
    mtls_cert_file: str | None = None
    mtls_key_file: str | None = None
    mtls_ca_bundle_file: str | None = None


@click.group()
@click.version_option(version=mcp_security_scanner.__version__)
def main() -> None:
    """
    MCP Security Scanner — Audit Model Context Protocol servers for vulnerabilities.

    Detects prompt injection, tool poisoning, capability escalation, and rug-pull attacks.
    Maps findings to OWASP LLM Top 10.

    Examples:
        mcp-scan server "python -m my_mcp_server" --format html --output report.html
        mcp-scan config claude_desktop_config.json --format sarif
        mcp-scan baseline "python -m my_mcp_server" --save baseline.json
    """


@main.group("cache")
def cache() -> None:
    """Manage scanner cache artifacts."""


@cache.command("rotate")
def cache_rotate() -> None:
    """Rotate OAuth persistent cache encryption key."""
    try:
        summary = _rotate_oauth_persistent_cache_key()
    except (RuntimeError, ValueError) as exc:
        click.echo(f"Cache rotation failed: {exc}", err=True)
        sys.exit(2)

    click.echo(
        "OAuth cache key rotated successfully "
        f"(source={summary['source']}, key_id={summary['key_id']}, entries={summary['entry_count']})."
    )
    sys.exit(0)


@main.command()
@click.argument("server_target", type=str)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
@click.option(
    "--dynamic",
    "dynamic_enabled",
    is_flag=True,
    help="Enable opt-in dynamic runtime probes against tools.",
)
@click.option(
    "--headers-json",
    "headers_json",
    default=None,
    type=str,
    help="JSON object of HTTP headers for URL targets.",
)
@click.option(
    "--auth-json",
    "auth_json",
    default=None,
    type=str,
    help="JSON auth object (same shape as config.auth) for URL targets.",
)
@click.option(
    "--mtls-cert-file",
    "mtls_cert_file",
    default=None,
    type=click.Path(),
    help="Client certificate path for URL transport mTLS.",
)
@click.option(
    "--mtls-key-file",
    "mtls_key_file",
    default=None,
    type=click.Path(),
    help="Client private key path for URL transport mTLS.",
)
@click.option(
    "--mtls-ca-bundle-file",
    "mtls_ca_bundle_file",
    default=None,
    type=click.Path(),
    help="Optional CA bundle path for URL transport mTLS.",
)
def server(
    server_target: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
    dynamic_enabled: bool,
    headers_json: str | None,
    auth_json: str | None,
    mtls_cert_file: str | None,
    mtls_key_file: str | None,
    mtls_ca_bundle_file: str | None,
) -> None:
    """
    Scan a single MCP server.

    SERVER_TARGET is either:
      - stdio command (e.g., "python -m my_server")
      - HTTP(S) URL (auto-detected: streamable-http, fallback to sse)

    Examples:
        mcp-scan server "python -m my_server"
        mcp-scan server "node server.js" --format html --output report.html
        mcp-scan server "my_server" --severity critical
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Scanning server: {server_target}[/debug]")
        console.print(f"[debug]Timeout: {timeout}s, Format: {output_format}, Severity: {severity}[/debug]")
        console.print(f"[debug]Dynamic probes enabled: {dynamic_enabled}[/debug]")

    threshold = _parse_severity_threshold(severity)

    try:
        url_target_options = URLTargetOptions(
            headers_json=headers_json,
            auth_json=auth_json,
            mtls_cert_file=mtls_cert_file,
            mtls_key_file=mtls_key_file,
            mtls_ca_bundle_file=mtls_ca_bundle_file,
        )
        report, filtered_findings = asyncio.run(
            _scan_single_server(
                server_target=server_target,
                timeout=timeout,
                threshold=threshold,
                dynamic_enabled=dynamic_enabled,
                url_target_options=url_target_options,
            )
        )
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Scan failed:[/red] {exc}")
        sys.exit(2)

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


@main.command()
@click.argument("config_file", type=click.Path(exists=True))
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for each server response.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
@click.option(
    "--dynamic",
    "dynamic_enabled",
    is_flag=True,
    help="Enable opt-in dynamic runtime probes against tools.",
)
def config(
    config_file: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
    dynamic_enabled: bool,
) -> None:
    """
    Scan all MCP servers configured in Claude Desktop config.

    CONFIG_FILE is path to claude_desktop_config.json.

    This command reads the config file, discovers all configured MCP servers,
    and scans each one sequentially. An aggregate report is generated.

    Examples:
        mcp-scan config ~/.claude/claude_desktop_config.json
        mcp-scan config claude_desktop_config.json --format html --output report.html
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Config file: {config_file}[/debug]")
        console.print(f"[debug]Dynamic probes enabled: {dynamic_enabled}[/debug]")

    try:
        config_data = json.loads(Path(config_file).read_text(encoding="utf-8"))
        server_entries = _extract_config_server_entries(config_data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Config scan failed:[/red] {exc}")
        sys.exit(2)

    threshold = _parse_severity_threshold(severity)

    _clear_oauth_token_cache()
    try:
        findings = asyncio.run(_scan_config_entries(server_entries, timeout=timeout, dynamic_enabled=dynamic_enabled))
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Config scan failed:[/red] {exc}")
        sys.exit(2)
    finally:
        _clear_oauth_token_cache()

    filtered_findings = _filter_findings(findings, threshold)
    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=f"config:{Path(config_file).name}",
        findings=filtered_findings,
    )

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


@main.command()
@click.argument("server_target", type=str)
@click.option(
    "--save",
    "baseline_path",
    required=True,
    type=click.Path(),
    help="Path to save baseline JSON file.",
)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
@click.option(
    "--headers-json",
    "headers_json",
    default=None,
    type=str,
    help="JSON object of HTTP headers for URL targets.",
)
@click.option(
    "--auth-json",
    "auth_json",
    default=None,
    type=str,
    help="JSON auth object (same shape as config.auth) for URL targets.",
)
@click.option(
    "--mtls-cert-file",
    "mtls_cert_file",
    default=None,
    type=click.Path(),
    help="Client certificate path for URL transport mTLS.",
)
@click.option(
    "--mtls-key-file",
    "mtls_key_file",
    default=None,
    type=click.Path(),
    help="Client private key path for URL transport mTLS.",
)
@click.option(
    "--mtls-ca-bundle-file",
    "mtls_ca_bundle_file",
    default=None,
    type=click.Path(),
    help="Optional CA bundle path for URL transport mTLS.",
)
def baseline(
    server_target: str,
    baseline_path: str,
    timeout: int,
    verbose: bool,
    headers_json: str | None,
    auth_json: str | None,
    mtls_cert_file: str | None,
    mtls_key_file: str | None,
    mtls_ca_bundle_file: str | None,
) -> None:
    """
    Create a baseline snapshot of an MCP server's tool schemas.

    Useful for later comparing against to detect tool mutations (rug-pull attacks).

    Examples:
        mcp-scan baseline "python -m my_server" --save baseline.json
        mcp-scan baseline "node server.js" --save server_baseline.json
    """
    console = Console(stderr=True)
    server_name = _derive_server_name(server_target)

    if verbose:
        console.print(f"[debug]Creating baseline for: {server_target}[/debug]")
        console.print(f"[debug]Saving to: {baseline_path}[/debug]")

    url_target_options = URLTargetOptions(
        headers_json=headers_json,
        auth_json=auth_json,
        mtls_cert_file=mtls_cert_file,
        mtls_key_file=mtls_key_file,
        mtls_ca_bundle_file=mtls_ca_bundle_file,
    )
    try:
        connector_configs = _build_target_connector_configs(
            server_target,
            timeout,
            url_target_options=url_target_options,
        )
        capabilities = asyncio.run(_discover_capabilities(server_name, connector_configs))
        baseline_document = build_baseline_document(
            scanner_version=mcp_security_scanner.__version__,
            server_name=server_name,
            command=server_target,
            tools=capabilities.tools,
        )
        Path(baseline_path).write_text(json.dumps(baseline_document, indent=2, ensure_ascii=False), encoding="utf-8")
    except (ConnectionError, RuntimeError, TimeoutError, ValueError, OSError) as exc:
        console.print(f"[red]Baseline creation failed:[/red] {exc}")
        sys.exit(2)

    if verbose:
        console.print(f"[debug]Baseline saved with {len(capabilities.tools)} tools[/debug]")

    sys.exit(0)


@main.command()
@click.argument("baseline_path", type=click.Path(exists=True))
@click.argument("server_target", type=str)
@click.option(
    "--timeout",
    default=30,
    help="Timeout in seconds for server responses.",
    type=int,
)
@click.option(
    "--format",
    "output_format",
    default="json",
    type=click.Choice(["json", "html", "sarif"]),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(),
    help="Save report to file (default: stdout).",
)
@click.option(
    "--severity",
    default="all",
    type=click.Choice(["critical", "high", "medium", "low", "info", "all"]),
    help="Only show findings at this severity level or higher.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable debug output.",
)
@click.option(
    "--headers-json",
    "headers_json",
    default=None,
    type=str,
    help="JSON object of HTTP headers for URL targets.",
)
@click.option(
    "--auth-json",
    "auth_json",
    default=None,
    type=str,
    help="JSON auth object (same shape as config.auth) for URL targets.",
)
@click.option(
    "--mtls-cert-file",
    "mtls_cert_file",
    default=None,
    type=click.Path(),
    help="Client certificate path for URL transport mTLS.",
)
@click.option(
    "--mtls-key-file",
    "mtls_key_file",
    default=None,
    type=click.Path(),
    help="Client private key path for URL transport mTLS.",
)
@click.option(
    "--mtls-ca-bundle-file",
    "mtls_ca_bundle_file",
    default=None,
    type=click.Path(),
    help="Optional CA bundle path for URL transport mTLS.",
)
def compare(
    baseline_path: str,
    server_target: str,
    timeout: int,
    output_format: str,
    output_path: str | None,
    severity: str,
    verbose: bool,
    headers_json: str | None,
    auth_json: str | None,
    mtls_cert_file: str | None,
    mtls_key_file: str | None,
    mtls_ca_bundle_file: str | None,
) -> None:
    """
    Compare current server state against a baseline snapshot.

    Detects tool mutations (descriptions, schemas, removals) indicating rug-pull attacks.

    Examples:
        mcp-scan compare baseline.json "python -m my_server"
        mcp-scan compare baseline.json "node server.js" --format html --output mutations.html
    """
    console = Console(stderr=True)

    if verbose:
        console.print(f"[debug]Baseline: {baseline_path}[/debug]")
        console.print(f"[debug]Server: {server_target}[/debug]")

    threshold = _parse_severity_threshold(severity)
    server_name = _derive_server_name(server_target)

    try:
        baseline_data = json.loads(Path(baseline_path).read_text(encoding="utf-8"))
        baseline_document = validate_baseline_document(baseline_data)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        console.print(f"[red]Compare failed:[/red] {exc}")
        sys.exit(2)

    url_target_options = URLTargetOptions(
        headers_json=headers_json,
        auth_json=auth_json,
        mtls_cert_file=mtls_cert_file,
        mtls_key_file=mtls_key_file,
        mtls_ca_bundle_file=mtls_ca_bundle_file,
    )
    try:
        connector_configs = _build_target_connector_configs(
            server_target,
            timeout,
            url_target_options=url_target_options,
        )
        capabilities = asyncio.run(_discover_capabilities(server_name, connector_configs))
    except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
        console.print(f"[red]Compare failed:[/red] {exc}")
        sys.exit(2)

    baseline_index = index_tool_snapshots(baseline_document["tools"])
    current_snapshots = [build_tool_snapshot(tool) for tool in capabilities.tools]
    current_index = index_tool_snapshots(current_snapshots)
    mutations = compare_tool_snapshots(baseline_index, current_index)

    findings = [_mutation_to_finding(mutation) for mutation in mutations]
    filtered_findings = _filter_findings(findings, threshold)

    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=server_name,
        findings=filtered_findings,
    )

    _write_report(report, output_format, output_path)

    if verbose:
        summary = report.summary
        console.print(
            "Findings after filter: "
            f"critical={summary['critical']} high={summary['high']} medium={summary['medium']} "
            f"low={summary['low']} info={summary['info']}"
        )

    sys.exit(1 if filtered_findings else 0)


async def _scan_single_server(
    server_target: str,
    timeout: int,
    threshold: Severity | None,
    dynamic_enabled: bool = False,
    url_target_options: URLTargetOptions | None = None,
) -> tuple[ScanReport, list[Finding]]:
    """Run discovery + MVP analyzers against one server target."""
    server_name = _derive_server_name(server_target)
    connector_configs = _build_target_connector_configs(
        server_target,
        timeout,
        url_target_options=url_target_options,
    )

    findings = await _scan_server_findings(server_name, connector_configs, dynamic_enabled=dynamic_enabled)
    filtered_findings = _filter_findings(findings, threshold)
    report = ScanReport(
        scanner_version=mcp_security_scanner.__version__,
        server_name=server_name,
        findings=filtered_findings,
    )
    return report, filtered_findings


async def _scan_config_entries(
    server_entries: dict[str, Any],
    timeout: int,
    dynamic_enabled: bool = False,
) -> list[Finding]:
    """Scan all entries under mcpServers and return aggregate findings."""
    findings: list[Finding] = []

    for server_name, raw_server_config in server_entries.items():
        connector_config, precheck_finding = _build_connector_config_from_config_entry(
            server_name,
            raw_server_config,
            timeout,
        )

        if precheck_finding is not None:
            findings.append(precheck_finding)
            continue

        assert connector_config is not None
        connector_configs = [connector_config]

        try:
            findings.extend(
                await _scan_server_findings(server_name, connector_configs, dynamic_enabled=dynamic_enabled)
            )
        except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
            findings.append(_build_scan_failure_finding(server_name, raw_server_config, exc))

    return findings


async def _scan_server_findings(
    server_name: str,
    connector_configs: list[dict[str, Any]],
    dynamic_enabled: bool = False,
) -> list[Finding]:
    """Discover capabilities from one server and run default analyzers (+ optional dynamic probes)."""
    if not connector_configs:
        raise ValueError("At least one connector configuration is required.")

    if not dynamic_enabled:
        capabilities = await _discover_capabilities(server_name, connector_configs)
        return await _run_mvp_analyzers(capabilities)

    errors: list[str] = []
    for connector_config in connector_configs:
        connector = MCPServerConnector(server_name=server_name)
        transport = str(connector_config.get("type", "unknown"))
        try:
            await connector.connect(connector_config)
            try:
                capabilities = await connector.get_server_capabilities()
                findings = await _run_mvp_analyzers(capabilities)
                findings.extend(await _run_dynamic_analyzer(capabilities, connector))
                return findings
            finally:
                await connector.disconnect()
        except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
            errors.append(f"{transport}: {exc}")
            await connector.disconnect()

    joined_errors = " | ".join(errors)
    raise ConnectionError(f"Failed to discover capabilities for {server_name}. Attempts: {joined_errors}")


async def _discover_capabilities(server_name: str, connector_configs: list[dict[str, Any]]) -> ServerCapabilities:
    """Try one or more transport configs and return discovered capabilities."""
    if not connector_configs:
        raise ValueError("At least one connector configuration is required.")

    errors: list[str] = []

    for connector_config in connector_configs:
        connector = MCPServerConnector(server_name=server_name)
        transport = str(connector_config.get("type", "unknown"))
        try:
            await connector.connect(connector_config)
            try:
                return await connector.get_server_capabilities()
            finally:
                await connector.disconnect()
        except (ConnectionError, RuntimeError, TimeoutError, ValueError) as exc:
            errors.append(f"{transport}: {exc}")
            await connector.disconnect()

    joined_errors = " | ".join(errors)
    raise ConnectionError(f"Failed to discover capabilities for {server_name}. Attempts: {joined_errors}")


async def _run_mvp_analyzers(capabilities: ServerCapabilities) -> list[Finding]:
    """Run the current default analyzer set against discovered capabilities."""
    analyzers = [
        StaticAnalyzer(),
        PromptInjectionAnalyzer(),
        EscalationAnalyzer(),
        ToolPoisoningAnalyzer(),
        CrossToolAnalyzer(),
    ]
    findings: list[Finding] = []

    for analyzer in analyzers:
        findings.extend(
            await analyzer.analyze(
                tools=capabilities.tools,
                resources=capabilities.resources,
                prompts=capabilities.prompts,
            )
        )

    return findings


async def _run_dynamic_analyzer(
    capabilities: ServerCapabilities,
    connector: MCPServerConnector,
) -> list[Finding]:
    """Run optional dynamic analyzer probes using the active connector session."""
    analyzer = DynamicAnalyzer()
    return await analyzer.analyze(
        tools=capabilities.tools,
        resources=capabilities.resources,
        prompts=capabilities.prompts,
        execute_tool=connector.call_tool,
    )


def _build_target_connector_configs(
    server_target: str,
    timeout: int,
    url_target_options: URLTargetOptions | None = None,
) -> list[dict[str, Any]]:
    """Build connector config candidates from CLI target."""
    effective_url_options = url_target_options or URLTargetOptions()
    target = server_target.strip()
    parsed = urlparse(target)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        shared_network_entry = _build_url_target_network_entry(target, effective_url_options)
        server_name = _derive_server_name(target)
        connector_configs: list[dict[str, Any]] = []
        for transport in ("streamable-http", "sse"):
            raw_server_config = {
                "transport": transport,
                **shared_network_entry,
            }
            connector_config, finding = _build_connector_config_from_config_entry(
                server_name=server_name,
                raw_server_config=raw_server_config,
                timeout=timeout,
            )
            if finding is not None:
                error_message = finding.description
                if finding.category in {"auth_config_error", "auth_token_error"}:
                    try:
                        evidence_payload = json.loads(finding.evidence)
                    except json.JSONDecodeError:
                        evidence_payload = {}
                    reason_value = evidence_payload.get("reason") if isinstance(evidence_payload, dict) else None
                    if isinstance(reason_value, str) and reason_value.strip():
                        error_message = reason_value.strip()
                raise ValueError(f"Invalid URL target configuration: {error_message}")
            assert connector_config is not None
            connector_configs.append(connector_config)
        return connector_configs

    if _has_url_target_options(effective_url_options):
        raise ValueError("URL auth/mTLS options are only supported when SERVER_TARGET is an http/https URL.")

    return [
        {
            "type": "stdio",
            "command": server_target,
            "timeout": timeout,
        }
    ]


def _has_url_target_options(url_target_options: URLTargetOptions) -> bool:
    """Return True when any URL-only option is set."""
    return any(
        value is not None
        for value in (
            url_target_options.headers_json,
            url_target_options.auth_json,
            url_target_options.mtls_cert_file,
            url_target_options.mtls_key_file,
            url_target_options.mtls_ca_bundle_file,
        )
    )


def _build_url_target_network_entry(server_target: str, url_target_options: URLTargetOptions) -> dict[str, Any]:
    """Build shared network entry payload for URL target candidates."""
    raw_entry: dict[str, Any] = {"url": server_target}

    headers_value = _parse_json_object_option(url_target_options.headers_json, option_name="headers-json")
    if headers_value is not None:
        raw_entry["headers"] = headers_value

    auth_value = _parse_json_object_option(url_target_options.auth_json, option_name="auth-json")
    if auth_value is not None:
        raw_entry["auth"] = auth_value

    if url_target_options.mtls_cert_file is not None:
        raw_entry["mtls_cert_file"] = url_target_options.mtls_cert_file
    if url_target_options.mtls_key_file is not None:
        raw_entry["mtls_key_file"] = url_target_options.mtls_key_file
    if url_target_options.mtls_ca_bundle_file is not None:
        raw_entry["mtls_ca_bundle_file"] = url_target_options.mtls_ca_bundle_file

    return raw_entry


def _parse_json_object_option(value: str | None, option_name: str) -> dict[str, Any] | None:
    """Parse a JSON object CLI option value."""
    if value is None:
        return None
    try:
        parsed_value = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--{option_name} must be valid JSON.") from exc
    if not isinstance(parsed_value, dict):
        raise ValueError(f"--{option_name} must be a JSON object.")
    return parsed_value


def _extract_config_server_entries(config_data: Any) -> dict[str, Any]:
    """Extract and validate mcpServers mapping from Claude Desktop config JSON."""
    if not isinstance(config_data, dict):
        raise ValueError("Config JSON must be an object.")

    server_entries = config_data.get("mcpServers")
    if not isinstance(server_entries, dict):
        raise ValueError("Config JSON must include an object field 'mcpServers'.")

    return server_entries


def _build_connector_config_from_config_entry(
    server_name: str,
    raw_server_config: Any,
    timeout: int,
) -> tuple[dict[str, Any] | None, Finding | None]:
    """Normalize one mcpServers entry into connector config or return finding."""
    if not isinstance(raw_server_config, dict):
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_config_entry",
            title=f"Invalid config entry for {server_name}",
            description="Server entry must be a JSON object.",
            raw_server_config=raw_server_config,
            remediation="Ensure each mcpServers entry is an object with command/args fields.",
        )

    transport_value = raw_server_config.get("transport", raw_server_config.get("type", "stdio"))
    if not isinstance(transport_value, str):
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_transport",
            title=f"Invalid transport value for {server_name}",
            description="Transport field must be a string when provided.",
            raw_server_config=raw_server_config,
            remediation="Set transport/type to one of: stdio, sse, streamable-http.",
        )

    transport = _normalize_transport_name(transport_value)
    if transport is None:
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.MEDIUM,
            category="unsupported_transport",
            title=f"Unsupported transport for {server_name}",
            description="Only stdio, sse, and streamable-http transports are supported; entry was skipped.",
            raw_server_config=raw_server_config,
            remediation="Use stdio, sse, or streamable-http transport.",
        )

    if transport in {"sse", "streamable-http"}:
        url_value = raw_server_config.get("url")
        if not isinstance(url_value, str) or not url_value.strip():
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_config_entry",
                title=f"Missing url for {server_name}",
                description=f"{transport} entries must include a non-empty URL.",
                raw_server_config=raw_server_config,
                remediation=f"Set a valid http/https URL for {transport} transport.",
            )

        parsed_url = urlparse(url_value)
        if parsed_url.scheme not in {"http", "https"}:
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_url",
                title=f"Invalid URL for {server_name}",
                description=f"{transport} URL must use http or https scheme.",
                raw_server_config=raw_server_config,
                remediation=f"Use an http:// or https:// URL for {transport} transport.",
            )

        headers_value = raw_server_config.get("headers")
        headers: dict[str, str] = {}
        if headers_value is not None:
            if not isinstance(headers_value, dict):
                return None, _build_config_entry_finding(
                    server_name=server_name,
                    severity=Severity.HIGH,
                    category="invalid_headers",
                    title=f"Invalid headers for {server_name}",
                    description=f"headers must be an object when provided for {transport}.",
                    raw_server_config=raw_server_config,
                    remediation="Set headers as a key/value JSON object.",
                )
            headers = {str(key): str(value) for key, value in headers_value.items()}

        auth_value = raw_server_config.get("auth")
        if auth_value is not None:
            headers, auth_finding = _resolve_auth_headers(
                server_name=server_name,
                transport=transport,
                auth_value=auth_value,
                explicit_headers=headers,
                timeout=timeout,
            )
            if auth_finding is not None:
                return None, auth_finding

        transport_mtls, transport_mtls_error = _resolve_transport_mtls_config(raw_server_config)
        if transport_mtls_error is not None:
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_config_entry",
                title=f"Invalid mTLS config for {server_name}",
                description=transport_mtls_error,
                raw_server_config=raw_server_config,
                remediation="Set mtls_cert_file and mtls_key_file together; verify optional CA bundle path.",
            )

        connector_config: dict[str, Any] = {
            "type": transport,
            "url": url_value,
            "timeout": timeout,
        }
        if headers:
            connector_config["headers"] = headers
        if transport_mtls is not None:
            connector_config.update(transport_mtls)

        return connector_config, None

    auth_value = raw_server_config.get("auth")
    if auth_value is not None:
        return None, _build_auth_config_error_finding(
            server_name=server_name,
            transport=transport,
            auth_type=_safe_auth_type(auth_value),
            env_var=_extract_auth_env_var(auth_value),
            reason="auth is only supported for sse and streamable-http transports.",
        )

    command = raw_server_config.get("command")
    if not isinstance(command, str) or not command.strip():
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_config_entry",
            title=f"Missing command for {server_name}",
            description="stdio entries must include a non-empty command string.",
            raw_server_config=raw_server_config,
            remediation="Set command and optional args for stdio server launch.",
        )

    composed_command = _compose_stdio_command(command, raw_server_config.get("args"))
    if composed_command is None:
        return None, _build_config_entry_finding(
            server_name=server_name,
            severity=Severity.HIGH,
            category="invalid_args",
            title=f"Invalid args for {server_name}",
            description="args must be an array of CLI arguments when provided.",
            raw_server_config=raw_server_config,
            remediation="Set args as an array of string-like values.",
        )

    env_value = raw_server_config.get("env")
    env: dict[str, str] | None = None
    if env_value is not None:
        if not isinstance(env_value, dict):
            return None, _build_config_entry_finding(
                server_name=server_name,
                severity=Severity.HIGH,
                category="invalid_env",
                title=f"Invalid env for {server_name}",
                description="env must be an object when provided.",
                raw_server_config=raw_server_config,
                remediation="Set env as a key/value JSON object.",
            )
        env = {str(key): str(value) for key, value in env_value.items()}

    connector_config = {
        "type": "stdio",
        "command": composed_command,
        "timeout": timeout,
    }
    if env is not None:
        connector_config["env"] = env

    return connector_config, None


def _compose_stdio_command(command: str, args: Any) -> str | None:
    """Compose a safe shell command from command + args array."""
    if args is None:
        return command

    if not isinstance(args, list):
        return None

    tokens = [command, *[str(item) for item in args]]
    return " ".join(shlex.quote(token) for token in tokens)


def _build_config_entry_finding(
    server_name: str,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    raw_server_config: Any,
    remediation: str,
) -> Finding:
    """Create a standardized finding for config-entry parsing issues."""
    return Finding(
        analyzer_name="config_scanner",
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=_safe_json_dump(raw_server_config),
        owasp_id="LLM10",
        remediation=remediation,
        metadata={"server_name": server_name},
    )


def _resolve_auth_headers(
    server_name: str,
    transport: str,
    auth_value: Any,
    explicit_headers: dict[str, str],
    timeout: int,
) -> tuple[dict[str, str], Finding | None]:
    """Resolve auth object into headers and merge over explicit headers."""
    headers = dict(explicit_headers)

    if not isinstance(auth_value, dict):
        return headers, _build_auth_config_error_finding(
            server_name=server_name,
            transport=transport,
            auth_type=_safe_auth_type(auth_value),
            env_var=None,
            reason="auth must be an object.",
        )

    raw_auth_type = auth_value.get("type")
    if not isinstance(raw_auth_type, str) or not raw_auth_type.strip():
        return headers, _build_auth_config_error_finding(
            server_name=server_name,
            transport=transport,
            auth_type=_safe_auth_type(auth_value),
            env_var=None,
            reason="auth.type must be a non-empty string.",
        )
    auth_type = raw_auth_type.strip().lower()
    oauth_cache_settings, oauth_cache_error = _coerce_oauth_cache_settings(auth_type=auth_type, auth_value=auth_value)
    if oauth_cache_error is not None:
        return headers, _build_auth_config_error_finding(
            server_name=server_name,
            transport=transport,
            auth_type=auth_type,
            env_var=_extract_auth_env_var(auth_value),
            reason=oauth_cache_error,
        )
    assert oauth_cache_settings is not None

    if auth_type == "bearer":
        token_env, token_env_error = _validate_auth_env_name(auth_value.get("token_env"), "token_env")
        if token_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=token_env,
                reason=token_env_error,
            )

        token_value, token_error = _read_auth_env_value(token_env)
        if token_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=token_env,
                reason=token_error,
            )
        assert token_value is not None

        header_name = _coerce_auth_header_name(auth_value.get("header"), default="Authorization")
        if header_name is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=token_env,
                reason="auth.header must be a non-empty string when provided.",
            )

        scheme_value = auth_value.get("scheme", "Bearer")
        if not isinstance(scheme_value, str):
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=token_env,
                reason="auth.scheme must be a string when provided.",
            )
        scheme = scheme_value.strip()
        auth_header_value = f"{scheme} {token_value}".strip() if scheme else token_value
        headers[header_name] = auth_header_value
        return headers, None

    if auth_type == "api_key":
        key_env, key_env_error = _validate_auth_env_name(auth_value.get("key_env"), "key_env")
        if key_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=key_env,
                reason=key_env_error,
            )

        key_value, key_error = _read_auth_env_value(key_env)
        if key_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=key_env,
                reason=key_error,
            )
        assert key_value is not None

        header_name = _coerce_auth_header_name(auth_value.get("header"), default="X-API-Key")
        if header_name is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=key_env,
                reason="auth.header must be a non-empty string when provided.",
            )

        headers[header_name] = key_value
        return headers, None

    if auth_type == "session_cookie":
        cookie_env, cookie_env_error = _validate_auth_env_name(auth_value.get("cookie_env"), "cookie_env")
        if cookie_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=cookie_env,
                reason=cookie_env_error,
            )

        cookie_value, cookie_error = _read_auth_env_value(cookie_env)
        if cookie_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=cookie_env,
                reason=cookie_error,
            )
        assert cookie_value is not None

        cookie_name_value = auth_value.get("cookie_name", "session")
        if not isinstance(cookie_name_value, str) or not cookie_name_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=cookie_env,
                reason="auth.cookie_name must be a non-empty string when provided.",
            )

        cookie_name = cookie_name_value.strip()
        cookie_pair = f"{cookie_name}={cookie_value}"
        existing_cookie = headers.get("Cookie")
        if existing_cookie and existing_cookie.strip():
            headers["Cookie"] = f"{existing_cookie}; {cookie_pair}"
        else:
            headers["Cookie"] = cookie_pair
        return headers, None

    if auth_type == "oauth_client_credentials":
        token_url_value = auth_value.get("token_url")
        if not isinstance(token_url_value, str) or not token_url_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a non-empty string.",
            )
        token_url = token_url_value.strip()
        parsed_token_url = urlparse(token_url)
        if parsed_token_url.scheme not in {"http", "https"} or not parsed_token_url.netloc:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a valid http/https URL.",
            )

        client_id_env, client_id_env_error = _validate_auth_env_name(auth_value.get("client_id_env"), "client_id_env")
        if client_id_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_env_error,
            )

        scope_value, scope_error = _validate_optional_auth_text(auth_value.get("scope"), "scope")
        if scope_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scope_error,
            )

        audience_value, audience_error = _validate_optional_auth_text(auth_value.get("audience"), "audience")
        if audience_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=audience_error,
            )

        token_endpoint_auth_method, token_endpoint_auth_method_error = _coerce_token_endpoint_auth_method(
            auth_value.get("token_endpoint_auth_method")
        )
        if token_endpoint_auth_method_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=token_endpoint_auth_method_error,
            )
        assert token_endpoint_auth_method is not None

        client_id_value, client_id_error = _read_auth_env_value(client_id_env)
        if client_id_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_error,
            )
        assert client_id_value is not None

        client_secret_env: str | None = None
        client_secret_value: str | None = None
        if token_endpoint_auth_method in {"client_secret_post", "client_secret_basic"}:
            client_secret_env, client_secret_env_error = _validate_auth_env_name(
                auth_value.get("client_secret_env"), "client_secret_env"
            )
            if client_secret_env_error is not None:
                return headers, _build_auth_config_error_finding(
                    server_name=server_name,
                    transport=transport,
                    auth_type=auth_type,
                    env_var=client_secret_env,
                    reason=client_secret_env_error,
                )
            client_secret_value, client_secret_error = _read_auth_env_value(client_secret_env)
            if client_secret_error is not None:
                return headers, _build_auth_config_error_finding(
                    server_name=server_name,
                    transport=transport,
                    auth_type=auth_type,
                    env_var=client_secret_env,
                    reason=client_secret_error,
                )
            assert client_secret_value is not None

        client_credentials_private_key_jwt_signer: OAuthPrivateKeyJWTSigner | None = None
        client_credentials_private_key_jwt_env_var: str | None = None
        if token_endpoint_auth_method == "private_key_jwt":
            (
                client_credentials_private_key_jwt_signer,
                client_credentials_private_key_jwt_env_var,
                private_key_jwt_error,
            ) = _resolve_oauth_private_key_jwt_signer(auth_value)
            if private_key_jwt_error is not None:
                return headers, _build_auth_config_error_finding(
                    server_name=server_name,
                    transport=transport,
                    auth_type=auth_type,
                    env_var=client_credentials_private_key_jwt_env_var or client_id_env,
                    reason=private_key_jwt_error,
                )
            assert client_credentials_private_key_jwt_signer is not None

        mtls_config, mtls_config_error = _resolve_oauth_mtls_config(auth_value)
        if mtls_config_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=mtls_config_error,
            )

        header_name = _coerce_auth_header_name(auth_value.get("header"), default="Authorization")
        if header_name is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason="auth.header must be a non-empty string when provided.",
            )

        scheme_value = auth_value.get("scheme")

        oauth_env_var = _join_auth_env_vars(
            client_id_env,
            client_secret_env,
            client_credentials_private_key_jwt_env_var,
        )
        token_value, token_type, token_error_finding = _resolve_oauth_client_credentials_token(
            server_name=server_name,
            transport=transport,
            auth_type=auth_type,
            token_url=token_url,
            client_id=client_id_value,
            client_secret=client_secret_value,
            scope=scope_value,
            audience=audience_value,
            token_endpoint_auth_method=token_endpoint_auth_method,
            client_assertion_signer=client_credentials_private_key_jwt_signer,
            mtls_config=mtls_config,
            timeout_seconds=timeout,
            env_var=oauth_env_var,
            cache_settings=oauth_cache_settings,
        )
        if token_error_finding is not None:
            return headers, token_error_finding
        assert token_value is not None

        auth_header_value, scheme_error = _build_oauth_auth_header_value(
            token_value=token_value,
            explicit_scheme_value=scheme_value,
            token_type=token_type,
        )
        if scheme_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scheme_error,
            )
        assert auth_header_value is not None

        headers[header_name] = auth_header_value
        return headers, None

    if auth_type == "oauth_device_code":
        device_authorization_url_value = auth_value.get("device_authorization_url")
        if not isinstance(device_authorization_url_value, str) or not device_authorization_url_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.device_authorization_url must be a non-empty string.",
            )
        device_authorization_url = device_authorization_url_value.strip()
        parsed_device_authorization_url = urlparse(device_authorization_url)
        if (
            parsed_device_authorization_url.scheme not in {"http", "https"}
            or not parsed_device_authorization_url.netloc
        ):
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.device_authorization_url must be a valid http/https URL.",
            )

        token_url_value = auth_value.get("token_url")
        if not isinstance(token_url_value, str) or not token_url_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a non-empty string.",
            )
        token_url = token_url_value.strip()
        parsed_token_url = urlparse(token_url)
        if parsed_token_url.scheme not in {"http", "https"} or not parsed_token_url.netloc:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a valid http/https URL.",
            )

        client_id_env, client_id_env_error = _validate_auth_env_name(auth_value.get("client_id_env"), "client_id_env")
        if client_id_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_env_error,
            )

        client_secret_env, client_secret_env_error = _validate_optional_auth_env_name(
            auth_value.get("client_secret_env"), "client_secret_env"
        )
        if client_secret_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_secret_env,
                reason=client_secret_env_error,
            )

        client_id_value, client_id_error = _read_auth_env_value(client_id_env)
        if client_id_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_error,
            )
        assert client_id_value is not None

        device_client_secret_value: str | None = None
        if client_secret_env is not None:
            device_client_secret_value, client_secret_error = _read_auth_env_value(client_secret_env)
            if client_secret_error is not None:
                return headers, _build_auth_config_error_finding(
                    server_name=server_name,
                    transport=transport,
                    auth_type=auth_type,
                    env_var=client_secret_env,
                    reason=client_secret_error,
                )
            assert device_client_secret_value is not None

        scope_value, scope_error = _validate_optional_auth_text(auth_value.get("scope"), "scope")
        if scope_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scope_error,
            )

        audience_value, audience_error = _validate_optional_auth_text(auth_value.get("audience"), "audience")
        if audience_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=audience_error,
            )

        token_endpoint_auth_method, token_endpoint_auth_method_error = _coerce_token_endpoint_auth_method(
            auth_value.get("token_endpoint_auth_method")
        )
        if token_endpoint_auth_method_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_secret_env or client_id_env,
                reason=token_endpoint_auth_method_error,
            )
        assert token_endpoint_auth_method is not None
        if token_endpoint_auth_method == "client_secret_basic" and client_secret_env is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=(
                    "auth.client_secret_env is required when " "auth.token_endpoint_auth_method='client_secret_basic'."
                ),
            )

        device_private_key_jwt_signer: OAuthPrivateKeyJWTSigner | None = None
        device_private_key_jwt_env_var: str | None = None
        if token_endpoint_auth_method == "private_key_jwt":
            (
                device_private_key_jwt_signer,
                device_private_key_jwt_env_var,
                private_key_jwt_error,
            ) = _resolve_oauth_private_key_jwt_signer(auth_value)
            if private_key_jwt_error is not None:
                return headers, _build_auth_config_error_finding(
                    server_name=server_name,
                    transport=transport,
                    auth_type=auth_type,
                    env_var=device_private_key_jwt_env_var or client_id_env,
                    reason=private_key_jwt_error,
                )
            assert device_private_key_jwt_signer is not None

        mtls_config, mtls_config_error = _resolve_oauth_mtls_config(auth_value)
        if mtls_config_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=mtls_config_error,
            )

        header_name = _coerce_auth_header_name(auth_value.get("header"), default="Authorization")
        if header_name is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason="auth.header must be a non-empty string when provided.",
            )

        scheme_value = auth_value.get("scheme")

        oauth_env_var = _join_auth_env_vars(client_id_env, client_secret_env, device_private_key_jwt_env_var)
        token_value, token_type, token_error_finding = _resolve_oauth_device_code_token(
            server_name=server_name,
            transport=transport,
            auth_type=auth_type,
            device_authorization_url=device_authorization_url,
            token_url=token_url,
            client_id=client_id_value,
            client_secret=device_client_secret_value,
            scope=scope_value,
            audience=audience_value,
            token_endpoint_auth_method=token_endpoint_auth_method,
            client_assertion_signer=device_private_key_jwt_signer,
            mtls_config=mtls_config,
            timeout_seconds=timeout,
            is_interactive_tty=_is_interactive_tty(),
            env_var=oauth_env_var,
            cache_settings=oauth_cache_settings,
        )
        if token_error_finding is not None:
            return headers, token_error_finding
        assert token_value is not None

        auth_header_value, scheme_error = _build_oauth_auth_header_value(
            token_value=token_value,
            explicit_scheme_value=scheme_value,
            token_type=token_type,
        )
        if scheme_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scheme_error,
            )
        assert auth_header_value is not None

        headers[header_name] = auth_header_value
        return headers, None

    if auth_type == "oauth_auth_code_pkce":
        authorization_url_value = auth_value.get("authorization_url")
        if not isinstance(authorization_url_value, str) or not authorization_url_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.authorization_url must be a non-empty string.",
            )
        authorization_url = authorization_url_value.strip()
        parsed_authorization_url = urlparse(authorization_url)
        if parsed_authorization_url.scheme not in {"http", "https"} or not parsed_authorization_url.netloc:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.authorization_url must be a valid http/https URL.",
            )

        token_url_value = auth_value.get("token_url")
        if not isinstance(token_url_value, str) or not token_url_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a non-empty string.",
            )
        token_url = token_url_value.strip()
        parsed_token_url = urlparse(token_url)
        if parsed_token_url.scheme not in {"http", "https"} or not parsed_token_url.netloc:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=None,
                reason="auth.token_url must be a valid http/https URL.",
            )

        client_id_env, client_id_env_error = _validate_auth_env_name(auth_value.get("client_id_env"), "client_id_env")
        if client_id_env_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_env_error,
            )

        client_id_value, client_id_error = _read_auth_env_value(client_id_env)
        if client_id_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=client_id_error,
            )
        assert client_id_value is not None

        scope_value, scope_error = _validate_optional_auth_text(auth_value.get("scope"), "scope")
        if scope_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scope_error,
            )

        audience_value, audience_error = _validate_optional_auth_text(auth_value.get("audience"), "audience")
        if audience_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=audience_error,
            )

        redirect_host_value = auth_value.get("redirect_host", "127.0.0.1")
        if not isinstance(redirect_host_value, str) or not redirect_host_value.strip():
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason="auth.redirect_host must be a non-empty string when provided.",
            )
        redirect_host = redirect_host_value.strip()

        redirect_port, redirect_port_error = _coerce_redirect_port(auth_value.get("redirect_port"), default=8765)
        if redirect_port_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=redirect_port_error,
            )

        callback_path_value = auth_value.get("callback_path", "/callback")
        callback_path, callback_path_error = _coerce_callback_path(callback_path_value)
        if callback_path_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=callback_path_error,
            )

        header_name = _coerce_auth_header_name(auth_value.get("header"), default="Authorization")
        if header_name is None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason="auth.header must be a non-empty string when provided.",
            )

        scheme_value = auth_value.get("scheme")

        oauth_env_var = _join_auth_env_vars(client_id_env)
        token_value, token_type, token_error_finding = _resolve_oauth_auth_code_pkce_token(
            server_name=server_name,
            transport=transport,
            auth_type=auth_type,
            authorization_url=authorization_url,
            token_url=token_url,
            client_id=client_id_value,
            scope=scope_value,
            audience=audience_value,
            redirect_host=redirect_host,
            redirect_port=redirect_port,
            callback_path=callback_path,
            timeout_seconds=timeout,
            is_interactive_tty=_is_interactive_tty(),
            env_var=oauth_env_var,
            cache_settings=oauth_cache_settings,
        )
        if token_error_finding is not None:
            return headers, token_error_finding
        assert token_value is not None

        auth_header_value, scheme_error = _build_oauth_auth_header_value(
            token_value=token_value,
            explicit_scheme_value=scheme_value,
            token_type=token_type,
        )
        if scheme_error is not None:
            return headers, _build_auth_config_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=client_id_env,
                reason=scheme_error,
            )
        assert auth_header_value is not None

        headers[header_name] = auth_header_value
        return headers, None

    return headers, _build_auth_config_error_finding(
        server_name=server_name,
        transport=transport,
        auth_type=auth_type,
        env_var=None,
        reason="Unsupported auth.type. Use bearer, api_key, session_cookie, oauth_client_credentials, oauth_device_code, or oauth_auth_code_pkce.",
    )


def _validate_auth_env_name(value: Any, field_name: str) -> tuple[str | None, str | None]:
    """Validate auth env var reference fields."""
    if not isinstance(value, str) or not value.strip():
        return None, f"auth.{field_name} must be a non-empty string."
    return value.strip(), None


def _validate_optional_auth_env_name(value: Any, field_name: str) -> tuple[str | None, str | None]:
    """Validate optional auth env refs that must be non-empty strings when provided."""
    if value is None:
        return None, None
    return _validate_auth_env_name(value, field_name)


def _read_auth_env_value(env_name: str | None) -> tuple[str | None, str | None]:
    """Read required secret value from environment without exposing secret content."""
    if env_name is None:
        return None, "auth env name is missing."

    raw_value = os.getenv(env_name)
    if raw_value is None or not raw_value.strip():
        return None, f"Environment variable {env_name} is missing or empty."
    return raw_value, None


def _coerce_auth_header_name(value: Any, default: str) -> str | None:
    """Normalize optional auth header names."""
    if value is None:
        return default
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _coerce_token_endpoint_auth_method(value: Any) -> tuple[str | None, str | None]:
    """Normalize optional OAuth token endpoint auth method."""
    if value is None:
        return "client_secret_post", None
    if not isinstance(value, str) or not value.strip():
        return None, (
            "auth.token_endpoint_auth_method must be one of: "
            "client_secret_post, client_secret_basic, private_key_jwt."
        )
    normalized = value.strip().lower()
    if normalized not in _SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS:
        return None, (
            "auth.token_endpoint_auth_method must be one of: "
            "client_secret_post, client_secret_basic, private_key_jwt."
        )
    return normalized, None


def _build_oauth_auth_header_value(
    token_value: str,
    explicit_scheme_value: Any,
    token_type: str | None,
) -> tuple[str, str | None]:
    """Build Authorization header with precedence auth.scheme > token_type > Bearer."""
    if explicit_scheme_value is not None and not isinstance(explicit_scheme_value, str):
        return "", "auth.scheme must be a string when provided."

    if isinstance(explicit_scheme_value, str):
        resolved_scheme = _normalize_oauth_scheme(explicit_scheme_value)
    elif token_type is not None and token_type.strip():
        resolved_scheme = _normalize_oauth_scheme(token_type)
    else:
        resolved_scheme = "Bearer"

    if resolved_scheme:
        return f"{resolved_scheme} {token_value}".strip(), None
    return token_value, None


def _normalize_oauth_scheme(value: str | None) -> str | None:
    """Normalize auth scheme tokens with sensible casing for known schemes."""
    normalized_text = _optional_non_empty_text(value)
    if normalized_text is None:
        return None
    lowered = normalized_text.lower()
    if lowered == "bearer":
        return "Bearer"
    if lowered == "dpop":
        return "DPoP"
    return normalized_text


def _extract_auth_env_var(auth_value: Any) -> str | None:
    """Extract primary env var reference from auth config for metadata."""
    if not isinstance(auth_value, dict):
        return None

    for key in (
        "token_env",
        "key_env",
        "cookie_env",
        "client_id_env",
        "client_secret_env",
        "client_assertion_key_env",
    ):
        value = auth_value.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _safe_auth_type(auth_value: Any) -> str:
    """Return safe auth type string for metadata without raising."""
    if isinstance(auth_value, dict):
        raw_auth_type = auth_value.get("type")
        if isinstance(raw_auth_type, str) and raw_auth_type.strip():
            return raw_auth_type.strip().lower()
    return "unknown"


def _build_auth_config_error_finding(
    server_name: str,
    transport: str,
    auth_type: str,
    env_var: str | None,
    reason: str,
) -> Finding:
    """Create a standardized finding for auth config resolution errors."""
    evidence_payload = {
        "reason": reason,
        "auth_type": auth_type,
        "env_var": env_var,
    }
    return Finding(
        analyzer_name="config_scanner",
        severity=Severity.HIGH,
        category="auth_config_error",
        title=f"Invalid auth configuration for {server_name}",
        description="Auth configuration could not be resolved; server was skipped.",
        evidence=json.dumps(evidence_payload, ensure_ascii=False, sort_keys=True),
        owasp_id="LLM10",
        remediation="Fix auth config fields and required env variables, then rerun config scan.",
        metadata={
            "server_name": server_name,
            "transport": transport,
            "auth_type": auth_type,
            "env_var": env_var,
        },
    )


def _build_auth_token_error_finding(
    server_name: str,
    transport: str,
    auth_type: str,
    env_var: str | None,
    token_url: str,
    reason: str,
    http_status: int | None,
) -> Finding:
    """Create finding for OAuth token endpoint failures without leaking secrets."""
    evidence_payload = {
        "reason": reason,
        "auth_type": auth_type,
        "env_var": env_var,
        "token_url": token_url,
        "http_status": http_status,
    }
    return Finding(
        analyzer_name="config_scanner",
        severity=Severity.HIGH,
        category="auth_token_error",
        title=f"OAuth token acquisition failed for {server_name}",
        description="OAuth token could not be acquired; server was skipped.",
        evidence=json.dumps(evidence_payload, ensure_ascii=False, sort_keys=True),
        owasp_id="LLM10",
        remediation="Verify OAuth token endpoint reachability and client credentials, then rerun config scan.",
        metadata={
            "server_name": server_name,
            "transport": transport,
            "auth_type": auth_type,
            "env_var": env_var,
            "token_url": token_url,
            "http_status": http_status,
        },
    )


def _validate_optional_auth_text(value: Any, field_name: str) -> tuple[str | None, str | None]:
    """Validate optional auth fields that, when provided, must be non-empty strings."""
    if value is None:
        return None, None
    if not isinstance(value, str) or not value.strip():
        return None, f"auth.{field_name} must be a non-empty string when provided."
    return value.strip(), None


def _resolve_transport_mtls_config(raw_server_config: dict[str, Any]) -> tuple[dict[str, str] | None, str | None]:
    """Resolve optional top-level transport mTLS fields for network connector config."""
    cert_file = raw_server_config.get("mtls_cert_file")
    key_file = raw_server_config.get("mtls_key_file")
    ca_bundle_file = raw_server_config.get("mtls_ca_bundle_file")

    def _normalize_mtls_path(value: Any, field_name: str) -> tuple[str | None, str | None]:
        if value is None:
            return None, None
        if not isinstance(value, str) or not value.strip():
            return None, f"{field_name} must be a non-empty string when provided."
        return value.strip(), None

    cert_path, cert_path_error = _normalize_mtls_path(cert_file, "mtls_cert_file")
    if cert_path_error is not None:
        return None, cert_path_error

    key_path, key_path_error = _normalize_mtls_path(key_file, "mtls_key_file")
    if key_path_error is not None:
        return None, key_path_error

    ca_path, ca_path_error = _normalize_mtls_path(ca_bundle_file, "mtls_ca_bundle_file")
    if ca_path_error is not None:
        return None, ca_path_error

    mtls_fields_provided = any(value is not None for value in (cert_path, key_path, ca_path))
    if not mtls_fields_provided:
        return None, None

    if cert_path is None or key_path is None:
        return None, "mtls_cert_file and mtls_key_file must be provided together."
    if not Path(cert_path).is_file():
        return None, "mtls_cert_file path does not exist or is not a file."
    if not Path(key_path).is_file():
        return None, "mtls_key_file path does not exist or is not a file."
    if ca_path is not None and not Path(ca_path).is_file():
        return None, "mtls_ca_bundle_file path does not exist or is not a file."

    mtls_config = {
        "mtls_cert_file": cert_path,
        "mtls_key_file": key_path,
    }
    if ca_path is not None:
        mtls_config["mtls_ca_bundle_file"] = ca_path
    return mtls_config, None


def _coerce_redirect_port(value: Any, default: int) -> tuple[int, str | None]:
    """Parse redirect_port as a valid TCP port."""
    if value is None:
        return default, None

    parsed_port: int
    if isinstance(value, int):
        parsed_port = value
    elif isinstance(value, float):
        parsed_port = int(value)
    elif isinstance(value, str):
        stripped_value = value.strip()
        if not stripped_value:
            return 0, "auth.redirect_port must be an integer between 1 and 65535 when provided."
        try:
            parsed_port = int(stripped_value)
        except ValueError:
            return 0, "auth.redirect_port must be an integer between 1 and 65535 when provided."
    else:
        return 0, "auth.redirect_port must be an integer between 1 and 65535 when provided."

    if parsed_port < 1 or parsed_port > 65535:
        return 0, "auth.redirect_port must be an integer between 1 and 65535 when provided."
    return parsed_port, None


def _coerce_callback_path(value: Any) -> tuple[str, str | None]:
    """Normalize callback_path and ensure it is an absolute path."""
    if not isinstance(value, str) or not value.strip():
        return "", "auth.callback_path must be a non-empty string when provided."

    callback_path = value.strip()
    if not callback_path.startswith("/"):
        return "", "auth.callback_path must start with '/'."
    return callback_path, None


def _coerce_oauth_cache_settings(
    auth_type: str, auth_value: dict[str, Any]
) -> tuple[OAuthCacheSettings | None, str | None]:
    """Normalize optional auth.cache settings and enforce OAuth-only usage."""
    cache_value = auth_value.get("cache")
    if auth_type not in _OAUTH_AUTH_TYPES:
        if cache_value is not None:
            return None, "auth.cache is only supported for OAuth auth types."
        return OAuthCacheSettings(), None

    if cache_value is None:
        return OAuthCacheSettings(), None
    if not isinstance(cache_value, dict):
        return None, "auth.cache must be an object when provided."

    unknown_fields = [
        str(key)
        for key in cache_value
        if str(key)
        not in {
            "persistent",
            "namespace",
            "backend",
            "aws_secret_id",
            "aws_ssm_parameter_name",
            "aws_region",
            "aws_endpoint_url",
            "gcp_secret_name",
            "gcp_endpoint_url",
            "azure_vault_url",
            "azure_secret_name",
            "azure_secret_version",
            "vault_url",
            "vault_secret_path",
            "vault_token_env",
            "vault_namespace",
            "k8s_secret_namespace",
            "k8s_secret_name",
            "k8s_secret_key",
            "oci_secret_ocid",
            "oci_region",
            "oci_endpoint_url",
            "doppler_project",
            "doppler_config",
            "doppler_secret_name",
            "doppler_token_env",
            "doppler_api_url",
            "op_connect_host",
            "op_vault_id",
            "op_item_id",
            "op_field_label",
            "op_connect_token_env",
            "bw_secret_id",
            "bw_access_token_env",
            "bw_api_url",
            "infisical_project_id",
            "infisical_environment",
            "infisical_secret_name",
            "infisical_token_env",
            "infisical_api_url",
            "akeyless_secret_name",
            "akeyless_token_env",
            "akeyless_api_url",
            "gitlab_project_id",
            "gitlab_group_id",
            "gitlab_variable_key",
            "gitlab_environment_scope",
            "gitlab_token_env",
            "gitlab_api_url",
            "github_repository",
            "github_organization",
            "github_environment_name",
            "github_variable_name",
            "github_token_env",
            "github_api_url",
            "consul_key_path",
            "consul_token_env",
            "consul_api_url",
            "redis_key",
            "redis_url",
            "redis_password_env",
            "cf_account_id",
            "cf_namespace_id",
            "cf_kv_key",
            "cf_api_token_env",
            "cf_api_url",
            "etcd_key",
            "etcd_api_url",
            "etcd_token_env",
        }
    ]
    if unknown_fields:
        return (
            None,
            "auth.cache supports only: persistent, namespace, backend, aws_secret_id, aws_ssm_parameter_name, "
            "aws_region, aws_endpoint_url, "
            "gcp_secret_name, gcp_endpoint_url, azure_vault_url, azure_secret_name, azure_secret_version, "
            "vault_url, vault_secret_path, vault_token_env, vault_namespace, "
            "k8s_secret_namespace, k8s_secret_name, k8s_secret_key, "
            "oci_secret_ocid, oci_region, oci_endpoint_url, "
            "doppler_project, doppler_config, doppler_secret_name, doppler_token_env, doppler_api_url, "
            "op_connect_host, op_vault_id, op_item_id, op_field_label, op_connect_token_env, "
            "bw_secret_id, bw_access_token_env, bw_api_url, "
            "infisical_project_id, infisical_environment, infisical_secret_name, infisical_token_env, "
            "infisical_api_url, akeyless_secret_name, akeyless_token_env, akeyless_api_url, "
            "gitlab_project_id, gitlab_group_id, gitlab_variable_key, gitlab_environment_scope, "
            "gitlab_token_env, gitlab_api_url, "
            "github_repository, github_organization, github_environment_name, github_variable_name, "
            "github_token_env, github_api_url, consul_key_path, consul_token_env, consul_api_url, "
            "redis_key, redis_url, redis_password_env, cf_account_id, cf_namespace_id, cf_kv_key, "
            "cf_api_token_env, cf_api_url, etcd_key, etcd_api_url, etcd_token_env.",
        )

    persistent_value = cache_value.get("persistent", False)
    if not isinstance(persistent_value, bool):
        return None, "auth.cache.persistent must be a boolean when provided."

    namespace_value = cache_value.get("namespace", "default")
    if not isinstance(namespace_value, str) or not namespace_value.strip():
        return None, "auth.cache.namespace must be a non-empty string when provided."

    backend_value = cache_value.get("backend", _OAUTH_CACHE_BACKEND_LOCAL)
    if not isinstance(backend_value, str) or not backend_value.strip():
        return None, "auth.cache.backend must be a non-empty string when provided."
    backend = backend_value.strip().lower()
    if backend not in _SUPPORTED_OAUTH_CACHE_BACKENDS:
        return (
            None,
            "auth.cache.backend must be one of: " f"{', '.join(sorted(_SUPPORTED_OAUTH_CACHE_BACKENDS))}.",
        )
    remote_backends = _SUPPORTED_OAUTH_CACHE_BACKENDS - {_OAUTH_CACHE_BACKEND_LOCAL}
    if set(_OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS) != remote_backends:
        return None, "auth.cache backend contract is inconsistent (remote loader map mismatch)."
    if set(_OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS) != remote_backends:
        return None, "auth.cache backend contract is inconsistent (remote persister map mismatch)."

    aws_secret_id_value = cache_value.get("aws_secret_id")
    if aws_secret_id_value is not None and (
        not isinstance(aws_secret_id_value, str) or not aws_secret_id_value.strip()
    ):
        return None, "auth.cache.aws_secret_id must be a non-empty string when provided."
    aws_secret_id = aws_secret_id_value.strip() if isinstance(aws_secret_id_value, str) else None

    aws_ssm_parameter_name_value = cache_value.get("aws_ssm_parameter_name")
    if aws_ssm_parameter_name_value is not None and (
        not isinstance(aws_ssm_parameter_name_value, str) or not aws_ssm_parameter_name_value.strip()
    ):
        return None, "auth.cache.aws_ssm_parameter_name must be a non-empty string when provided."
    aws_ssm_parameter_name = (
        aws_ssm_parameter_name_value.strip() if isinstance(aws_ssm_parameter_name_value, str) else None
    )

    aws_region_value = cache_value.get("aws_region")
    if aws_region_value is not None and (not isinstance(aws_region_value, str) or not aws_region_value.strip()):
        return None, "auth.cache.aws_region must be a non-empty string when provided."
    aws_region = aws_region_value.strip() if isinstance(aws_region_value, str) else None

    aws_endpoint_url_value = cache_value.get("aws_endpoint_url")
    if aws_endpoint_url_value is not None and (
        not isinstance(aws_endpoint_url_value, str) or not aws_endpoint_url_value.strip()
    ):
        return None, "auth.cache.aws_endpoint_url must be a non-empty string when provided."
    aws_endpoint_url = aws_endpoint_url_value.strip() if isinstance(aws_endpoint_url_value, str) else None
    if aws_endpoint_url is not None:
        parsed_aws_endpoint_url = urlparse(aws_endpoint_url)
        if parsed_aws_endpoint_url.scheme not in {"http", "https"} or not parsed_aws_endpoint_url.netloc:
            return None, "auth.cache.aws_endpoint_url must be a valid http/https URL."

    gcp_secret_name_value = cache_value.get("gcp_secret_name")
    if gcp_secret_name_value is not None and (
        not isinstance(gcp_secret_name_value, str) or not gcp_secret_name_value.strip()
    ):
        return None, "auth.cache.gcp_secret_name must be a non-empty string when provided."
    gcp_secret_name = gcp_secret_name_value.strip() if isinstance(gcp_secret_name_value, str) else None
    if gcp_secret_name is not None and not _is_valid_gcp_secret_name(gcp_secret_name):
        return (
            None,
            "auth.cache.gcp_secret_name must match 'projects/<project>/secrets/<secret>'.",
        )

    gcp_endpoint_url_value = cache_value.get("gcp_endpoint_url")
    if gcp_endpoint_url_value is not None and (
        not isinstance(gcp_endpoint_url_value, str) or not gcp_endpoint_url_value.strip()
    ):
        return None, "auth.cache.gcp_endpoint_url must be a non-empty string when provided."
    gcp_endpoint_url = gcp_endpoint_url_value.strip() if isinstance(gcp_endpoint_url_value, str) else None
    if gcp_endpoint_url is not None:
        parsed_gcp_endpoint_url = urlparse(gcp_endpoint_url)
        if parsed_gcp_endpoint_url.scheme not in {"http", "https"} or not parsed_gcp_endpoint_url.netloc:
            return None, "auth.cache.gcp_endpoint_url must be a valid http/https URL."

    azure_vault_url_value = cache_value.get("azure_vault_url")
    if azure_vault_url_value is not None and (
        not isinstance(azure_vault_url_value, str) or not azure_vault_url_value.strip()
    ):
        return None, "auth.cache.azure_vault_url must be a non-empty string when provided."
    azure_vault_url = azure_vault_url_value.strip() if isinstance(azure_vault_url_value, str) else None
    if azure_vault_url is not None and not _is_valid_azure_vault_url(azure_vault_url):
        return None, "auth.cache.azure_vault_url must be a valid https://<name>.vault.azure.net URL."

    azure_secret_name_value = cache_value.get("azure_secret_name")
    if azure_secret_name_value is not None and (
        not isinstance(azure_secret_name_value, str) or not azure_secret_name_value.strip()
    ):
        return None, "auth.cache.azure_secret_name must be a non-empty string when provided."
    azure_secret_name = azure_secret_name_value.strip() if isinstance(azure_secret_name_value, str) else None
    if azure_secret_name is not None and not _is_valid_azure_secret_name(azure_secret_name):
        return None, "auth.cache.azure_secret_name must match Azure secret naming rules ([0-9A-Za-z-], max 127)."

    azure_secret_version_value = cache_value.get("azure_secret_version", "latest")
    if azure_secret_version_value is not None and (
        not isinstance(azure_secret_version_value, str) or not azure_secret_version_value.strip()
    ):
        return None, "auth.cache.azure_secret_version must be a non-empty string when provided."
    azure_secret_version = (
        azure_secret_version_value.strip() if isinstance(azure_secret_version_value, str) else "latest"
    )

    vault_url_value = cache_value.get("vault_url")
    if vault_url_value is not None and (not isinstance(vault_url_value, str) or not vault_url_value.strip()):
        return None, "auth.cache.vault_url must be a non-empty string when provided."
    vault_url = vault_url_value.strip() if isinstance(vault_url_value, str) else None
    if vault_url is not None:
        parsed_vault_url = urlparse(vault_url)
        if parsed_vault_url.scheme not in {"http", "https"} or not parsed_vault_url.netloc:
            return None, "auth.cache.vault_url must be a valid http/https URL."

    vault_secret_path_value = cache_value.get("vault_secret_path")
    if vault_secret_path_value is not None and (
        not isinstance(vault_secret_path_value, str) or not vault_secret_path_value.strip()
    ):
        return None, "auth.cache.vault_secret_path must be a non-empty string when provided."
    vault_secret_path = vault_secret_path_value.strip() if isinstance(vault_secret_path_value, str) else None
    if vault_secret_path is not None and not _is_valid_vault_secret_path(vault_secret_path):
        return None, "auth.cache.vault_secret_path must be a valid Vault KV path."

    vault_token_env_value = cache_value.get("vault_token_env")
    if vault_token_env_value is not None and (
        not isinstance(vault_token_env_value, str) or not vault_token_env_value.strip()
    ):
        return None, "auth.cache.vault_token_env must be a non-empty string when provided."
    vault_token_env = vault_token_env_value.strip() if isinstance(vault_token_env_value, str) else None

    vault_namespace_value = cache_value.get("vault_namespace")
    if vault_namespace_value is not None and (
        not isinstance(vault_namespace_value, str) or not vault_namespace_value.strip()
    ):
        return None, "auth.cache.vault_namespace must be a non-empty string when provided."
    vault_namespace = vault_namespace_value.strip() if isinstance(vault_namespace_value, str) else None

    k8s_secret_namespace_value = cache_value.get("k8s_secret_namespace")
    if k8s_secret_namespace_value is not None and (
        not isinstance(k8s_secret_namespace_value, str) or not k8s_secret_namespace_value.strip()
    ):
        return None, "auth.cache.k8s_secret_namespace must be a non-empty string when provided."
    k8s_secret_namespace = k8s_secret_namespace_value.strip() if isinstance(k8s_secret_namespace_value, str) else None
    if k8s_secret_namespace is not None and not _is_valid_k8s_resource_name(k8s_secret_namespace):
        return (
            None,
            "auth.cache.k8s_secret_namespace must match Kubernetes DNS subdomain naming rules.",
        )

    k8s_secret_name_value = cache_value.get("k8s_secret_name")
    if k8s_secret_name_value is not None and (
        not isinstance(k8s_secret_name_value, str) or not k8s_secret_name_value.strip()
    ):
        return None, "auth.cache.k8s_secret_name must be a non-empty string when provided."
    k8s_secret_name = k8s_secret_name_value.strip() if isinstance(k8s_secret_name_value, str) else None
    if k8s_secret_name is not None and not _is_valid_k8s_resource_name(k8s_secret_name):
        return (
            None,
            "auth.cache.k8s_secret_name must match Kubernetes DNS subdomain naming rules.",
        )

    k8s_secret_key_value = cache_value.get("k8s_secret_key")
    if k8s_secret_key_value is not None and (
        not isinstance(k8s_secret_key_value, str) or not k8s_secret_key_value.strip()
    ):
        return None, "auth.cache.k8s_secret_key must be a non-empty string when provided."
    k8s_secret_key = k8s_secret_key_value.strip() if isinstance(k8s_secret_key_value, str) else None
    if k8s_secret_key is not None and not _is_valid_k8s_secret_key(k8s_secret_key):
        return None, "auth.cache.k8s_secret_key must match Kubernetes Secret data key naming rules."

    oci_secret_ocid_value = cache_value.get("oci_secret_ocid")
    if oci_secret_ocid_value is not None and (
        not isinstance(oci_secret_ocid_value, str) or not oci_secret_ocid_value.strip()
    ):
        return None, "auth.cache.oci_secret_ocid must be a non-empty string when provided."
    oci_secret_ocid = oci_secret_ocid_value.strip() if isinstance(oci_secret_ocid_value, str) else None
    if oci_secret_ocid is not None and not _is_valid_oci_secret_ocid(oci_secret_ocid):
        return None, "auth.cache.oci_secret_ocid must be a valid OCI OCID."

    oci_region_value = cache_value.get("oci_region")
    if oci_region_value is not None and (not isinstance(oci_region_value, str) or not oci_region_value.strip()):
        return None, "auth.cache.oci_region must be a non-empty string when provided."
    oci_region = oci_region_value.strip() if isinstance(oci_region_value, str) else None

    oci_endpoint_url_value = cache_value.get("oci_endpoint_url")
    if oci_endpoint_url_value is not None and (
        not isinstance(oci_endpoint_url_value, str) or not oci_endpoint_url_value.strip()
    ):
        return None, "auth.cache.oci_endpoint_url must be a non-empty string when provided."
    oci_endpoint_url = oci_endpoint_url_value.strip() if isinstance(oci_endpoint_url_value, str) else None
    if oci_endpoint_url is not None:
        parsed_oci_endpoint_url = urlparse(oci_endpoint_url)
        if parsed_oci_endpoint_url.scheme not in {"http", "https"} or not parsed_oci_endpoint_url.netloc:
            return None, "auth.cache.oci_endpoint_url must be a valid http/https URL."

    doppler_project_value = cache_value.get("doppler_project")
    if doppler_project_value is not None and (
        not isinstance(doppler_project_value, str) or not doppler_project_value.strip()
    ):
        return None, "auth.cache.doppler_project must be a non-empty string when provided."
    doppler_project = doppler_project_value.strip() if isinstance(doppler_project_value, str) else None
    if doppler_project is not None and not _is_valid_doppler_identifier(doppler_project):
        return None, "auth.cache.doppler_project must match Doppler identifier rules ([0-9A-Za-z_.-])."

    doppler_config_value = cache_value.get("doppler_config")
    if doppler_config_value is not None and (
        not isinstance(doppler_config_value, str) or not doppler_config_value.strip()
    ):
        return None, "auth.cache.doppler_config must be a non-empty string when provided."
    doppler_config = doppler_config_value.strip() if isinstance(doppler_config_value, str) else None
    if doppler_config is not None and not _is_valid_doppler_identifier(doppler_config):
        return None, "auth.cache.doppler_config must match Doppler identifier rules ([0-9A-Za-z_.-])."

    doppler_secret_name_value = cache_value.get("doppler_secret_name")
    if doppler_secret_name_value is not None and (
        not isinstance(doppler_secret_name_value, str) or not doppler_secret_name_value.strip()
    ):
        return None, "auth.cache.doppler_secret_name must be a non-empty string when provided."
    doppler_secret_name = doppler_secret_name_value.strip() if isinstance(doppler_secret_name_value, str) else None
    if doppler_secret_name is not None and not _is_valid_doppler_identifier(doppler_secret_name):
        return None, "auth.cache.doppler_secret_name must match Doppler identifier rules ([0-9A-Za-z_.-])."

    doppler_token_env_value = cache_value.get("doppler_token_env")
    if doppler_token_env_value is not None and (
        not isinstance(doppler_token_env_value, str) or not doppler_token_env_value.strip()
    ):
        return None, "auth.cache.doppler_token_env must be a non-empty string when provided."
    doppler_token_env = doppler_token_env_value.strip() if isinstance(doppler_token_env_value, str) else None
    if doppler_token_env is not None and not _is_valid_env_var_name(doppler_token_env):
        return None, "auth.cache.doppler_token_env must be a valid environment variable name."

    doppler_api_url_value = cache_value.get("doppler_api_url")
    if doppler_api_url_value is not None and (
        not isinstance(doppler_api_url_value, str) or not doppler_api_url_value.strip()
    ):
        return None, "auth.cache.doppler_api_url must be a non-empty string when provided."
    doppler_api_url = doppler_api_url_value.strip() if isinstance(doppler_api_url_value, str) else None
    if doppler_api_url is not None:
        parsed_doppler_api_url = urlparse(doppler_api_url)
        if parsed_doppler_api_url.scheme != "https" or not parsed_doppler_api_url.netloc:
            return None, "auth.cache.doppler_api_url must be a valid https URL."

    op_connect_host_value = cache_value.get("op_connect_host")
    if op_connect_host_value is not None and (
        not isinstance(op_connect_host_value, str) or not op_connect_host_value.strip()
    ):
        return None, "auth.cache.op_connect_host must be a non-empty string when provided."
    op_connect_host = op_connect_host_value.strip() if isinstance(op_connect_host_value, str) else None
    if op_connect_host is not None:
        parsed_op_connect_host = urlparse(op_connect_host)
        if parsed_op_connect_host.scheme != "https" or not parsed_op_connect_host.netloc:
            return None, "auth.cache.op_connect_host must be a valid https URL."

    op_vault_id_value = cache_value.get("op_vault_id")
    if op_vault_id_value is not None and (not isinstance(op_vault_id_value, str) or not op_vault_id_value.strip()):
        return None, "auth.cache.op_vault_id must be a non-empty string when provided."
    op_vault_id = op_vault_id_value.strip() if isinstance(op_vault_id_value, str) else None

    op_item_id_value = cache_value.get("op_item_id")
    if op_item_id_value is not None and (not isinstance(op_item_id_value, str) or not op_item_id_value.strip()):
        return None, "auth.cache.op_item_id must be a non-empty string when provided."
    op_item_id = op_item_id_value.strip() if isinstance(op_item_id_value, str) else None

    op_field_label_value = cache_value.get("op_field_label")
    if op_field_label_value is not None and (
        not isinstance(op_field_label_value, str) or not op_field_label_value.strip()
    ):
        return None, "auth.cache.op_field_label must be a non-empty string when provided."
    op_field_label = op_field_label_value.strip() if isinstance(op_field_label_value, str) else None

    op_connect_token_env_value = cache_value.get("op_connect_token_env")
    if op_connect_token_env_value is not None and (
        not isinstance(op_connect_token_env_value, str) or not op_connect_token_env_value.strip()
    ):
        return None, "auth.cache.op_connect_token_env must be a non-empty string when provided."
    op_connect_token_env = op_connect_token_env_value.strip() if isinstance(op_connect_token_env_value, str) else None
    if op_connect_token_env is not None and not _is_valid_env_var_name(op_connect_token_env):
        return None, "auth.cache.op_connect_token_env must be a valid environment variable name."

    bw_secret_id_value = cache_value.get("bw_secret_id")
    if bw_secret_id_value is not None and (not isinstance(bw_secret_id_value, str) or not bw_secret_id_value.strip()):
        return None, "auth.cache.bw_secret_id must be a non-empty string when provided."
    bw_secret_id = bw_secret_id_value.strip() if isinstance(bw_secret_id_value, str) else None
    if bw_secret_id is not None and not _is_valid_bitwarden_secret_id(bw_secret_id):
        return None, "auth.cache.bw_secret_id must be a valid Bitwarden secret identifier."

    bw_access_token_env_value = cache_value.get("bw_access_token_env")
    if bw_access_token_env_value is not None and (
        not isinstance(bw_access_token_env_value, str) or not bw_access_token_env_value.strip()
    ):
        return None, "auth.cache.bw_access_token_env must be a non-empty string when provided."
    bw_access_token_env = bw_access_token_env_value.strip() if isinstance(bw_access_token_env_value, str) else None
    if bw_access_token_env is not None and not _is_valid_env_var_name(bw_access_token_env):
        return None, "auth.cache.bw_access_token_env must be a valid environment variable name."

    bw_api_url_value = cache_value.get("bw_api_url")
    if bw_api_url_value is not None and (not isinstance(bw_api_url_value, str) or not bw_api_url_value.strip()):
        return None, "auth.cache.bw_api_url must be a non-empty string when provided."
    bw_api_url = bw_api_url_value.strip() if isinstance(bw_api_url_value, str) else None
    if bw_api_url is not None:
        parsed_bw_api_url = urlparse(bw_api_url)
        if parsed_bw_api_url.scheme != "https" or not parsed_bw_api_url.netloc:
            return None, "auth.cache.bw_api_url must be a valid https URL."

    infisical_project_id_value = cache_value.get("infisical_project_id")
    if infisical_project_id_value is not None and (
        not isinstance(infisical_project_id_value, str) or not infisical_project_id_value.strip()
    ):
        return None, "auth.cache.infisical_project_id must be a non-empty string when provided."
    infisical_project_id = infisical_project_id_value.strip() if isinstance(infisical_project_id_value, str) else None
    if infisical_project_id is not None and not _is_valid_infisical_identifier(infisical_project_id):
        return None, "auth.cache.infisical_project_id must match Infisical identifier rules ([0-9A-Za-z_.:-])."

    infisical_environment_value = cache_value.get("infisical_environment")
    if infisical_environment_value is not None and (
        not isinstance(infisical_environment_value, str) or not infisical_environment_value.strip()
    ):
        return None, "auth.cache.infisical_environment must be a non-empty string when provided."
    infisical_environment = (
        infisical_environment_value.strip() if isinstance(infisical_environment_value, str) else None
    )
    if infisical_environment is not None and not _is_valid_infisical_identifier(infisical_environment):
        return None, "auth.cache.infisical_environment must match Infisical identifier rules ([0-9A-Za-z_.:-])."

    infisical_secret_name_value = cache_value.get("infisical_secret_name")
    if infisical_secret_name_value is not None and (
        not isinstance(infisical_secret_name_value, str) or not infisical_secret_name_value.strip()
    ):
        return None, "auth.cache.infisical_secret_name must be a non-empty string when provided."
    infisical_secret_name = (
        infisical_secret_name_value.strip() if isinstance(infisical_secret_name_value, str) else None
    )
    if infisical_secret_name is not None and not _is_valid_infisical_identifier(infisical_secret_name):
        return None, "auth.cache.infisical_secret_name must match Infisical identifier rules ([0-9A-Za-z_.:-])."

    infisical_token_env_value = cache_value.get("infisical_token_env")
    if infisical_token_env_value is not None and (
        not isinstance(infisical_token_env_value, str) or not infisical_token_env_value.strip()
    ):
        return None, "auth.cache.infisical_token_env must be a non-empty string when provided."
    infisical_token_env = infisical_token_env_value.strip() if isinstance(infisical_token_env_value, str) else None
    if infisical_token_env is not None and not _is_valid_env_var_name(infisical_token_env):
        return None, "auth.cache.infisical_token_env must be a valid environment variable name."

    infisical_api_url_value = cache_value.get("infisical_api_url")
    if infisical_api_url_value is not None and (
        not isinstance(infisical_api_url_value, str) or not infisical_api_url_value.strip()
    ):
        return None, "auth.cache.infisical_api_url must be a non-empty string when provided."
    infisical_api_url = infisical_api_url_value.strip() if isinstance(infisical_api_url_value, str) else None
    if infisical_api_url is not None:
        parsed_infisical_api_url = urlparse(infisical_api_url)
        if parsed_infisical_api_url.scheme != "https" or not parsed_infisical_api_url.netloc:
            return None, "auth.cache.infisical_api_url must be a valid https URL."

    akeyless_secret_name_value = cache_value.get("akeyless_secret_name")
    if akeyless_secret_name_value is not None and (
        not isinstance(akeyless_secret_name_value, str) or not akeyless_secret_name_value.strip()
    ):
        return None, "auth.cache.akeyless_secret_name must be a non-empty string when provided."
    akeyless_secret_name = akeyless_secret_name_value.strip() if isinstance(akeyless_secret_name_value, str) else None
    if akeyless_secret_name is not None and not _is_valid_akeyless_secret_name(akeyless_secret_name):
        return None, "auth.cache.akeyless_secret_name must match Akeyless secret naming rules ([0-9A-Za-z_./:-])."

    akeyless_token_env_value = cache_value.get("akeyless_token_env")
    if akeyless_token_env_value is not None and (
        not isinstance(akeyless_token_env_value, str) or not akeyless_token_env_value.strip()
    ):
        return None, "auth.cache.akeyless_token_env must be a non-empty string when provided."
    akeyless_token_env = akeyless_token_env_value.strip() if isinstance(akeyless_token_env_value, str) else None
    if akeyless_token_env is not None and not _is_valid_env_var_name(akeyless_token_env):
        return None, "auth.cache.akeyless_token_env must be a valid environment variable name."

    akeyless_api_url_value = cache_value.get("akeyless_api_url")
    if akeyless_api_url_value is not None and (
        not isinstance(akeyless_api_url_value, str) or not akeyless_api_url_value.strip()
    ):
        return None, "auth.cache.akeyless_api_url must be a non-empty string when provided."
    akeyless_api_url = akeyless_api_url_value.strip() if isinstance(akeyless_api_url_value, str) else None
    if akeyless_api_url is not None:
        parsed_akeyless_api_url = urlparse(akeyless_api_url)
        if parsed_akeyless_api_url.scheme != "https" or not parsed_akeyless_api_url.netloc:
            return None, "auth.cache.akeyless_api_url must be a valid https URL."

    gitlab_project_id_value = cache_value.get("gitlab_project_id")
    if gitlab_project_id_value is not None and (
        not isinstance(gitlab_project_id_value, str) or not gitlab_project_id_value.strip()
    ):
        return None, "auth.cache.gitlab_project_id must be a non-empty string when provided."
    gitlab_project_id = gitlab_project_id_value.strip() if isinstance(gitlab_project_id_value, str) else None
    if gitlab_project_id is not None and not _is_valid_gitlab_project_id(gitlab_project_id):
        return None, "auth.cache.gitlab_project_id must be a numeric GitLab project ID."

    gitlab_group_id_value = cache_value.get("gitlab_group_id")
    if gitlab_group_id_value is not None and (
        not isinstance(gitlab_group_id_value, str) or not gitlab_group_id_value.strip()
    ):
        return None, "auth.cache.gitlab_group_id must be a non-empty string when provided."
    gitlab_group_id = gitlab_group_id_value.strip() if isinstance(gitlab_group_id_value, str) else None
    if gitlab_group_id is not None and not _is_valid_gitlab_group_id(gitlab_group_id):
        return None, "auth.cache.gitlab_group_id must be a numeric GitLab group ID."

    gitlab_variable_key_value = cache_value.get("gitlab_variable_key")
    if gitlab_variable_key_value is not None and (
        not isinstance(gitlab_variable_key_value, str) or not gitlab_variable_key_value.strip()
    ):
        return None, "auth.cache.gitlab_variable_key must be a non-empty string when provided."
    gitlab_variable_key = gitlab_variable_key_value.strip() if isinstance(gitlab_variable_key_value, str) else None
    if gitlab_variable_key is not None and not _is_valid_gitlab_variable_key(gitlab_variable_key):
        return None, "auth.cache.gitlab_variable_key must match environment-style key naming rules."

    gitlab_environment_scope_value = cache_value.get("gitlab_environment_scope")
    if gitlab_environment_scope_value is not None and (
        not isinstance(gitlab_environment_scope_value, str) or not gitlab_environment_scope_value.strip()
    ):
        return None, "auth.cache.gitlab_environment_scope must be a non-empty string when provided."
    gitlab_environment_scope = (
        gitlab_environment_scope_value.strip() if isinstance(gitlab_environment_scope_value, str) else None
    )

    gitlab_token_env_value = cache_value.get("gitlab_token_env")
    if gitlab_token_env_value is not None and (
        not isinstance(gitlab_token_env_value, str) or not gitlab_token_env_value.strip()
    ):
        return None, "auth.cache.gitlab_token_env must be a non-empty string when provided."
    gitlab_token_env = gitlab_token_env_value.strip() if isinstance(gitlab_token_env_value, str) else None
    if gitlab_token_env is not None and not _is_valid_env_var_name(gitlab_token_env):
        return None, "auth.cache.gitlab_token_env must be a valid environment variable name."

    gitlab_api_url_value = cache_value.get("gitlab_api_url")
    if gitlab_api_url_value is not None and (
        not isinstance(gitlab_api_url_value, str) or not gitlab_api_url_value.strip()
    ):
        return None, "auth.cache.gitlab_api_url must be a non-empty string when provided."
    gitlab_api_url = gitlab_api_url_value.strip() if isinstance(gitlab_api_url_value, str) else None
    if gitlab_api_url is not None:
        parsed_gitlab_api_url = urlparse(gitlab_api_url)
        if parsed_gitlab_api_url.scheme != "https" or not parsed_gitlab_api_url.netloc:
            return None, "auth.cache.gitlab_api_url must be a valid https URL."

    github_repository_value = cache_value.get("github_repository")
    if github_repository_value is not None and (
        not isinstance(github_repository_value, str) or not github_repository_value.strip()
    ):
        return None, "auth.cache.github_repository must be a non-empty string when provided."
    github_repository = github_repository_value.strip() if isinstance(github_repository_value, str) else None
    if github_repository is not None and not _is_valid_github_repository(github_repository):
        return None, "auth.cache.github_repository must match '<owner>/<repo>' format."

    github_organization_value = cache_value.get("github_organization")
    if github_organization_value is not None and (
        not isinstance(github_organization_value, str) or not github_organization_value.strip()
    ):
        return None, "auth.cache.github_organization must be a non-empty string when provided."
    github_organization = github_organization_value.strip() if isinstance(github_organization_value, str) else None
    if github_organization is not None and not _is_valid_github_organization(github_organization):
        return None, "auth.cache.github_organization must match GitHub organization naming rules."

    github_environment_name_value = cache_value.get("github_environment_name")
    if github_environment_name_value is not None and (
        not isinstance(github_environment_name_value, str) or not github_environment_name_value.strip()
    ):
        return None, "auth.cache.github_environment_name must be a non-empty string when provided."
    github_environment_name = (
        github_environment_name_value.strip() if isinstance(github_environment_name_value, str) else None
    )

    github_variable_name_value = cache_value.get("github_variable_name")
    if github_variable_name_value is not None and (
        not isinstance(github_variable_name_value, str) or not github_variable_name_value.strip()
    ):
        return None, "auth.cache.github_variable_name must be a non-empty string when provided."
    github_variable_name = github_variable_name_value.strip() if isinstance(github_variable_name_value, str) else None
    if github_variable_name is not None and not _is_valid_github_variable_name(github_variable_name):
        return None, "auth.cache.github_variable_name must match environment-style key naming rules."

    github_token_env_value = cache_value.get("github_token_env")
    if github_token_env_value is not None and (
        not isinstance(github_token_env_value, str) or not github_token_env_value.strip()
    ):
        return None, "auth.cache.github_token_env must be a non-empty string when provided."
    github_token_env = github_token_env_value.strip() if isinstance(github_token_env_value, str) else None
    if github_token_env is not None and not _is_valid_env_var_name(github_token_env):
        return None, "auth.cache.github_token_env must be a valid environment variable name."

    github_api_url_value = cache_value.get("github_api_url")
    if github_api_url_value is not None and (
        not isinstance(github_api_url_value, str) or not github_api_url_value.strip()
    ):
        return None, "auth.cache.github_api_url must be a non-empty string when provided."
    github_api_url = github_api_url_value.strip() if isinstance(github_api_url_value, str) else None
    if github_api_url is not None:
        parsed_github_api_url = urlparse(github_api_url)
        if parsed_github_api_url.scheme != "https" or not parsed_github_api_url.netloc:
            return None, "auth.cache.github_api_url must be a valid https URL."

    consul_key_path_value = cache_value.get("consul_key_path")
    if consul_key_path_value is not None and (
        not isinstance(consul_key_path_value, str) or not consul_key_path_value.strip()
    ):
        return None, "auth.cache.consul_key_path must be a non-empty string when provided."
    consul_key_path = consul_key_path_value.strip() if isinstance(consul_key_path_value, str) else None
    if consul_key_path is not None and not _is_valid_consul_key_path(consul_key_path):
        return None, "auth.cache.consul_key_path must be a valid Consul KV path."

    consul_token_env_value = cache_value.get("consul_token_env")
    if consul_token_env_value is not None and (
        not isinstance(consul_token_env_value, str) or not consul_token_env_value.strip()
    ):
        return None, "auth.cache.consul_token_env must be a non-empty string when provided."
    consul_token_env = consul_token_env_value.strip() if isinstance(consul_token_env_value, str) else None
    if consul_token_env is not None and not _is_valid_env_var_name(consul_token_env):
        return None, "auth.cache.consul_token_env must be a valid environment variable name."

    consul_api_url_value = cache_value.get("consul_api_url")
    if consul_api_url_value is not None and (
        not isinstance(consul_api_url_value, str) or not consul_api_url_value.strip()
    ):
        return None, "auth.cache.consul_api_url must be a non-empty string when provided."
    consul_api_url = consul_api_url_value.strip() if isinstance(consul_api_url_value, str) else None
    if consul_api_url is not None:
        parsed_consul_api_url = urlparse(consul_api_url)
        if parsed_consul_api_url.scheme not in {"http", "https"} or not parsed_consul_api_url.netloc:
            return None, "auth.cache.consul_api_url must be a valid http/https URL."

    redis_key_value = cache_value.get("redis_key")
    if redis_key_value is not None and (not isinstance(redis_key_value, str) or not redis_key_value.strip()):
        return None, "auth.cache.redis_key must be a non-empty string when provided."
    redis_key = redis_key_value.strip() if isinstance(redis_key_value, str) else None
    if redis_key is not None and not _is_valid_redis_key(redis_key):
        return None, "auth.cache.redis_key must be a valid Redis key path."

    redis_url_value = cache_value.get("redis_url")
    if redis_url_value is not None and (not isinstance(redis_url_value, str) or not redis_url_value.strip()):
        return None, "auth.cache.redis_url must be a non-empty string when provided."
    redis_url = redis_url_value.strip() if isinstance(redis_url_value, str) else None
    if redis_url is not None:
        parsed_redis_url = urlparse(redis_url)
        if parsed_redis_url.scheme not in {"redis", "rediss"} or not parsed_redis_url.netloc:
            return None, "auth.cache.redis_url must be a valid redis:// or rediss:// URL."

    redis_password_env_value = cache_value.get("redis_password_env")
    if redis_password_env_value is not None and (
        not isinstance(redis_password_env_value, str) or not redis_password_env_value.strip()
    ):
        return None, "auth.cache.redis_password_env must be a non-empty string when provided."
    redis_password_env = redis_password_env_value.strip() if isinstance(redis_password_env_value, str) else None
    if redis_password_env is not None and not _is_valid_env_var_name(redis_password_env):
        return None, "auth.cache.redis_password_env must be a valid environment variable name."

    cf_account_id_value = cache_value.get("cf_account_id")
    if cf_account_id_value is not None and (
        not isinstance(cf_account_id_value, str) or not cf_account_id_value.strip()
    ):
        return None, "auth.cache.cf_account_id must be a non-empty string when provided."
    cf_account_id = cf_account_id_value.strip() if isinstance(cf_account_id_value, str) else None
    if cf_account_id is not None and not _is_valid_cloudflare_identifier(cf_account_id):
        return None, "auth.cache.cf_account_id must match Cloudflare identifier naming rules."

    cf_namespace_id_value = cache_value.get("cf_namespace_id")
    if cf_namespace_id_value is not None and (
        not isinstance(cf_namespace_id_value, str) or not cf_namespace_id_value.strip()
    ):
        return None, "auth.cache.cf_namespace_id must be a non-empty string when provided."
    cf_namespace_id = cf_namespace_id_value.strip() if isinstance(cf_namespace_id_value, str) else None
    if cf_namespace_id is not None and not _is_valid_cloudflare_identifier(cf_namespace_id):
        return None, "auth.cache.cf_namespace_id must match Cloudflare identifier naming rules."

    cf_kv_key_value = cache_value.get("cf_kv_key")
    if cf_kv_key_value is not None and (not isinstance(cf_kv_key_value, str) or not cf_kv_key_value.strip()):
        return None, "auth.cache.cf_kv_key must be a non-empty string when provided."
    cf_kv_key = cf_kv_key_value.strip() if isinstance(cf_kv_key_value, str) else None
    if cf_kv_key is not None and not _is_valid_cloudflare_kv_key(cf_kv_key):
        return None, "auth.cache.cf_kv_key must be a valid Cloudflare KV key."

    cf_api_token_env_value = cache_value.get("cf_api_token_env")
    if cf_api_token_env_value is not None and (
        not isinstance(cf_api_token_env_value, str) or not cf_api_token_env_value.strip()
    ):
        return None, "auth.cache.cf_api_token_env must be a non-empty string when provided."
    cf_api_token_env = cf_api_token_env_value.strip() if isinstance(cf_api_token_env_value, str) else None
    if cf_api_token_env is not None and not _is_valid_env_var_name(cf_api_token_env):
        return None, "auth.cache.cf_api_token_env must be a valid environment variable name."

    cf_api_url_value = cache_value.get("cf_api_url")
    if cf_api_url_value is not None and (not isinstance(cf_api_url_value, str) or not cf_api_url_value.strip()):
        return None, "auth.cache.cf_api_url must be a non-empty string when provided."
    cf_api_url = cf_api_url_value.strip() if isinstance(cf_api_url_value, str) else None
    if cf_api_url is not None:
        parsed_cf_api_url = urlparse(cf_api_url)
        if parsed_cf_api_url.scheme != "https" or not parsed_cf_api_url.netloc:
            return None, "auth.cache.cf_api_url must be a valid https URL."

    etcd_key_value = cache_value.get("etcd_key")
    if etcd_key_value is not None and (not isinstance(etcd_key_value, str) or not etcd_key_value.strip()):
        return None, "auth.cache.etcd_key must be a non-empty string when provided."
    etcd_key = etcd_key_value.strip() if isinstance(etcd_key_value, str) else None
    if etcd_key is not None and not _is_valid_etcd_key(etcd_key):
        return None, "auth.cache.etcd_key must be a valid etcd key path."

    etcd_api_url_value = cache_value.get("etcd_api_url")
    if etcd_api_url_value is not None and (not isinstance(etcd_api_url_value, str) or not etcd_api_url_value.strip()):
        return None, "auth.cache.etcd_api_url must be a non-empty string when provided."
    etcd_api_url = etcd_api_url_value.strip() if isinstance(etcd_api_url_value, str) else None
    if etcd_api_url is not None:
        parsed_etcd_api_url = urlparse(etcd_api_url)
        if parsed_etcd_api_url.scheme not in {"http", "https"} or not parsed_etcd_api_url.netloc:
            return None, "auth.cache.etcd_api_url must be a valid http/https URL."

    etcd_token_env_value = cache_value.get("etcd_token_env")
    if etcd_token_env_value is not None and (
        not isinstance(etcd_token_env_value, str) or not etcd_token_env_value.strip()
    ):
        return None, "auth.cache.etcd_token_env must be a non-empty string when provided."
    etcd_token_env = etcd_token_env_value.strip() if isinstance(etcd_token_env_value, str) else None
    if etcd_token_env is not None and not _is_valid_env_var_name(etcd_token_env):
        return None, "auth.cache.etcd_token_env must be a valid environment variable name."

    if backend != _OAUTH_CACHE_BACKEND_DOPPLER_SECRETS and (
        doppler_project is not None
        or doppler_config is not None
        or doppler_secret_name is not None
        or doppler_token_env is not None
        or doppler_api_url is not None
    ):
        return (
            None,
            "auth.cache.doppler_project, auth.cache.doppler_config, auth.cache.doppler_secret_name, "
            "auth.cache.doppler_token_env, and auth.cache.doppler_api_url are only supported when "
            "auth.cache.backend='doppler_secrets'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT and (
        op_connect_host is not None
        or op_vault_id is not None
        or op_item_id is not None
        or op_field_label is not None
        or op_connect_token_env is not None
    ):
        return (
            None,
            "auth.cache.op_connect_host, auth.cache.op_vault_id, auth.cache.op_item_id, "
            "auth.cache.op_field_label, and auth.cache.op_connect_token_env are only supported when "
            "auth.cache.backend='onepassword_connect'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_BITWARDEN_SECRETS and (
        bw_secret_id is not None or bw_access_token_env is not None or bw_api_url is not None
    ):
        return (
            None,
            "auth.cache.bw_secret_id, auth.cache.bw_access_token_env, and auth.cache.bw_api_url are only "
            "supported when auth.cache.backend='bitwarden_secrets'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_INFISICAL_SECRETS and (
        infisical_project_id is not None
        or infisical_environment is not None
        or infisical_secret_name is not None
        or infisical_token_env is not None
        or infisical_api_url is not None
    ):
        return (
            None,
            "auth.cache.infisical_project_id, auth.cache.infisical_environment, auth.cache.infisical_secret_name, "
            "auth.cache.infisical_token_env, and auth.cache.infisical_api_url are only supported when "
            "auth.cache.backend='infisical_secrets'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_AKEYLESS_SECRETS and (
        akeyless_secret_name is not None or akeyless_token_env is not None or akeyless_api_url is not None
    ):
        return (
            None,
            "auth.cache.akeyless_secret_name, auth.cache.akeyless_token_env, and auth.cache.akeyless_api_url are "
            "only supported when auth.cache.backend='akeyless_secrets'.",
        )

    if backend == _OAUTH_CACHE_BACKEND_AKEYLESS_SECRETS and akeyless_secret_name is None:
        return (
            None,
            "auth.cache.akeyless_secret_name is required when auth.cache.backend='akeyless_secrets'.",
        )

    gitlab_capability = _GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES.get(backend)
    if gitlab_capability is None and (
        gitlab_project_id is not None
        or gitlab_group_id is not None
        or gitlab_variable_key is not None
        or gitlab_environment_scope is not None
        or gitlab_token_env is not None
        or gitlab_api_url is not None
    ):
        return (
            None,
            "auth.cache.gitlab_project_id, auth.cache.gitlab_group_id, auth.cache.gitlab_variable_key, "
            "auth.cache.gitlab_environment_scope, auth.cache.gitlab_token_env, and auth.cache.gitlab_api_url "
            "are only supported when "
            "auth.cache.backend is 'gitlab_variables', 'gitlab_group_variables', or "
            "'gitlab_instance_variables'.",
        )

    if (
        gitlab_capability is not None
        and gitlab_project_id is not None
        and gitlab_capability.identifier_field != ("gitlab_project_id")
    ):
        return (
            None,
            "auth.cache.gitlab_project_id is only supported when auth.cache.backend='gitlab_variables'.",
        )

    if (
        gitlab_capability is not None
        and gitlab_group_id is not None
        and gitlab_capability.identifier_field != ("gitlab_group_id")
    ):
        return (
            None,
            "auth.cache.gitlab_group_id is only supported when auth.cache.backend='gitlab_group_variables'.",
        )

    if (
        gitlab_capability is not None
        and gitlab_capability.identifier_field == "gitlab_project_id"
        and gitlab_project_id is None
    ):
        return (
            None,
            "auth.cache.gitlab_project_id is required when auth.cache.backend='gitlab_variables'.",
        )

    if (
        gitlab_capability is not None
        and gitlab_capability.identifier_field == "gitlab_group_id"
        and gitlab_group_id is None
    ):
        return (
            None,
            "auth.cache.gitlab_group_id is required when auth.cache.backend='gitlab_group_variables'.",
        )

    if (
        gitlab_capability is not None
        and not gitlab_capability.supports_environment_scope
        and gitlab_environment_scope is not None
    ):
        return (
            None,
            "auth.cache.gitlab_environment_scope is only supported when auth.cache.backend is "
            "'gitlab_variables' or 'gitlab_group_variables'.",
        )

    if gitlab_capability is not None and gitlab_variable_key is None:
        return (
            None,
            "auth.cache.gitlab_variable_key is required when auth.cache.backend is "
            "'gitlab_variables', 'gitlab_group_variables', or 'gitlab_instance_variables'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES and github_environment_name is not None:
        return (
            None,
            "auth.cache.github_environment_name is only supported when "
            "auth.cache.backend='github_environment_variables'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES and github_organization is not None:
        return (
            None,
            "auth.cache.github_organization is only supported when "
            "auth.cache.backend='github_organization_variables'.",
        )

    if (
        backend
        not in {
            _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES,
            _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES,
        }
        and github_repository is not None
    ):
        return (
            None,
            "auth.cache.github_repository is only supported when auth.cache.backend is "
            "'github_actions_variables' or 'github_environment_variables'.",
        )

    if backend not in {
        _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES,
        _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES,
        _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES,
    } and (
        github_repository is not None
        or github_variable_name is not None
        or github_token_env is not None
        or github_api_url is not None
    ):
        return (
            None,
            "auth.cache.github_variable_name, auth.cache.github_token_env, and auth.cache.github_api_url are "
            "only supported when auth.cache.backend is 'github_actions_variables', "
            "'github_environment_variables', or 'github_organization_variables'.",
        )

    if (
        backend
        in {
            _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES,
            _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES,
        }
        and github_repository is None
    ):
        return (
            None,
            "auth.cache.github_repository is required when auth.cache.backend is "
            "'github_actions_variables' or 'github_environment_variables'.",
        )
    if (
        backend
        in {
            _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES,
            _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES,
            _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES,
        }
        and github_variable_name is None
    ):
        return (
            None,
            "auth.cache.github_variable_name is required when auth.cache.backend is "
            "'github_actions_variables', 'github_environment_variables', or "
            "'github_organization_variables'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES and github_environment_name is None:
        return (
            None,
            "auth.cache.github_environment_name is required when auth.cache.backend='github_environment_variables'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES and github_organization is None:
        return (
            None,
            "auth.cache.github_organization is required when auth.cache.backend='github_organization_variables'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_CONSUL_KV and (
        consul_key_path is not None or consul_token_env is not None or consul_api_url is not None
    ):
        return (
            None,
            "auth.cache.consul_key_path, auth.cache.consul_token_env, and auth.cache.consul_api_url are "
            "only supported when auth.cache.backend='consul_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_CONSUL_KV and consul_key_path is None:
        return (
            None,
            "auth.cache.consul_key_path is required when auth.cache.backend='consul_kv'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_REDIS_KV and (
        redis_key is not None or redis_url is not None or redis_password_env is not None
    ):
        return (
            None,
            "auth.cache.redis_key, auth.cache.redis_url, and auth.cache.redis_password_env are only "
            "supported when auth.cache.backend='redis_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_REDIS_KV and redis_key is None:
        return (
            None,
            "auth.cache.redis_key is required when auth.cache.backend='redis_kv'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV and (
        cf_account_id is not None
        or cf_namespace_id is not None
        or cf_kv_key is not None
        or cf_api_token_env is not None
        or cf_api_url is not None
    ):
        return (
            None,
            "auth.cache.cf_account_id, auth.cache.cf_namespace_id, auth.cache.cf_kv_key, "
            "auth.cache.cf_api_token_env, and auth.cache.cf_api_url are only supported when "
            "auth.cache.backend='cloudflare_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV and cf_account_id is None:
        return (
            None,
            "auth.cache.cf_account_id is required when auth.cache.backend='cloudflare_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV and cf_namespace_id is None:
        return (
            None,
            "auth.cache.cf_namespace_id is required when auth.cache.backend='cloudflare_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV and cf_kv_key is None:
        return (
            None,
            "auth.cache.cf_kv_key is required when auth.cache.backend='cloudflare_kv'.",
        )

    if backend != _OAUTH_CACHE_BACKEND_ETCD_KV and (
        etcd_key is not None or etcd_api_url is not None or etcd_token_env is not None
    ):
        return (
            None,
            "auth.cache.etcd_key, auth.cache.etcd_api_url, and auth.cache.etcd_token_env are only "
            "supported when auth.cache.backend='etcd_kv'.",
        )
    if backend == _OAUTH_CACHE_BACKEND_ETCD_KV and etcd_key is None:
        return (
            None,
            "auth.cache.etcd_key is required when auth.cache.backend='etcd_kv'.",
        )

    if backend == _OAUTH_CACHE_BACKEND_AWS_SECRETS_MANAGER:
        if aws_secret_id is None:
            return (
                None,
                "auth.cache.aws_secret_id is required when auth.cache.backend='aws_secrets_manager'.",
            )
        if aws_ssm_parameter_name is not None:
            return (
                None,
                "auth.cache.aws_ssm_parameter_name is only supported when auth.cache.backend='aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_AWS_SSM_PARAMETER_STORE:
        if aws_ssm_parameter_name is None:
            return (
                None,
                "auth.cache.aws_ssm_parameter_name is required when auth.cache.backend='aws_ssm_parameter_store'.",
            )
        if aws_secret_id is not None:
            return (
                None,
                "auth.cache.aws_secret_id is only supported when auth.cache.backend='aws_secrets_manager'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_GCP_SECRET_MANAGER:
        if gcp_secret_name is None:
            return (
                None,
                "auth.cache.gcp_secret_name is required when auth.cache.backend='gcp_secret_manager'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_AZURE_KEY_VAULT:
        if azure_vault_url is None:
            return (
                None,
                "auth.cache.azure_vault_url is required when auth.cache.backend='azure_key_vault'.",
            )
        if azure_secret_name is None:
            return (
                None,
                "auth.cache.azure_secret_name is required when auth.cache.backend='azure_key_vault'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_HASHICORP_VAULT:
        if vault_url is None:
            return (
                None,
                "auth.cache.vault_url is required when auth.cache.backend='hashicorp_vault'.",
            )
        if vault_secret_path is None:
            return (
                None,
                "auth.cache.vault_secret_path is required when auth.cache.backend='hashicorp_vault'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_KUBERNETES_SECRETS:
        if k8s_secret_namespace is None:
            return (
                None,
                "auth.cache.k8s_secret_namespace is required when auth.cache.backend='kubernetes_secrets'.",
            )
        if k8s_secret_name is None:
            return (
                None,
                "auth.cache.k8s_secret_name is required when auth.cache.backend='kubernetes_secrets'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_OCI_VAULT:
        if oci_secret_ocid is None:
            return (
                None,
                "auth.cache.oci_secret_ocid is required when auth.cache.backend='oci_vault'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_DOPPLER_SECRETS:
        if doppler_project is None:
            return (
                None,
                "auth.cache.doppler_project is required when auth.cache.backend='doppler_secrets'.",
            )
        if doppler_config is None:
            return (
                None,
                "auth.cache.doppler_config is required when auth.cache.backend='doppler_secrets'.",
            )
        if doppler_secret_name is None:
            return (
                None,
                "auth.cache.doppler_secret_name is required when auth.cache.backend='doppler_secrets'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT:
        if op_connect_host is None:
            return (
                None,
                "auth.cache.op_connect_host is required when auth.cache.backend='onepassword_connect'.",
            )
        if op_vault_id is None:
            return (
                None,
                "auth.cache.op_vault_id is required when auth.cache.backend='onepassword_connect'.",
            )
        if op_item_id is None:
            return (
                None,
                "auth.cache.op_item_id is required when auth.cache.backend='onepassword_connect'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
        if doppler_project is not None or doppler_config is not None or doppler_secret_name is not None:
            return (
                None,
                "auth.cache.doppler_project, auth.cache.doppler_config, and auth.cache.doppler_secret_name are "
                "only supported when auth.cache.backend='doppler_secrets'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_BITWARDEN_SECRETS:
        if bw_secret_id is None:
            return (
                None,
                "auth.cache.bw_secret_id is required when auth.cache.backend='bitwarden_secrets'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
        if doppler_project is not None or doppler_config is not None or doppler_secret_name is not None:
            return (
                None,
                "auth.cache.doppler_project, auth.cache.doppler_config, and auth.cache.doppler_secret_name are "
                "only supported when auth.cache.backend='doppler_secrets'.",
            )
        if op_connect_host is not None or op_vault_id is not None or op_item_id is not None:
            return (
                None,
                "auth.cache.op_connect_host, auth.cache.op_vault_id, and auth.cache.op_item_id are only "
                "supported when auth.cache.backend='onepassword_connect'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_INFISICAL_SECRETS:
        if infisical_project_id is None:
            return (
                None,
                "auth.cache.infisical_project_id is required when auth.cache.backend='infisical_secrets'.",
            )
        if infisical_environment is None:
            return (
                None,
                "auth.cache.infisical_environment is required when auth.cache.backend='infisical_secrets'.",
            )
        if infisical_secret_name is None:
            return (
                None,
                "auth.cache.infisical_secret_name is required when auth.cache.backend='infisical_secrets'.",
            )
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend in {_OAUTH_CACHE_BACKEND_GITLAB_VARIABLES, _OAUTH_CACHE_BACKEND_GITLAB_GROUP_VARIABLES}:
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES:
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES:
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    elif backend == _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES:
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )
    else:
        if (
            aws_secret_id is not None
            or aws_ssm_parameter_name is not None
            or aws_region is not None
            or aws_endpoint_url is not None
        ):
            return (
                None,
                "auth.cache.aws_secret_id, auth.cache.aws_ssm_parameter_name, auth.cache.aws_region, and "
                "auth.cache.aws_endpoint_url are only supported when auth.cache.backend is "
                "'aws_secrets_manager' or 'aws_ssm_parameter_store'.",
            )
        if gcp_secret_name is not None or gcp_endpoint_url is not None:
            return (
                None,
                "auth.cache.gcp_secret_name and auth.cache.gcp_endpoint_url are only supported when "
                "auth.cache.backend='gcp_secret_manager'.",
            )
        if azure_vault_url is not None or azure_secret_name is not None or azure_secret_version not in {None, "latest"}:
            return (
                None,
                "auth.cache.azure_vault_url, auth.cache.azure_secret_name, and auth.cache.azure_secret_version are "
                "only supported when auth.cache.backend='azure_key_vault'.",
            )
        if (
            vault_url is not None
            or vault_secret_path is not None
            or vault_token_env is not None
            or vault_namespace is not None
        ):
            return (
                None,
                "auth.cache.vault_url, auth.cache.vault_secret_path, auth.cache.vault_token_env, and "
                "auth.cache.vault_namespace are only supported when auth.cache.backend='hashicorp_vault'.",
            )
        if k8s_secret_namespace is not None or k8s_secret_name is not None or k8s_secret_key is not None:
            return (
                None,
                "auth.cache.k8s_secret_namespace, auth.cache.k8s_secret_name, and auth.cache.k8s_secret_key are "
                "only supported when auth.cache.backend='kubernetes_secrets'.",
            )
        if oci_secret_ocid is not None or oci_region is not None or oci_endpoint_url is not None:
            return (
                None,
                "auth.cache.oci_secret_ocid, auth.cache.oci_region, and auth.cache.oci_endpoint_url are only "
                "supported when auth.cache.backend='oci_vault'.",
            )

    return (
        OAuthCacheSettings(
            persistent=persistent_value,
            namespace=namespace_value.strip(),
            backend=backend,
            aws_secret_id=aws_secret_id,
            aws_ssm_parameter_name=aws_ssm_parameter_name,
            aws_region=aws_region,
            aws_endpoint_url=aws_endpoint_url,
            gcp_secret_name=gcp_secret_name,
            gcp_endpoint_url=gcp_endpoint_url,
            azure_vault_url=azure_vault_url,
            azure_secret_name=azure_secret_name,
            azure_secret_version=azure_secret_version,
            vault_url=vault_url,
            vault_secret_path=vault_secret_path,
            vault_token_env=vault_token_env,
            vault_namespace=vault_namespace,
            k8s_secret_namespace=k8s_secret_namespace,
            k8s_secret_name=k8s_secret_name,
            k8s_secret_key=(
                k8s_secret_key
                if k8s_secret_key is not None
                else ("oauth_cache" if backend == _OAUTH_CACHE_BACKEND_KUBERNETES_SECRETS else None)
            ),
            oci_secret_ocid=oci_secret_ocid,
            oci_region=oci_region,
            oci_endpoint_url=oci_endpoint_url,
            doppler_project=doppler_project,
            doppler_config=doppler_config,
            doppler_secret_name=doppler_secret_name,
            doppler_token_env=(
                doppler_token_env
                if doppler_token_env is not None
                else ("DOPPLER_TOKEN" if backend == _OAUTH_CACHE_BACKEND_DOPPLER_SECRETS else None)
            ),
            doppler_api_url=doppler_api_url,
            op_connect_host=op_connect_host,
            op_vault_id=op_vault_id,
            op_item_id=op_item_id,
            op_field_label=(
                op_field_label
                if op_field_label is not None
                else ("oauth_cache" if backend == _OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT else None)
            ),
            op_connect_token_env=(
                op_connect_token_env
                if op_connect_token_env is not None
                else ("OP_CONNECT_TOKEN" if backend == _OAUTH_CACHE_BACKEND_ONEPASSWORD_CONNECT else None)
            ),
            bw_secret_id=bw_secret_id,
            bw_access_token_env=(
                bw_access_token_env
                if bw_access_token_env is not None
                else ("BWS_ACCESS_TOKEN" if backend == _OAUTH_CACHE_BACKEND_BITWARDEN_SECRETS else None)
            ),
            bw_api_url=bw_api_url,
            infisical_project_id=infisical_project_id,
            infisical_environment=infisical_environment,
            infisical_secret_name=infisical_secret_name,
            infisical_token_env=(
                infisical_token_env
                if infisical_token_env is not None
                else ("INFISICAL_TOKEN" if backend == _OAUTH_CACHE_BACKEND_INFISICAL_SECRETS else None)
            ),
            infisical_api_url=infisical_api_url,
            akeyless_secret_name=akeyless_secret_name,
            akeyless_token_env=(
                akeyless_token_env
                if akeyless_token_env is not None
                else ("AKEYLESS_TOKEN" if backend == _OAUTH_CACHE_BACKEND_AKEYLESS_SECRETS else None)
            ),
            akeyless_api_url=akeyless_api_url,
            gitlab_project_id=gitlab_project_id,
            gitlab_group_id=gitlab_group_id,
            gitlab_variable_key=gitlab_variable_key,
            gitlab_environment_scope=(
                gitlab_environment_scope
                if gitlab_environment_scope is not None
                else ("*" if gitlab_capability is not None and gitlab_capability.supports_environment_scope else None)
            ),
            gitlab_token_env=(
                gitlab_token_env
                if gitlab_token_env is not None
                else ("GITLAB_TOKEN" if gitlab_capability is not None else None)
            ),
            gitlab_api_url=gitlab_api_url,
            github_repository=github_repository,
            github_organization=github_organization,
            github_environment_name=github_environment_name,
            github_variable_name=github_variable_name,
            github_token_env=(
                github_token_env
                if github_token_env is not None
                else (
                    "GITHUB_TOKEN"
                    if backend
                    in {
                        _OAUTH_CACHE_BACKEND_GITHUB_ACTIONS_VARIABLES,
                        _OAUTH_CACHE_BACKEND_GITHUB_ENVIRONMENT_VARIABLES,
                        _OAUTH_CACHE_BACKEND_GITHUB_ORGANIZATION_VARIABLES,
                    }
                    else None
                )
            ),
            github_api_url=github_api_url,
            consul_key_path=consul_key_path,
            consul_token_env=(
                consul_token_env
                if consul_token_env is not None
                else ("CONSUL_HTTP_TOKEN" if backend == _OAUTH_CACHE_BACKEND_CONSUL_KV else None)
            ),
            consul_api_url=consul_api_url,
            redis_key=redis_key,
            redis_url=redis_url,
            redis_password_env=(
                redis_password_env
                if redis_password_env is not None
                else ("REDIS_PASSWORD" if backend == _OAUTH_CACHE_BACKEND_REDIS_KV else None)
            ),
            cf_account_id=cf_account_id,
            cf_namespace_id=cf_namespace_id,
            cf_kv_key=cf_kv_key,
            cf_api_token_env=(
                cf_api_token_env
                if cf_api_token_env is not None
                else ("CLOUDFLARE_API_TOKEN" if backend == _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV else None)
            ),
            cf_api_url=(
                cf_api_url
                if cf_api_url is not None
                else (_CLOUDFLARE_DEFAULT_API_URL if backend == _OAUTH_CACHE_BACKEND_CLOUDFLARE_KV else None)
            ),
            etcd_key=etcd_key,
            etcd_api_url=(
                etcd_api_url
                if etcd_api_url is not None
                else (_ETCD_DEFAULT_API_URL if backend == _OAUTH_CACHE_BACKEND_ETCD_KV else None)
            ),
            etcd_token_env=(
                etcd_token_env
                if etcd_token_env is not None
                else ("ETCD_TOKEN" if backend == _OAUTH_CACHE_BACKEND_ETCD_KV else None)
            ),
        ),
        None,
    )


def _is_valid_gcp_secret_name(value: str) -> bool:
    """Validate gcp secret name shape: projects/<project>/secrets/<secret>."""
    return re.fullmatch(r"projects/[^/]+/secrets/[^/]+", value) is not None


def _is_valid_azure_vault_url(value: str) -> bool:
    """Validate Azure Key Vault URL shape: https://<name>.vault.azure.net."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return False
    host = parsed.netloc.lower()
    return host.endswith(".vault.azure.net")


def _is_valid_azure_secret_name(value: str) -> bool:
    """Validate Azure Key Vault secret name shape."""
    return re.fullmatch(r"[0-9A-Za-z-]{1,127}", value) is not None


def _is_valid_vault_secret_path(value: str) -> bool:
    """Validate HashiCorp Vault KV path shape."""
    return re.fullmatch(r"[A-Za-z0-9_.\-\/]{1,256}", value) is not None


def _is_valid_k8s_resource_name(value: str) -> bool:
    """Validate Kubernetes DNS subdomain naming shape (namespace/secret name)."""
    return len(value) <= 253 and re.fullmatch(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?", value) is not None


def _is_valid_k8s_secret_key(value: str) -> bool:
    """Validate Kubernetes Secret data key naming shape."""
    return re.fullmatch(r"[A-Za-z0-9._-]{1,253}", value) is not None


def _is_valid_oci_secret_ocid(value: str) -> bool:
    """Validate generic OCI OCID shape for Vault secret identifiers."""
    return re.fullmatch(r"ocid1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+", value) is not None


def _is_valid_env_var_name(value: str) -> bool:
    """Validate POSIX-style environment variable name shape."""
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is not None


def _is_valid_bitwarden_secret_id(value: str) -> bool:
    """Validate Bitwarden secret identifier shape (UUID-style)."""
    return re.fullmatch(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", value) is not None


def _is_valid_doppler_identifier(value: str) -> bool:
    """Validate Doppler identifier-like values used for project/config/secret fields."""
    return re.fullmatch(r"[0-9A-Za-z_.-]{1,128}", value) is not None


def _is_valid_infisical_identifier(value: str) -> bool:
    """Validate Infisical identifier-like values used for project/environment/secret fields."""
    return re.fullmatch(r"[0-9A-Za-z_.:-]{1,128}", value) is not None


def _is_valid_akeyless_secret_name(value: str) -> bool:
    """Validate Akeyless secret name/path shape used for pre-provisioned secret lookup."""
    return re.fullmatch(r"[0-9A-Za-z_./:-]{1,256}", value) is not None


def _is_valid_gitlab_project_id(value: str) -> bool:
    """Validate GitLab project identifier shape for API path usage."""
    return re.fullmatch(r"[0-9]{1,20}", value) is not None


def _is_valid_gitlab_group_id(value: str) -> bool:
    """Validate GitLab group identifier shape for API path usage."""
    return re.fullmatch(r"[0-9]{1,20}", value) is not None


def _is_valid_gitlab_variable_key(value: str) -> bool:
    """Validate GitLab CI variable key naming shape."""
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,254}", value) is not None


def _is_valid_github_repository(value: str) -> bool:
    """Validate GitHub repository slug shape (<owner>/<repo>)."""
    return re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value) is not None


def _is_valid_github_organization(value: str) -> bool:
    """Validate GitHub organization slug shape."""
    return re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", value) is not None


def _is_valid_github_variable_name(value: str) -> bool:
    """Validate GitHub Actions variable naming shape."""
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,254}", value) is not None


def _is_valid_consul_key_path(value: str) -> bool:
    """Validate Consul KV key path shape."""
    normalized = value.strip().strip("/")
    if not normalized:
        return False
    return re.fullmatch(r"[0-9A-Za-z_.\-/]{1,512}", normalized) is not None


def _is_valid_redis_key(value: str) -> bool:
    """Validate Redis key path shape."""
    normalized = value.strip().strip("/")
    if not normalized:
        return False
    return re.fullmatch(r"[0-9A-Za-z_.:\-/]{1,512}", normalized) is not None


def _is_valid_etcd_key(value: str) -> bool:
    """Validate etcd v3 key path shape."""
    normalized = value.strip().strip("/")
    if not normalized:
        return False
    return re.fullmatch(r"[0-9A-Za-z_.:\-/]{1,512}", normalized) is not None


def _is_valid_cloudflare_identifier(value: str) -> bool:
    """Validate Cloudflare account/namespace identifier shape."""
    return re.fullmatch(r"[0-9A-Za-z_-]{1,128}", value) is not None


def _is_valid_cloudflare_kv_key(value: str) -> bool:
    """Validate Cloudflare KV key shape."""
    normalized = value.strip()
    if not normalized:
        return False
    return re.fullmatch(r"[0-9A-Za-z_.:\-/]{1,512}", normalized) is not None


def _join_auth_env_vars(*env_vars: str | None) -> str | None:
    """Join non-empty env var names for metadata without exposing secret values."""
    joined = [value for value in env_vars if isinstance(value, str) and value.strip()]
    if not joined:
        return None
    return ",".join(joined)


def _read_auth_file_value(file_path: str, field_name: str) -> tuple[str | None, str | None]:
    """Read required auth file contents without exposing file secrets."""
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return None, f"auth.{field_name} path does not exist or is not a file."
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None, f"auth.{field_name} could not be read."
    if not content.strip():
        return None, f"auth.{field_name} file is empty."
    return content, None


def _resolve_oauth_mtls_config(auth_value: dict[str, Any]) -> tuple[OAuthMTLSConfig | None, str | None]:
    """Resolve optional mTLS config for OAuth token endpoint calls."""
    cert_file, cert_file_error = _validate_optional_auth_text(auth_value.get("mtls_cert_file"), "mtls_cert_file")
    if cert_file_error is not None:
        return None, cert_file_error

    key_file, key_file_error = _validate_optional_auth_text(auth_value.get("mtls_key_file"), "mtls_key_file")
    if key_file_error is not None:
        return None, key_file_error

    ca_bundle_file, ca_bundle_error = _validate_optional_auth_text(
        auth_value.get("mtls_ca_bundle_file"), "mtls_ca_bundle_file"
    )
    if ca_bundle_error is not None:
        return None, ca_bundle_error

    mtls_fields_provided = any(value is not None for value in (cert_file, key_file, ca_bundle_file))
    if not mtls_fields_provided:
        return None, None

    if cert_file is None or key_file is None:
        return None, "auth.mtls_cert_file and auth.mtls_key_file must be provided together."

    cert_path = Path(cert_file)
    key_path = Path(key_file)
    if not cert_path.exists() or not cert_path.is_file():
        return None, "auth.mtls_cert_file path does not exist or is not a file."
    if not key_path.exists() or not key_path.is_file():
        return None, "auth.mtls_key_file path does not exist or is not a file."

    if ca_bundle_file is not None:
        ca_path = Path(ca_bundle_file)
        if not ca_path.exists() or not ca_path.is_file():
            return None, "auth.mtls_ca_bundle_file path does not exist or is not a file."

    return OAuthMTLSConfig(cert_file=cert_file, key_file=key_file, ca_bundle_file=ca_bundle_file), None


def _resolve_oauth_private_key_jwt_signer(
    auth_value: dict[str, Any],
) -> tuple[OAuthPrivateKeyJWTSigner | None, str | None, str | None]:
    """Resolve private_key_jwt signing source from env, file, or AWS KMS."""
    key_env, key_env_error = _validate_optional_auth_env_name(
        auth_value.get("client_assertion_key_env"), "client_assertion_key_env"
    )
    if key_env_error is not None:
        return None, None, key_env_error

    key_file, key_file_error = _validate_optional_auth_text(
        auth_value.get("client_assertion_key_file"), "client_assertion_key_file"
    )
    if key_file_error is not None:
        return None, None, key_file_error

    kms_key_id, kms_key_id_error = _validate_optional_auth_text(
        auth_value.get("client_assertion_kms_key_id"),
        "client_assertion_kms_key_id",
    )
    if kms_key_id_error is not None:
        return None, None, kms_key_id_error

    kms_region, kms_region_error = _validate_optional_auth_text(
        auth_value.get("client_assertion_kms_region"),
        "client_assertion_kms_region",
    )
    if kms_region_error is not None:
        return None, key_env, kms_region_error

    kms_endpoint_url, kms_endpoint_url_error = _validate_optional_auth_text(
        auth_value.get("client_assertion_kms_endpoint_url"),
        "client_assertion_kms_endpoint_url",
    )
    if kms_endpoint_url_error is not None:
        return None, key_env, kms_endpoint_url_error
    if kms_endpoint_url is not None:
        parsed_kms_endpoint_url = urlparse(kms_endpoint_url)
        if parsed_kms_endpoint_url.scheme not in {"http", "https"} or not parsed_kms_endpoint_url.netloc:
            return None, key_env, "auth.client_assertion_kms_endpoint_url must be a valid http/https URL."

    selected_sources = [source for source in (key_env, key_file, kms_key_id) if source is not None]
    if not selected_sources:
        return (
            None,
            None,
            "auth.client_assertion_key_env or auth.client_assertion_key_file or auth.client_assertion_kms_key_id is required when "
            "auth.token_endpoint_auth_method='private_key_jwt'.",
        )
    if len(selected_sources) > 1:
        return (
            None,
            None,
            "Provide exactly one of auth.client_assertion_key_env or auth.client_assertion_key_file or "
            "auth.client_assertion_kms_key_id.",
        )

    kid, kid_error = _validate_optional_auth_text(auth_value.get("client_assertion_kid"), "client_assertion_kid")
    if kid_error is not None:
        return None, key_env, kid_error

    if kms_key_id is not None:
        return (
            OAuthPrivateKeyJWTSigner(
                private_key_pem=None,
                kid=kid,
                signing_source="aws_kms",
                kms_key_id=kms_key_id,
                kms_region=kms_region,
                kms_endpoint_url=kms_endpoint_url,
            ),
            key_env,
            None,
        )

    private_key_pem: str
    if key_env is not None:
        private_key_pem_value, key_env_read_error = _read_auth_env_value(key_env)
        if key_env_read_error is not None:
            return None, key_env, key_env_read_error
        assert private_key_pem_value is not None
        private_key_pem = private_key_pem_value
    else:
        assert key_file is not None
        private_key_pem_value, key_file_read_error = _read_auth_file_value(key_file, "client_assertion_key_file")
        if key_file_read_error is not None:
            return None, None, key_file_read_error
        assert private_key_pem_value is not None
        private_key_pem = private_key_pem_value

    key_validate_error = _validate_private_key_jwt_signing_key(private_key_pem)
    if key_validate_error is not None:
        return None, key_env, key_validate_error

    return OAuthPrivateKeyJWTSigner(private_key_pem=private_key_pem, kid=kid, signing_source="pem"), key_env, None


def _validate_private_key_jwt_signing_key(private_key_pem: str) -> str | None:
    """Validate PEM signing key for RS256 client assertions."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    except Exception:
        return "cryptography backend is required for private_key_jwt signing."

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    except Exception:
        return "Unable to parse auth client assertion private key."

    if not isinstance(private_key, RSAPrivateKey):
        return "auth private key for private_key_jwt must be an RSA private key."
    return None


def _build_private_key_jwt_client_assertion(
    token_url: str,
    client_id: str,
    signer: OAuthPrivateKeyJWTSigner,
) -> tuple[str | None, str | None]:
    """Build RFC7523 private_key_jwt assertion for token endpoint authentication."""
    issued_at = int(time.time())
    header_payload: dict[str, Any] = {"alg": "RS256", "typ": "JWT"}
    if signer.kid is not None:
        header_payload["kid"] = signer.kid

    claims_payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_url,
        "iat": issued_at,
        "exp": issued_at + 300,
        "jti": secrets.token_urlsafe(24),
    }

    header_segment = _base64url_encode(
        json.dumps(header_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    claims_segment = _base64url_encode(
        json.dumps(claims_payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{header_segment}.{claims_segment}".encode("ascii")

    if signer.signing_source == "aws_kms":
        signature, signature_error = _sign_private_key_jwt_with_aws_kms(signing_input=signing_input, signer=signer)
        if signature_error is not None:
            return None, signature_error
        assert signature is not None
    else:
        if signer.private_key_pem is None:
            return None, "auth private key for private_key_jwt is missing."
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        except Exception:
            return None, "cryptography backend is required for private_key_jwt signing."

        try:
            private_key = serialization.load_pem_private_key(signer.private_key_pem.encode("utf-8"), password=None)
        except Exception:
            return None, "Unable to parse auth client assertion private key."
        if not isinstance(private_key, RSAPrivateKey):
            return None, "auth private key for private_key_jwt must be an RSA private key."

        try:
            signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return None, "Failed to sign OAuth private_key_jwt client assertion."

    signature_segment = _base64url_encode(signature)
    return f"{header_segment}.{claims_segment}.{signature_segment}", None


def _sign_private_key_jwt_with_aws_kms(
    signing_input: bytes,
    signer: OAuthPrivateKeyJWTSigner,
) -> tuple[bytes | None, str | None]:
    """Sign private_key_jwt assertion bytes with AWS KMS Sign API."""
    if signer.kms_key_id is None:
        return None, "auth.client_assertion_kms_key_id is required for AWS KMS signing."

    try:
        boto3_module = importlib.import_module("boto3")
    except Exception:
        return None, "boto3 is required for auth.token_endpoint_auth_method='private_key_jwt' with KMS signing."

    try:
        client_kwargs: dict[str, Any] = {}
        if signer.kms_region is not None:
            client_kwargs["region_name"] = signer.kms_region
        if signer.kms_endpoint_url is not None:
            client_kwargs["endpoint_url"] = signer.kms_endpoint_url

        kms_client = boto3_module.client("kms", **client_kwargs)
        response = kms_client.sign(
            KeyId=signer.kms_key_id,
            Message=signing_input,
            MessageType="RAW",
            SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256",
        )
    except Exception as exc:
        return None, f"AWS KMS signing failed: {exc.__class__.__name__}."

    signature = response.get("Signature")
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        return None, "AWS KMS signing response did not include a valid signature."
    return bytes(signature), None


def _base64url_encode(value: bytes) -> str:
    """Base64url encode helper without '=' padding."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _resolve_oauth_client_credentials_token(
    server_name: str,
    transport: str,
    auth_type: str,
    token_url: str,
    client_id: str,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    token_endpoint_auth_method: str,
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None,
    mtls_config: OAuthMTLSConfig | None,
    timeout_seconds: int,
    env_var: str | None,
    cache_settings: OAuthCacheSettings,
) -> tuple[str | None, str | None, Finding | None]:
    """Resolve OAuth token with single-run cache and build findings on fetch failure."""
    cache_key = _build_oauth_cache_key(
        token_url=token_url,
        client_id=client_id,
        scope=scope,
        audience=audience,
        namespace=cache_settings.namespace,
    )
    _hydrate_oauth_cache_from_persistent(cache_key=cache_key, cache_settings=cache_settings)
    cached_token = _get_cached_oauth_token(cache_key)
    cached_token_type = _get_cached_oauth_token_type(cache_key)
    if cached_token is not None:
        return cached_token, cached_token_type, None

    if client_assertion_signer is None and mtls_config is None:
        request_result = _request_oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            audience=audience,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
        )
    elif client_assertion_signer is not None and mtls_config is None:
        request_result = _request_oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            audience=audience,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            client_assertion_signer=client_assertion_signer,
        )
    elif client_assertion_signer is None and mtls_config is not None:
        request_result = _request_oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            audience=audience,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            mtls_config=mtls_config,
        )
    else:
        request_result = _request_oauth_client_credentials_token(
            token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            audience=audience,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            client_assertion_signer=client_assertion_signer,
            mtls_config=mtls_config,
        )
    token_value, expires_in, token_error, http_status, token_type = _coerce_client_credentials_token_response(
        request_result
    )
    if token_error is not None or token_value is None:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason=token_error or "OAuth token endpoint returned an empty token.",
                http_status=http_status,
            ),
        )

    _store_oauth_token_cache(
        cache_key=cache_key,
        token=token_value,
        expires_in=expires_in,
        token_type=token_type,
        cache_settings=cache_settings,
    )
    return token_value, token_type, None


def _resolve_oauth_device_code_token(
    server_name: str,
    transport: str,
    auth_type: str,
    device_authorization_url: str,
    token_url: str,
    client_id: str,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    token_endpoint_auth_method: str,
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None,
    mtls_config: OAuthMTLSConfig | None,
    timeout_seconds: int,
    is_interactive_tty: bool,
    env_var: str | None,
    cache_settings: OAuthCacheSettings,
) -> tuple[str | None, str | None, Finding | None]:
    """Resolve OAuth device-code token with refresh-first behavior on expiry."""
    cache_key = _build_oauth_cache_key(
        token_url=token_url,
        client_id=client_id,
        scope=scope,
        audience=audience,
        namespace=cache_settings.namespace,
    )
    _hydrate_oauth_cache_from_persistent(cache_key=cache_key, cache_settings=cache_settings)
    cached_token = _get_cached_oauth_token(cache_key)
    cached_token_type = _get_cached_oauth_token_type(cache_key)
    if cached_token is not None:
        return cached_token, cached_token_type, None

    cached_refresh_token = _get_cached_oauth_refresh_token(cache_key)
    if cached_refresh_token is not None:
        if client_assertion_signer is None and mtls_config is None:
            refresh_result = _request_oauth_refresh_token(
                token_url=token_url,
                refresh_token=cached_refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                timeout_seconds=timeout_seconds,
            )
        elif client_assertion_signer is not None and mtls_config is None:
            refresh_result = _request_oauth_refresh_token(
                token_url=token_url,
                refresh_token=cached_refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                timeout_seconds=timeout_seconds,
                client_assertion_signer=client_assertion_signer,
            )
        elif client_assertion_signer is None and mtls_config is not None:
            refresh_result = _request_oauth_refresh_token(
                token_url=token_url,
                refresh_token=cached_refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                timeout_seconds=timeout_seconds,
                mtls_config=mtls_config,
            )
        else:
            refresh_result = _request_oauth_refresh_token(
                token_url=token_url,
                refresh_token=cached_refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                timeout_seconds=timeout_seconds,
                client_assertion_signer=client_assertion_signer,
                mtls_config=mtls_config,
            )
        refreshed_token, refreshed_expires_in, next_refresh_token, refresh_error, refresh_http_status, refresh_type = (
            _coerce_oauth_refresh_response(refresh_result)
        )
        if refresh_error is not None or refreshed_token is None:
            if _is_reauth_fallback_error(refresh_error):
                _drop_oauth_refresh_token(cache_key, cache_settings=cache_settings)
                if not is_interactive_tty:
                    return (
                        None,
                        None,
                        _build_auth_token_error_finding(
                            server_name=server_name,
                            transport=transport,
                            auth_type=auth_type,
                            env_var=env_var,
                            token_url=token_url,
                            reason=(
                                "Refresh token is invalid and interactive re-authorization is "
                                "not available in this environment."
                            ),
                            http_status=refresh_http_status,
                        ),
                    )
            else:
                return (
                    None,
                    None,
                    _build_auth_token_error_finding(
                        server_name=server_name,
                        transport=transport,
                        auth_type=auth_type,
                        env_var=env_var,
                        token_url=token_url,
                        reason=refresh_error or "Refresh token flow returned an empty access_token.",
                        http_status=refresh_http_status,
                    ),
                )
        else:
            _store_oauth_token_cache(
                cache_key=cache_key,
                token=refreshed_token,
                expires_in=refreshed_expires_in,
                refresh_token=next_refresh_token or cached_refresh_token,
                token_type=refresh_type,
                cache_settings=cache_settings,
            )
            return refreshed_token, refresh_type, None

    if not is_interactive_tty:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason="oauth_device_code requires an interactive TTY for verification.",
                http_status=None,
            ),
        )

    device_payload, device_error, device_http_status = _request_oauth_device_authorization(
        device_authorization_url=device_authorization_url,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        audience=audience,
        timeout_seconds=timeout_seconds,
    )
    if device_error is not None or device_payload is None:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason=device_error or "Device authorization endpoint returned an empty response.",
                http_status=device_http_status,
            ),
        )

    device_code = device_payload.get("device_code")
    if not isinstance(device_code, str) or not device_code.strip():
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason="Device authorization response is missing a non-empty device_code.",
                http_status=device_http_status,
            ),
        )

    verification_uri = _optional_non_empty_text(device_payload.get("verification_uri"))
    verification_uri_complete = _optional_non_empty_text(device_payload.get("verification_uri_complete"))
    user_code = _optional_non_empty_text(device_payload.get("user_code"))

    _emit_oauth_device_code_instructions(
        server_name=server_name,
        verification_uri=verification_uri,
        verification_uri_complete=verification_uri_complete,
        user_code=user_code,
    )

    device_expires_in = _coerce_expires_in_value(device_payload.get("expires_in"))
    poll_interval_seconds = _coerce_poll_interval_seconds(device_payload.get("interval"), default=5)

    if client_assertion_signer is None and mtls_config is None:
        poll_result = _poll_oauth_device_code_token(
            token_url=token_url,
            device_code=device_code.strip(),
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            device_expires_in=device_expires_in,
        )
    elif client_assertion_signer is not None and mtls_config is None:
        poll_result = _poll_oauth_device_code_token(
            token_url=token_url,
            device_code=device_code.strip(),
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            device_expires_in=device_expires_in,
            client_assertion_signer=client_assertion_signer,
        )
    elif client_assertion_signer is None and mtls_config is not None:
        poll_result = _poll_oauth_device_code_token(
            token_url=token_url,
            device_code=device_code.strip(),
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            device_expires_in=device_expires_in,
            mtls_config=mtls_config,
        )
    else:
        poll_result = _poll_oauth_device_code_token(
            token_url=token_url,
            device_code=device_code.strip(),
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            device_expires_in=device_expires_in,
            client_assertion_signer=client_assertion_signer,
            mtls_config=mtls_config,
        )
    token_value, expires_in, refresh_token, token_error, token_http_status, token_type = (
        _coerce_oauth_token_with_refresh_response(poll_result)
    )
    if token_error is not None or token_value is None:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason=token_error or "Device code polling returned an empty access_token.",
                http_status=token_http_status,
            ),
        )

    _store_oauth_token_cache(
        cache_key=cache_key,
        token=token_value,
        expires_in=expires_in,
        refresh_token=refresh_token,
        token_type=token_type,
        cache_settings=cache_settings,
    )
    return token_value, token_type, None


def _resolve_oauth_auth_code_pkce_token(
    server_name: str,
    transport: str,
    auth_type: str,
    authorization_url: str,
    token_url: str,
    client_id: str,
    scope: str | None,
    audience: str | None,
    redirect_host: str,
    redirect_port: int,
    callback_path: str,
    timeout_seconds: int,
    is_interactive_tty: bool,
    env_var: str | None,
    cache_settings: OAuthCacheSettings,
) -> tuple[str | None, str | None, Finding | None]:
    """Resolve OAuth auth-code (PKCE) token with cache + refresh behavior."""
    cache_key = _build_oauth_cache_key(
        token_url=token_url,
        client_id=client_id,
        scope=scope,
        audience=audience,
        namespace=cache_settings.namespace,
    )
    _hydrate_oauth_cache_from_persistent(cache_key=cache_key, cache_settings=cache_settings)
    cached_token = _get_cached_oauth_token(cache_key)
    cached_token_type = _get_cached_oauth_token_type(cache_key)
    if cached_token is not None:
        return cached_token, cached_token_type, None

    cached_refresh_token = _get_cached_oauth_refresh_token(cache_key)
    if cached_refresh_token is not None:
        refresh_result = _request_oauth_refresh_token(
            token_url=token_url,
            refresh_token=cached_refresh_token,
            client_id=client_id,
            client_secret=None,
            token_endpoint_auth_method="client_secret_post",
            timeout_seconds=timeout_seconds,
        )
        refreshed_token, refreshed_expires_in, next_refresh_token, refresh_error, refresh_http_status, refresh_type = (
            _coerce_oauth_refresh_response(refresh_result)
        )
        if refresh_error is not None or refreshed_token is None:
            if _is_reauth_fallback_error(refresh_error):
                _drop_oauth_refresh_token(cache_key, cache_settings=cache_settings)
                if not is_interactive_tty:
                    return (
                        None,
                        None,
                        _build_auth_token_error_finding(
                            server_name=server_name,
                            transport=transport,
                            auth_type=auth_type,
                            env_var=env_var,
                            token_url=token_url,
                            reason=(
                                "Refresh token is invalid and interactive re-authorization is "
                                "not available in this environment."
                            ),
                            http_status=refresh_http_status,
                        ),
                    )
            else:
                return (
                    None,
                    None,
                    _build_auth_token_error_finding(
                        server_name=server_name,
                        transport=transport,
                        auth_type=auth_type,
                        env_var=env_var,
                        token_url=token_url,
                        reason=refresh_error or "Refresh token flow returned an empty access_token.",
                        http_status=refresh_http_status,
                    ),
                )
        else:
            _store_oauth_token_cache(
                cache_key=cache_key,
                token=refreshed_token,
                expires_in=refreshed_expires_in,
                refresh_token=next_refresh_token or cached_refresh_token,
                token_type=refresh_type,
                cache_settings=cache_settings,
            )
            return refreshed_token, refresh_type, None

    if not is_interactive_tty:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason="oauth_auth_code_pkce requires an interactive TTY for verification.",
                http_status=None,
            ),
        )

    code_verifier = _generate_pkce_code_verifier()
    code_challenge = _generate_pkce_code_challenge(code_verifier)
    expected_state = _generate_oauth_state()

    auth_code, callback_state, redirect_uri, auth_code_error = _run_oauth_auth_code_pkce_flow(
        server_name=server_name,
        authorization_url=authorization_url,
        client_id=client_id,
        scope=scope,
        audience=audience,
        redirect_host=redirect_host,
        redirect_port=redirect_port,
        callback_path=callback_path,
        code_challenge=code_challenge,
        expected_state=expected_state,
        timeout_seconds=timeout_seconds,
    )
    if auth_code_error is not None or auth_code is None or callback_state is None or redirect_uri is None:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason=auth_code_error or "Authorization code flow did not complete successfully.",
                http_status=None,
            ),
        )

    if callback_state != expected_state:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason="OAuth callback state mismatch detected.",
                http_status=None,
            ),
        )

    exchange_result = _request_oauth_auth_code_token(
        token_url=token_url,
        auth_code=auth_code,
        redirect_uri=redirect_uri,
        client_id=client_id,
        code_verifier=code_verifier,
        scope=scope,
        audience=audience,
        timeout_seconds=timeout_seconds,
    )
    token_value, expires_in, refresh_token, token_error, token_http_status, token_type = (
        _coerce_oauth_token_with_refresh_response(exchange_result)
    )
    if token_error is not None or token_value is None:
        return (
            None,
            None,
            _build_auth_token_error_finding(
                server_name=server_name,
                transport=transport,
                auth_type=auth_type,
                env_var=env_var,
                token_url=token_url,
                reason=token_error or "Token exchange returned an empty access_token.",
                http_status=token_http_status,
            ),
        )

    _store_oauth_token_cache(
        cache_key=cache_key,
        token=token_value,
        expires_in=expires_in,
        refresh_token=refresh_token,
        token_type=token_type,
        cache_settings=cache_settings,
    )
    return token_value, token_type, None


def _run_oauth_auth_code_pkce_flow(
    server_name: str,
    authorization_url: str,
    client_id: str,
    scope: str | None,
    audience: str | None,
    redirect_host: str,
    redirect_port: int,
    callback_path: str,
    code_challenge: str,
    expected_state: str,
    timeout_seconds: int,
) -> tuple[str | None, str | None, str | None, str | None]:
    """Run local-callback auth-code flow and return callback code/state."""
    callback_server, callback_port, callback_payload, callback_error = _create_oauth_callback_http_server(
        host=redirect_host,
        preferred_port=redirect_port,
        callback_path=callback_path,
    )
    if callback_error is not None or callback_server is None or callback_port is None or callback_payload is None:
        return None, None, None, callback_error or "Unable to start OAuth callback listener."

    redirect_uri = f"http://{redirect_host}:{callback_port}{callback_path}"
    authorization_request_url = _build_oauth_authorization_request_url(
        authorization_url=authorization_url,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        state=expected_state,
        scope=scope,
        audience=audience,
    )
    _emit_oauth_auth_code_pkce_instructions(
        server_name=server_name, authorization_request_url=authorization_request_url
    )

    try:
        received_payload, wait_error = _wait_for_oauth_callback(
            callback_server=callback_server,
            callback_payload=callback_payload,
            timeout_seconds=timeout_seconds,
        )
    finally:
        callback_server.server_close()

    if wait_error is not None or received_payload is None:
        return None, None, redirect_uri, wait_error or "OAuth callback was not received."

    callback_error_code = _optional_non_empty_text(received_payload.get("error"))
    if callback_error_code is not None:
        callback_error_description = _optional_non_empty_text(received_payload.get("error_description"))
        if callback_error_description is not None:
            return (
                None,
                None,
                redirect_uri,
                f"Authorization endpoint returned error '{callback_error_code}': {callback_error_description}.",
            )
        return None, None, redirect_uri, f"Authorization endpoint returned error '{callback_error_code}'."

    auth_code = _optional_non_empty_text(received_payload.get("code"))
    callback_state = _optional_non_empty_text(received_payload.get("state"))
    if auth_code is None:
        return None, None, redirect_uri, "OAuth callback is missing authorization code."
    if callback_state is None:
        return None, None, redirect_uri, "OAuth callback is missing state value."
    return auth_code, callback_state, redirect_uri, None


def _create_oauth_callback_http_server(
    host: str,
    preferred_port: int,
    callback_path: str,
) -> tuple[HTTPServer | None, int | None, dict[str, str | None] | None, str | None]:
    """Create local callback listener; retry with random port on bind failure."""
    callback_payload: dict[str, str | None] = {}

    def _build_server(port: int) -> tuple[HTTPServer | None, str | None]:
        class OAuthCallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: Any) -> None:
                return None

            def do_GET(self) -> None:
                parsed_url = urlparse(self.path)
                if parsed_url.path != callback_path:
                    self.send_response(404)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b"Not found.")
                    return

                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                callback_payload["received"] = "1"
                callback_payload["code"] = _first_query_value(query_params.get("code"))
                callback_payload["state"] = _first_query_value(query_params.get("state"))
                callback_payload["error"] = _first_query_value(query_params.get("error"))
                callback_payload["error_description"] = _first_query_value(query_params.get("error_description"))

                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Authentication received. You can close this window.")

        try:
            server = HTTPServer((host, port), OAuthCallbackHandler)
        except OSError as exc:
            return None, str(exc)
        return server, None

    first_server, first_error = _build_server(preferred_port)
    if first_server is not None:
        return first_server, int(first_server.server_address[1]), callback_payload, None

    fallback_server, fallback_error = _build_server(0)
    if fallback_server is not None:
        return fallback_server, int(fallback_server.server_address[1]), callback_payload, None

    error_parts = [
        f"failed on {host}:{preferred_port} ({first_error or 'unknown bind error'})",
        f"random port fallback failed ({fallback_error or 'unknown bind error'})",
    ]
    return None, None, None, "Unable to bind OAuth callback listener: " + "; ".join(error_parts)


def _wait_for_oauth_callback(
    callback_server: HTTPServer,
    callback_payload: dict[str, str | None],
    timeout_seconds: int,
) -> tuple[dict[str, str | None] | None, str | None]:
    """Wait for one OAuth callback until timeout."""
    deadline = _oauth_now() + max(1.0, float(timeout_seconds))

    while _oauth_now() < deadline:
        if callback_payload.get("received") == "1":
            break

        remaining_seconds = deadline - _oauth_now()
        callback_server.timeout = min(0.5, max(0.05, remaining_seconds))
        callback_server.handle_request()

    if callback_payload.get("received") != "1":
        return None, "Timed out waiting for OAuth callback."
    return callback_payload, None


def _build_oauth_authorization_request_url(
    authorization_url: str,
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    state: str,
    scope: str | None,
    audience: str | None,
) -> str:
    """Build full authorization URL with PKCE + callback parameters."""
    parsed_url = urlparse(authorization_url)
    query_params = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
    query_params.update(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
    )
    if scope is not None:
        query_params["scope"] = scope
    if audience is not None:
        query_params["audience"] = audience
    return urlunparse(parsed_url._replace(query=urlencode(query_params)))


def _request_oauth_auth_code_token(
    token_url: str,
    auth_code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
    scope: str | None,
    audience: str | None,
    timeout_seconds: int,
) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
    """Exchange authorization code for access token using PKCE verifier."""
    request_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if scope is not None:
        request_data["scope"] = scope
    if audience is not None:
        request_data["audience"] = audience

    payload, request_error, http_status = _request_oauth_form_payload(
        endpoint_url=token_url,
        request_data=request_data,
        timeout_seconds=timeout_seconds,
        endpoint_name="Token endpoint",
    )
    if request_error is not None:
        return None, None, None, request_error, http_status, None
    assert payload is not None

    if http_status is not None and http_status >= 400:
        return None, None, None, _extract_oauth_error_reason(payload, http_status), http_status, None

    access_token = _optional_non_empty_text(payload.get("access_token"))
    if access_token is None:
        return None, None, None, "Token endpoint response is missing a non-empty access_token.", http_status, None

    expires_in = _coerce_expires_in_value(payload.get("expires_in"))
    refresh_token = _optional_non_empty_text(payload.get("refresh_token"))
    token_type = _normalize_oauth_scheme(_optional_non_empty_text(payload.get("token_type")))
    return access_token, expires_in, refresh_token, None, http_status, token_type


def _generate_pkce_code_verifier() -> str:
    """Generate RFC7636-compatible high-entropy PKCE code_verifier."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode("ascii").rstrip("=")
    if len(verifier) < 43:
        verifier = verifier + ("A" * (43 - len(verifier)))
    return verifier[:128]


def _generate_pkce_code_challenge(code_verifier: str) -> str:
    """Generate S256 PKCE code_challenge for a verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _generate_oauth_state() -> str:
    """Generate random OAuth state token."""
    return secrets.token_urlsafe(32).rstrip("=")


def _first_query_value(values: list[str] | None) -> str | None:
    """Return first query parameter value when available."""
    if not values:
        return None
    return values[0]


def _request_oauth_device_authorization(
    device_authorization_url: str,
    client_id: str,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    timeout_seconds: int,
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Request OAuth device authorization details."""
    request_data = {"client_id": client_id}
    if client_secret is not None:
        request_data["client_secret"] = client_secret
    if scope is not None:
        request_data["scope"] = scope
    if audience is not None:
        request_data["audience"] = audience

    payload, request_error, http_status = _request_oauth_form_payload(
        endpoint_url=device_authorization_url,
        request_data=request_data,
        timeout_seconds=timeout_seconds,
        endpoint_name="Device authorization endpoint",
    )
    if request_error is not None:
        return None, request_error, http_status
    assert payload is not None

    if http_status is not None and http_status >= 400:
        return None, _extract_oauth_error_reason(payload, http_status), http_status

    return payload, None, http_status


def _poll_oauth_device_code_token(
    token_url: str,
    device_code: str,
    client_id: str,
    client_secret: str | None,
    token_endpoint_auth_method: str,
    timeout_seconds: int,
    poll_interval_seconds: int,
    device_expires_in: float | None,
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None = None,
    mtls_config: OAuthMTLSConfig | None = None,
) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
    """Poll OAuth token endpoint for device-code completion."""
    deadline = _oauth_now() + max(1.0, float(timeout_seconds))
    if device_expires_in is not None:
        deadline = min(deadline, _oauth_now() + device_expires_in)

    current_interval = poll_interval_seconds

    while True:
        if _oauth_now() >= deadline:
            return None, None, None, "Device authorization timed out before completion.", None, None

        request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": device_code,
            "client_id": client_id,
        }

        if client_assertion_signer is None and mtls_config is None:
            payload, request_error, http_status = _request_oauth_form_payload(
                endpoint_url=token_url,
                request_data=request_data,
                timeout_seconds=timeout_seconds,
                endpoint_name="Token endpoint",
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
            )
        elif client_assertion_signer is not None and mtls_config is None:
            payload, request_error, http_status = _request_oauth_form_payload(
                endpoint_url=token_url,
                request_data=request_data,
                timeout_seconds=timeout_seconds,
                endpoint_name="Token endpoint",
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                client_assertion_signer=client_assertion_signer,
            )
        elif client_assertion_signer is None and mtls_config is not None:
            payload, request_error, http_status = _request_oauth_form_payload(
                endpoint_url=token_url,
                request_data=request_data,
                timeout_seconds=timeout_seconds,
                endpoint_name="Token endpoint",
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                mtls_config=mtls_config,
            )
        else:
            payload, request_error, http_status = _request_oauth_form_payload(
                endpoint_url=token_url,
                request_data=request_data,
                timeout_seconds=timeout_seconds,
                endpoint_name="Token endpoint",
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_endpoint_auth_method,
                client_assertion_signer=client_assertion_signer,
                mtls_config=mtls_config,
            )
        if request_error is not None:
            return None, None, None, request_error, http_status, None
        assert payload is not None

        error_code, error_description = _extract_oauth_error_fields(payload)
        if error_code is not None:
            if error_code == "authorization_pending":
                _sleep_until_deadline(interval_seconds=current_interval, deadline=deadline)
                continue
            if error_code == "slow_down":
                current_interval += 5
                _sleep_until_deadline(interval_seconds=current_interval, deadline=deadline)
                continue
            if error_code == "access_denied":
                return None, None, None, "Device authorization was denied by the user.", http_status, None
            if error_code == "expired_token":
                return None, None, None, "Device code expired before authorization completed.", http_status, None

            if error_description is not None:
                return (
                    None,
                    None,
                    None,
                    f"Token endpoint returned OAuth error '{error_code}': {error_description}.",
                    http_status,
                    None,
                )
            return None, None, None, f"Token endpoint returned OAuth error '{error_code}'.", http_status, None

        if http_status is not None and http_status >= 400:
            return None, None, None, f"Token endpoint returned HTTP {http_status}.", http_status, None

        access_token = _optional_non_empty_text(payload.get("access_token"))
        if access_token is None:
            return None, None, None, "Token endpoint response is missing a non-empty access_token.", http_status, None

        expires_in = _coerce_expires_in_value(payload.get("expires_in"))
        refresh_token = _optional_non_empty_text(payload.get("refresh_token"))
        token_type = _normalize_oauth_scheme(_optional_non_empty_text(payload.get("token_type")))
        return access_token, expires_in, refresh_token, None, http_status, token_type


def _request_oauth_refresh_token(
    token_url: str,
    refresh_token: str,
    client_id: str,
    client_secret: str | None,
    token_endpoint_auth_method: str,
    timeout_seconds: int,
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None = None,
    mtls_config: OAuthMTLSConfig | None = None,
) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
    """Refresh OAuth access token using refresh_token grant."""
    request_data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }

    payload, request_error, http_status = _request_oauth_form_payload(
        endpoint_url=token_url,
        request_data=request_data,
        timeout_seconds=timeout_seconds,
        endpoint_name="Token endpoint",
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint_auth_method=token_endpoint_auth_method,
        client_assertion_signer=client_assertion_signer,
        mtls_config=mtls_config,
    )
    if request_error is not None:
        return None, None, None, request_error, http_status, None
    assert payload is not None

    if http_status is not None and http_status >= 400:
        return None, None, None, _extract_oauth_error_reason(payload, http_status), http_status, None

    access_token = _optional_non_empty_text(payload.get("access_token"))
    if access_token is None:
        return None, None, None, "Token endpoint response is missing a non-empty access_token.", http_status, None

    expires_in = _coerce_expires_in_value(payload.get("expires_in"))
    next_refresh_token = _optional_non_empty_text(payload.get("refresh_token"))
    token_type = _normalize_oauth_scheme(_optional_non_empty_text(payload.get("token_type")))
    return access_token, expires_in, next_refresh_token, None, http_status, token_type


def _request_oauth_form_payload(
    endpoint_url: str,
    request_data: dict[str, str],
    timeout_seconds: int,
    endpoint_name: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    token_endpoint_auth_method: str = "client_secret_post",
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None = None,
    mtls_config: OAuthMTLSConfig | None = None,
) -> tuple[dict[str, Any] | None, str | None, int | None]:
    """Execute OAuth form POST with transient retry and parse provider payload."""
    request_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    request_body = dict(request_data)

    if token_endpoint_auth_method == "client_secret_basic":
        if client_id is None or client_secret is None:
            return (
                None,
                f"{endpoint_name} client_secret_basic requires both client_id and client_secret.",
                None,
            )
        basic_token = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode("ascii")
        request_headers["Authorization"] = f"Basic {basic_token}"
        request_body.pop("client_secret", None)
    elif token_endpoint_auth_method == "client_secret_post":
        if client_secret is not None and "client_secret" not in request_body:
            request_body["client_secret"] = client_secret
    elif token_endpoint_auth_method == "private_key_jwt":
        if client_id is None:
            return None, f"{endpoint_name} private_key_jwt requires client_id.", None
        if client_assertion_signer is None:
            return None, f"{endpoint_name} private_key_jwt requires client assertion signing key.", None
        client_assertion, client_assertion_error = _build_private_key_jwt_client_assertion(
            token_url=endpoint_url,
            client_id=client_id,
            signer=client_assertion_signer,
        )
        if client_assertion_error is not None:
            return None, client_assertion_error, None
        assert client_assertion is not None
        request_body["client_assertion_type"] = _OAUTH_CLIENT_ASSERTION_TYPE
        request_body["client_assertion"] = client_assertion
        request_body.pop("client_secret", None)
    else:
        return None, f"{endpoint_name} received unsupported token endpoint auth method.", None

    last_request_error: str | None = None
    last_http_status: int | None = None

    for attempt in range(_OAUTH_FORM_REQUEST_MAX_RETRIES + 1):
        try:
            request_kwargs: dict[str, Any] = {}
            if mtls_config is not None:
                request_kwargs["cert"] = (mtls_config.cert_file, mtls_config.key_file)
                if mtls_config.ca_bundle_file is not None:
                    request_kwargs["verify"] = mtls_config.ca_bundle_file
            response = httpx.post(
                endpoint_url,
                data=request_body,
                headers=request_headers,
                timeout=timeout_seconds,
                **request_kwargs,
            )
        except httpx.HTTPError as exc:
            last_request_error = f"{endpoint_name} request failed: {exc}"
            last_http_status = None
            if _is_retryable_oauth_exception(exc) and attempt < _OAUTH_FORM_REQUEST_MAX_RETRIES:
                _oauth_sleep(_oauth_request_backoff_seconds(attempt + 1))
                continue
            return None, last_request_error, None

        http_status = response.status_code
        payload, payload_error = _parse_oauth_response_payload(response=response, endpoint_name=endpoint_name)

        if _is_retryable_oauth_status(http_status) and attempt < _OAUTH_FORM_REQUEST_MAX_RETRIES:
            _oauth_sleep(_oauth_request_backoff_seconds(attempt + 1))
            continue

        if payload_error is not None:
            return None, payload_error, http_status
        assert payload is not None
        return payload, None, http_status

    return None, last_request_error or "OAuth request failed after retries.", last_http_status


def _parse_oauth_response_payload(response: Any, endpoint_name: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse OAuth response payload as JSON object, with form-encoded fallback."""
    http_status = _coerce_optional_int(getattr(response, "status_code", None)) or 0
    response_text = str(getattr(response, "text", ""))

    try:
        payload = response.json()
    except ValueError:
        form_payload = _parse_form_encoded_payload(response_text)
        if form_payload is not None:
            return form_payload, None
        if http_status >= 400:
            return None, f"{endpoint_name} returned HTTP {http_status}."
        return None, f"{endpoint_name} returned a non-JSON response."

    if not isinstance(payload, dict):
        return None, f"{endpoint_name} response must be a JSON object."
    return payload, None


def _is_retryable_oauth_status(http_status: int | None) -> bool:
    """Return True when OAuth HTTP status should be retried."""
    if http_status is None:
        return False
    return http_status in _OAUTH_RETRYABLE_HTTP_STATUS_CODES


def _is_retryable_oauth_exception(exc: Exception) -> bool:
    """Return True for transient OAuth transport exceptions."""
    return isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.ConnectError))


def _oauth_request_backoff_seconds(retry_attempt: int) -> float:
    """Return bounded backoff for OAuth retry attempts."""
    return min(1.0, _OAUTH_FORM_REQUEST_BASE_BACKOFF_SECONDS * float(max(1, retry_attempt)))


def _extract_oauth_error_reason(payload: dict[str, Any], http_status: int) -> str:
    """Render deterministic OAuth error reason from endpoint payload."""
    error_code, error_description = _extract_oauth_error_fields(payload)
    if error_code is None:
        return f"OAuth endpoint returned HTTP {http_status}."
    if error_description is None:
        return f"OAuth endpoint returned error '{error_code}' (HTTP {http_status})."
    return f"OAuth endpoint returned error '{error_code}' (HTTP {http_status}): {error_description}."


def _extract_oauth_error_fields(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    """Extract normalized OAuth error code and description from heterogeneous provider payloads."""
    error_code = _optional_non_empty_text(payload.get("error")) or _optional_non_empty_text(payload.get("error_code"))
    if error_code is not None:
        error_code = error_code.strip().lower()

    error_description = (
        _optional_non_empty_text(payload.get("error_description"))
        or _optional_non_empty_text(payload.get("error_message"))
        or _optional_non_empty_text(payload.get("message"))
    )
    return error_code, error_description


def _coerce_client_credentials_token_response(
    result: Any,
) -> tuple[str | None, float | None, str | None, int | None, str | None]:
    """Support legacy and current tuple shapes for client-credentials responses."""
    if isinstance(result, tuple):
        if len(result) == 5:
            token_value, expires_in, token_error, http_status, token_type = result
            return (
                _optional_non_empty_text(token_value),
                _coerce_expires_in_value(expires_in),
                _optional_non_empty_text(token_error),
                _coerce_optional_int(http_status),
                _normalize_oauth_scheme(_optional_non_empty_text(token_type)),
            )
        if len(result) == 4:
            token_value, expires_in, token_error, http_status = result
            return (
                _optional_non_empty_text(token_value),
                _coerce_expires_in_value(expires_in),
                _optional_non_empty_text(token_error),
                _coerce_optional_int(http_status),
                None,
            )
    return None, None, "Invalid token response shape.", None, None


def _coerce_oauth_token_with_refresh_response(
    result: Any,
) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
    """Support legacy and current tuple shapes for OAuth responses with refresh token."""
    if isinstance(result, tuple):
        if len(result) == 6:
            token_value, expires_in, refresh_token, token_error, http_status, token_type = result
            return (
                _optional_non_empty_text(token_value),
                _coerce_expires_in_value(expires_in),
                _optional_non_empty_text(refresh_token),
                _optional_non_empty_text(token_error),
                _coerce_optional_int(http_status),
                _normalize_oauth_scheme(_optional_non_empty_text(token_type)),
            )
        if len(result) == 5:
            token_value, expires_in, refresh_token, token_error, http_status = result
            return (
                _optional_non_empty_text(token_value),
                _coerce_expires_in_value(expires_in),
                _optional_non_empty_text(refresh_token),
                _optional_non_empty_text(token_error),
                _coerce_optional_int(http_status),
                None,
            )
    return None, None, None, "Invalid token response shape.", None, None


def _coerce_oauth_refresh_response(
    result: Any,
) -> tuple[str | None, float | None, str | None, str | None, int | None, str | None]:
    """Support legacy and current tuple shapes for refresh-token responses."""
    return _coerce_oauth_token_with_refresh_response(result)


def _coerce_optional_int(value: Any) -> int | None:
    """Normalize optional integer fields from patched test responses."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return int(float(stripped))
        except ValueError:
            return None
    return None


def _extract_oauth_error_code_from_reason(reason: str | None) -> str | None:
    """Extract OAuth error code from standardized reason text when available."""
    if reason is None:
        return None
    match = re.search(r"error '([^']+)'", reason)
    if match is None:
        return None
    return match.group(1).strip().lower() or None


def _is_reauth_fallback_error(reason: str | None) -> bool:
    """Return True when refresh failure should trigger one-time primary grant fallback."""
    error_code = _extract_oauth_error_code_from_reason(reason)
    return error_code in {"invalid_grant", "invalid_token"}


def _parse_form_encoded_payload(payload_text: str) -> dict[str, Any] | None:
    """Parse form-encoded OAuth payloads as fallback when JSON decoding fails."""
    parsed = parse_qs(payload_text, keep_blank_values=True)
    if not parsed:
        return None
    return {key: _first_query_value(values) for key, values in parsed.items()}


def _optional_non_empty_text(value: Any) -> str | None:
    """Normalize optional textual OAuth payload fields."""
    if not isinstance(value, str):
        return None
    stripped_value = value.strip()
    return stripped_value if stripped_value else None


def _coerce_poll_interval_seconds(value: Any, default: int) -> int:
    """Parse polling interval as positive integer seconds."""
    if isinstance(value, (int, float)):
        parsed = int(value)
    elif isinstance(value, str):
        try:
            parsed = int(float(value.strip()))
        except ValueError:
            return default
    else:
        return default
    return parsed if parsed > 0 else default


def _sleep_until_deadline(interval_seconds: int, deadline: float) -> None:
    """Sleep up to the configured polling interval without exceeding deadline."""
    remaining_seconds = deadline - _oauth_now()
    if remaining_seconds <= 0:
        return
    _oauth_sleep(min(float(interval_seconds), remaining_seconds))


def _emit_oauth_device_code_instructions(
    server_name: str,
    verification_uri: str | None,
    verification_uri_complete: str | None,
    user_code: str | None,
) -> None:
    """Print copy/paste instructions for OAuth device-code flow."""
    click.echo(f"[oauth] Complete verification for server '{server_name}'.", err=True)
    if verification_uri_complete is not None:
        click.echo(f"[oauth] Open: {verification_uri_complete}", err=True)
    elif verification_uri is not None:
        click.echo(f"[oauth] Open: {verification_uri}", err=True)
    if user_code is not None:
        click.echo(f"[oauth] Enter code: {user_code}", err=True)


def _emit_oauth_auth_code_pkce_instructions(server_name: str, authorization_request_url: str) -> None:
    """Print copy/paste instructions for OAuth auth-code PKCE flow."""
    click.echo(f"[oauth] Complete authorization for server '{server_name}'.", err=True)
    click.echo(f"[oauth] Open: {authorization_request_url}", err=True)
    click.echo("[oauth] Waiting for local callback...", err=True)


def _request_oauth_client_credentials_token(
    token_url: str,
    client_id: str,
    client_secret: str | None,
    scope: str | None,
    audience: str | None,
    token_endpoint_auth_method: str,
    timeout_seconds: int,
    client_assertion_signer: OAuthPrivateKeyJWTSigner | None = None,
    mtls_config: OAuthMTLSConfig | None = None,
) -> tuple[str | None, float | None, str | None, int | None, str | None]:
    """Request OAuth client-credentials token with x-www-form-urlencoded payload."""
    request_data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
    }
    if scope is not None:
        request_data["scope"] = scope
    if audience is not None:
        request_data["audience"] = audience

    payload, request_error, http_status = _request_oauth_form_payload(
        endpoint_url=token_url,
        request_data=request_data,
        timeout_seconds=timeout_seconds,
        endpoint_name="Token endpoint",
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint_auth_method=token_endpoint_auth_method,
        client_assertion_signer=client_assertion_signer,
        mtls_config=mtls_config,
    )
    if request_error is not None:
        return None, None, request_error, http_status, None
    assert payload is not None

    if http_status is not None and http_status >= 400:
        return None, None, _extract_oauth_error_reason(payload, http_status), http_status, None

    token_value = _optional_non_empty_text(payload.get("access_token"))
    if token_value is None:
        return None, None, "Token endpoint response is missing a non-empty access_token.", http_status, None

    expires_in = _coerce_expires_in_value(payload.get("expires_in"))
    token_type = _normalize_oauth_scheme(_optional_non_empty_text(payload.get("token_type")))
    return token_value, expires_in, None, http_status, token_type


def _coerce_expires_in_value(value: Any) -> float | None:
    """Parse optional expires_in as seconds; invalid values disable TTL caching."""
    if value is None:
        return None

    seconds: float
    if isinstance(value, (int, float)):
        seconds = float(value)
    elif isinstance(value, str):
        try:
            seconds = float(value.strip())
        except ValueError:
            return None
    else:
        return None

    if seconds < 0:
        return 0.0
    return seconds


def _oauth_now() -> float:
    """Clock source for OAuth cache expiry checks."""
    return time.monotonic()


def _oauth_sleep(seconds: float) -> None:
    """Sleep function wrapper for OAuth polling to aid deterministic testing."""
    time.sleep(seconds)


def _is_interactive_tty() -> bool:
    """Return True when both stdin and stderr are interactive TTYs."""
    stdin_is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
    stderr_is_tty = bool(getattr(sys.stderr, "isatty", lambda: False)())
    return stdin_is_tty and stderr_is_tty


def _build_oauth_cache_key(
    token_url: str,
    client_id: str,
    scope: str | None,
    audience: str | None,
    namespace: str = "default",
) -> str:
    """Build deterministic cache key for OAuth token reuse."""
    normalized_namespace = namespace.strip() or "default"
    return "\x1f".join([normalized_namespace, token_url, client_id, scope or "", audience or ""])


def _hydrate_oauth_cache_from_persistent(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Hydrate in-memory token cache from encrypted disk cache when enabled."""
    if not cache_settings.persistent:
        return
    if cache_key in _OAUTH_TOKEN_CACHE:
        return

    persistent_entries = _load_oauth_persistent_cache_entries(cache_settings=cache_settings)
    cached_entry = persistent_entries.get(cache_key)
    if not isinstance(cached_entry, dict):
        return
    _OAUTH_TOKEN_CACHE[cache_key] = dict(cached_entry)


def _resolve_oauth_remote_persistent_cache_loader(
    backend: str,
) -> Callable[..., dict[str, dict[str, Any]]] | None:
    """Resolve remote persistent-cache loader handler for backend."""
    function_name = _OAUTH_REMOTE_PERSISTENT_CACHE_LOADERS.get(backend)
    if function_name is None:
        return None
    resolved = globals().get(function_name)
    if not callable(resolved):
        return None
    return cast(Callable[..., dict[str, dict[str, Any]]], resolved)


def _resolve_oauth_remote_persistent_cache_persister(backend: str) -> Callable[..., None] | None:
    """Resolve remote persistent-cache persister handler for backend."""
    function_name = _OAUTH_REMOTE_PERSISTENT_CACHE_PERSISTERS.get(backend)
    if function_name is None:
        return None
    resolved = globals().get(function_name)
    if not callable(resolved):
        return None
    return cast(Callable[..., None], resolved)


def _load_oauth_persistent_cache_entries(
    cache_settings: OAuthCacheSettings | None = None,
) -> dict[str, dict[str, Any]]:
    """Load persistent OAuth cache entries from configured backend; returns empty map on failure/bypass."""
    resolved_settings = cache_settings or OAuthCacheSettings()
    loader = _resolve_oauth_remote_persistent_cache_loader(resolved_settings.backend)
    if loader is not None:
        try:
            return loader(cache_settings=resolved_settings)
        except Exception:
            return {}
    try:
        return _load_oauth_persistent_cache_entries_local()
    except Exception:
        return {}


def _load_oauth_persistent_cache_entries_local() -> dict[str, dict[str, Any]]:
    """Read encrypted local OAuth cache; returns empty map on any failure/bypass."""
    lock_handle, _ = _acquire_oauth_cache_lock()
    if lock_handle is None:
        return {}
    try:
        key_set = _resolve_oauth_cache_key_set(create_if_missing=True)
        if key_set is None:
            return {}
        entries, _ = _load_oauth_cache_entries_locked(
            key_set=key_set,
            recover_corrupt=True,
        )
        return entries
    finally:
        _release_oauth_cache_lock(lock_handle)


def _persist_oauth_cache_entry(cache_key: str, cache_settings: OAuthCacheSettings | None = None) -> None:
    """Persist one in-memory OAuth cache entry to configured persistent backend when possible."""
    resolved_settings = cache_settings or OAuthCacheSettings()
    persister = _resolve_oauth_remote_persistent_cache_persister(resolved_settings.backend)
    if persister is not None:
        try:
            persister(cache_key=cache_key, cache_settings=resolved_settings)
        except Exception:
            return
        return
    try:
        _persist_oauth_cache_entry_local(cache_key=cache_key)
    except Exception:
        return


def _persist_oauth_cache_entry_local(cache_key: str) -> None:
    """Persist one in-memory OAuth cache entry to encrypted local cache when possible."""
    lock_handle, _ = _acquire_oauth_cache_lock()
    if lock_handle is None:
        return
    try:
        key_set = _resolve_oauth_cache_key_set(create_if_missing=True)
        if key_set is None:
            return

        persistent_entries, _ = _load_oauth_cache_entries_locked(
            key_set=key_set,
            recover_corrupt=True,
        )
        in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
        if isinstance(in_memory_entry, dict):
            persistent_entries[cache_key] = dict(in_memory_entry)
        else:
            persistent_entries.pop(cache_key, None)

        _write_oauth_cache_entries_locked(key_set=key_set, entries=persistent_entries)
    finally:
        _release_oauth_cache_lock(lock_handle)


def _load_oauth_persistent_cache_entries_from_aws(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from AWS Secrets Manager; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_aws(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_aws(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to AWS Secrets Manager; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_aws(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_aws(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_aws_ssm(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from AWS SSM Parameter Store; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_aws_ssm(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_aws_ssm(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to AWS SSM Parameter Store; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_aws_ssm(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_aws_ssm(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_gcp(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from GCP Secret Manager; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_gcp(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_gcp(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to GCP Secret Manager; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_gcp(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_gcp(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_azure(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Azure Key Vault; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_azure(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_azure(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Azure Key Vault; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_azure(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_azure(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_vault(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from HashiCorp Vault; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_vault(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_vault(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to HashiCorp Vault; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_vault(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_vault(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_kubernetes(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Kubernetes Secret; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_kubernetes(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_kubernetes(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Kubernetes Secret; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_kubernetes(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_kubernetes(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_oci(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from OCI Vault secret; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_oci(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_oci(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to OCI Vault secret; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_oci(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_oci(cache_settings=cache_settings, entries=persistent_entries)


def _build_aws_secrets_manager_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create AWS Secrets Manager client for OAuth cache backend."""
    try:
        boto3_module = importlib.import_module("boto3")
    except Exception:
        return None

    client_kwargs: dict[str, Any] = {}
    if cache_settings.aws_region is not None:
        client_kwargs["region_name"] = cache_settings.aws_region
    if cache_settings.aws_endpoint_url is not None:
        client_kwargs["endpoint_url"] = cache_settings.aws_endpoint_url

    try:
        return boto3_module.client("secretsmanager", **client_kwargs)
    except Exception:
        return None


def _extract_aws_error_code(exc: Exception) -> str | None:
    """Extract AWS API error code when available."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return None
    error_payload = response.get("Error")
    if not isinstance(error_payload, dict):
        return None
    error_code = error_payload.get("Code")
    if not isinstance(error_code, str) or not error_code.strip():
        return None
    return error_code.strip()


def _read_oauth_cache_payload_from_aws(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from AWS Secrets Manager secret."""
    if cache_settings.aws_secret_id is None:
        return None

    client = _build_aws_secrets_manager_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        response = client.get_secret_value(SecretId=cache_settings.aws_secret_id)
    except Exception as exc:
        if _extract_aws_error_code(exc) in {"ResourceNotFoundException", "ResourceNotFound"}:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        return None

    secret_text = response.get("SecretString")
    if isinstance(secret_text, str) and secret_text.strip():
        raw_payload = secret_text
    else:
        secret_binary = response.get("SecretBinary")
        if isinstance(secret_binary, bytes):
            raw_payload = secret_binary.decode("utf-8", errors="ignore")
        elif isinstance(secret_binary, str):
            raw_payload = secret_binary
        else:
            return None

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_aws(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to AWS Secrets Manager."""
    if cache_settings.aws_secret_id is None:
        return False

    client = _build_aws_secrets_manager_client(cache_settings=cache_settings)
    if client is None:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    try:
        client.update_secret(SecretId=cache_settings.aws_secret_id, SecretString=serialized_payload)
        return True
    except Exception as exc:
        if _extract_aws_error_code(exc) not in {"ResourceNotFoundException", "ResourceNotFound"}:
            return False

    try:
        client.create_secret(Name=cache_settings.aws_secret_id, SecretString=serialized_payload)
    except Exception:
        return False
    return True


def _build_aws_ssm_parameter_store_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create AWS SSM Parameter Store client for OAuth cache backend."""
    try:
        boto3_module = importlib.import_module("boto3")
    except Exception:
        return None

    client_kwargs: dict[str, Any] = {}
    if cache_settings.aws_region is not None:
        client_kwargs["region_name"] = cache_settings.aws_region
    if cache_settings.aws_endpoint_url is not None:
        client_kwargs["endpoint_url"] = cache_settings.aws_endpoint_url

    try:
        return boto3_module.client("ssm", **client_kwargs)
    except Exception:
        return None


def _read_oauth_cache_payload_from_aws_ssm(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from AWS SSM Parameter Store SecureString parameter."""
    if cache_settings.aws_ssm_parameter_name is None:
        return None

    client = _build_aws_ssm_parameter_store_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        response = client.get_parameter(Name=cache_settings.aws_ssm_parameter_name, WithDecryption=True)
    except Exception as exc:
        if _extract_aws_error_code(exc) == "ParameterNotFound":
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        return None

    parameter = response.get("Parameter")
    if not isinstance(parameter, dict):
        return None
    parameter_value = parameter.get("Value")
    if not isinstance(parameter_value, str) or not parameter_value.strip():
        return None

    try:
        payload = json.loads(parameter_value)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_aws_ssm(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to AWS SSM Parameter Store SecureString parameter."""
    if cache_settings.aws_ssm_parameter_name is None:
        return False

    client = _build_aws_ssm_parameter_store_client(cache_settings=cache_settings)
    if client is None:
        return False

    # Pre-provisioned mode: require parameter to already exist.
    try:
        client.get_parameter(Name=cache_settings.aws_ssm_parameter_name, WithDecryption=True)
    except Exception:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    try:
        client.put_parameter(
            Name=cache_settings.aws_ssm_parameter_name,
            Value=serialized_payload,
            Type="SecureString",
            Overwrite=True,
        )
    except Exception:
        return False
    return True


def _build_gcp_secret_manager_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create GCP Secret Manager client for OAuth cache backend."""
    try:
        secretmanager_module = importlib.import_module("google.cloud.secretmanager")
    except Exception:
        return None

    client_kwargs: dict[str, Any] = {}
    if cache_settings.gcp_endpoint_url is not None:
        client_kwargs["client_options"] = {"api_endpoint": cache_settings.gcp_endpoint_url}

    try:
        return cast(Any, secretmanager_module).SecretManagerServiceClient(**client_kwargs)
    except Exception:
        return None


def _read_oauth_cache_payload_from_gcp(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from GCP Secret Manager secret."""
    if cache_settings.gcp_secret_name is None:
        return None

    client = _build_gcp_secret_manager_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        response = client.access_secret_version(request={"name": f"{cache_settings.gcp_secret_name}/versions/latest"})
    except Exception:
        return None

    payload_container = getattr(response, "payload", None)
    secret_data = getattr(payload_container, "data", None)
    if isinstance(secret_data, bytes):
        raw_payload = secret_data.decode("utf-8", errors="ignore")
    elif isinstance(secret_data, str):
        raw_payload = secret_data
    else:
        return None

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_gcp(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to GCP Secret Manager as a new secret version."""
    if cache_settings.gcp_secret_name is None:
        return False

    client = _build_gcp_secret_manager_client(cache_settings=cache_settings)
    if client is None:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

    try:
        client.add_secret_version(
            request={
                "parent": cache_settings.gcp_secret_name,
                "payload": {"data": serialized_payload},
            }
        )
    except Exception:
        return False
    return True


def _build_azure_key_vault_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create Azure Key Vault SecretClient for OAuth cache backend."""
    if cache_settings.azure_vault_url is None:
        return None

    try:
        identity_module = importlib.import_module("azure.identity")
        keyvault_module = importlib.import_module("azure.keyvault.secrets")
    except Exception:
        return None

    try:
        credential = cast(Any, identity_module).DefaultAzureCredential()
        return cast(Any, keyvault_module).SecretClient(
            vault_url=cache_settings.azure_vault_url,
            credential=credential,
        )
    except Exception:
        return None


def _read_oauth_cache_payload_from_azure(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from Azure Key Vault secret."""
    if cache_settings.azure_secret_name is None:
        return None

    client = _build_azure_key_vault_client(cache_settings=cache_settings)
    if client is None:
        return None

    version = cache_settings.azure_secret_version or "latest"
    try:
        secret_bundle = client.get_secret(name=cache_settings.azure_secret_name, version=version)
    except Exception:
        return None

    secret_value = getattr(secret_bundle, "value", None)
    if not isinstance(secret_value, str) or not secret_value.strip():
        return None

    try:
        payload = json.loads(secret_value)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_azure(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to Azure Key Vault secret."""
    if cache_settings.azure_secret_name is None:
        return False

    client = _build_azure_key_vault_client(cache_settings=cache_settings)
    if client is None:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    # Pre-provisioned mode: do not auto-create a missing secret.
    try:
        client.get_secret(name=cache_settings.azure_secret_name)
    except Exception:
        return False

    try:
        client.set_secret(name=cache_settings.azure_secret_name, value=serialized_payload)
    except Exception:
        return False
    return True


def _build_hashicorp_vault_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create HashiCorp Vault client for OAuth cache backend."""
    if cache_settings.vault_url is None:
        return None

    try:
        hvac_module = importlib.import_module("hvac")
    except Exception:
        return None

    token: str | None = None
    if cache_settings.vault_token_env is not None:
        token_value = os.getenv(cache_settings.vault_token_env, "").strip()
        token = token_value or None
    else:
        token = os.getenv("VAULT_TOKEN", "").strip() or None

    client_kwargs: dict[str, Any] = {"url": cache_settings.vault_url}
    if token is not None:
        client_kwargs["token"] = token
    if cache_settings.vault_namespace is not None:
        client_kwargs["namespace"] = cache_settings.vault_namespace

    try:
        return cast(Any, hvac_module).Client(**client_kwargs)
    except Exception:
        return None


def _read_oauth_cache_payload_from_vault(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from HashiCorp Vault KV v2 secret."""
    if cache_settings.vault_secret_path is None:
        return None

    client = _build_hashicorp_vault_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        response = client.secrets.kv.v2.read_secret_version(path=cache_settings.vault_secret_path)
    except Exception:
        return None

    if not isinstance(response, dict):
        return None
    response_data = response.get("data")
    if not isinstance(response_data, dict):
        return None
    secret_data = response_data.get("data")
    if not isinstance(secret_data, dict):
        return None
    raw_payload = secret_data.get("oauth_cache_envelope")
    if not isinstance(raw_payload, str) or not raw_payload.strip():
        return None

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_vault(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to HashiCorp Vault KV v2 secret."""
    if cache_settings.vault_secret_path is None:
        return False

    client = _build_hashicorp_vault_client(cache_settings=cache_settings)
    if client is None:
        return False

    # Pre-provisioned mode: require secret to already exist.
    try:
        client.secrets.kv.v2.read_secret_version(path=cache_settings.vault_secret_path)
    except Exception:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

    try:
        client.secrets.kv.v2.create_or_update_secret(
            path=cache_settings.vault_secret_path,
            secret={"oauth_cache_envelope": serialized_payload},
        )
    except Exception:
        return False
    return True


def _build_kubernetes_secret_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create Kubernetes CoreV1Api client for OAuth cache backend."""
    del cache_settings
    try:
        kubernetes_client_module = importlib.import_module("kubernetes.client")
        kubernetes_config_module = importlib.import_module("kubernetes.config")
    except Exception:
        return None

    load_incluster_config = getattr(kubernetes_config_module, "load_incluster_config", None)
    load_kube_config = getattr(kubernetes_config_module, "load_kube_config", None)
    if not callable(load_incluster_config) or not callable(load_kube_config):
        return None

    try:
        load_incluster_config()
    except Exception:
        try:
            load_kube_config()
        except Exception:
            return None

    try:
        return cast(Any, kubernetes_client_module).CoreV1Api()
    except Exception:
        return None


def _read_oauth_cache_payload_from_kubernetes(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from pre-provisioned Kubernetes Secret data key."""
    if cache_settings.k8s_secret_namespace is None or cache_settings.k8s_secret_name is None:
        return None
    secret_key = cache_settings.k8s_secret_key or "oauth_cache"

    client = _build_kubernetes_secret_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        secret = client.read_namespaced_secret(
            name=cache_settings.k8s_secret_name,
            namespace=cache_settings.k8s_secret_namespace,
        )
    except Exception:
        return None

    data = getattr(secret, "data", None)
    if not isinstance(data, dict):
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    encoded_payload = data.get(secret_key)
    if not isinstance(encoded_payload, str) or not encoded_payload.strip():
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    try:
        raw_payload = base64.b64decode(encoded_payload, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return None

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_kubernetes(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Kubernetes Secret data key."""
    if cache_settings.k8s_secret_namespace is None or cache_settings.k8s_secret_name is None:
        return False
    secret_key = cache_settings.k8s_secret_key or "oauth_cache"

    client = _build_kubernetes_secret_client(cache_settings=cache_settings)
    if client is None:
        return False

    # Pre-provisioned mode: require the Secret to already exist.
    try:
        secret = client.read_namespaced_secret(
            name=cache_settings.k8s_secret_name,
            namespace=cache_settings.k8s_secret_namespace,
        )
    except Exception:
        return False

    existing_data = getattr(secret, "data", None)
    merged_data = dict(existing_data) if isinstance(existing_data, dict) else {}

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    merged_data[secret_key] = base64.b64encode(serialized_payload).decode("ascii")

    try:
        client.patch_namespaced_secret(
            name=cache_settings.k8s_secret_name,
            namespace=cache_settings.k8s_secret_namespace,
            body={"data": merged_data},
        )
    except Exception:
        return False
    return True


def _resolve_oci_auth_context(
    cache_settings: OAuthCacheSettings, oci_module: Any
) -> tuple[dict[str, Any] | None, Any | None]:
    """Resolve OCI auth context by trying resource principal first, then config-file chain."""
    auth_module = getattr(oci_module, "auth", None)
    signers_module = getattr(auth_module, "signers", None)
    get_resource_principals_signer = getattr(signers_module, "get_resource_principals_signer", None)
    if callable(get_resource_principals_signer):
        try:
            signer = get_resource_principals_signer()
            config: dict[str, Any] = {}
            if cache_settings.oci_region is not None:
                config["region"] = cache_settings.oci_region
            return config, signer
        except Exception:
            pass

    config_module = getattr(oci_module, "config", None)
    from_file = getattr(config_module, "from_file", None)
    if not callable(from_file):
        return None, None

    from_file_kwargs: dict[str, str] = {}
    config_file = os.getenv("OCI_CONFIG_FILE", "").strip()
    if config_file:
        from_file_kwargs["file_location"] = config_file
    profile_name = os.getenv("OCI_CONFIG_PROFILE", "").strip()
    if profile_name:
        from_file_kwargs["profile_name"] = profile_name

    raw_config: Any
    try:
        raw_config = from_file(**from_file_kwargs)
    except Exception:
        return None, None
    if not isinstance(raw_config, dict):
        return None, None

    resolved_config = dict(raw_config)
    if cache_settings.oci_region is not None:
        resolved_config["region"] = cache_settings.oci_region
    return resolved_config, None


def _build_oci_secrets_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create OCI SecretsClient for OAuth cache backend."""
    try:
        oci_module = importlib.import_module("oci")
    except Exception:
        return None

    config, signer = _resolve_oci_auth_context(cache_settings=cache_settings, oci_module=oci_module)
    if config is None and signer is None:
        return None

    secrets_module = getattr(oci_module, "secrets", None)
    secrets_client_cls = getattr(secrets_module, "SecretsClient", None)
    if secrets_client_cls is None:
        return None

    client_kwargs: dict[str, Any] = {}
    if signer is not None:
        client_kwargs["signer"] = signer
    if cache_settings.oci_endpoint_url is not None:
        client_kwargs["service_endpoint"] = cache_settings.oci_endpoint_url

    try:
        return secrets_client_cls(config or {}, **client_kwargs)
    except Exception:
        return None


def _build_oci_vault_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create OCI VaultsClient for OAuth cache backend."""
    try:
        oci_module = importlib.import_module("oci")
    except Exception:
        return None

    config, signer = _resolve_oci_auth_context(cache_settings=cache_settings, oci_module=oci_module)
    if config is None and signer is None:
        return None

    vault_module = getattr(oci_module, "vault", None)
    vaults_client_cls = getattr(vault_module, "VaultsClient", None)
    if vaults_client_cls is None:
        return None

    client_kwargs: dict[str, Any] = {}
    if signer is not None:
        client_kwargs["signer"] = signer
    if cache_settings.oci_endpoint_url is not None:
        client_kwargs["service_endpoint"] = cache_settings.oci_endpoint_url

    try:
        return vaults_client_cls(config or {}, **client_kwargs)
    except Exception:
        return None


def _read_oauth_cache_payload_from_oci(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from OCI Vault secret bundle."""
    if cache_settings.oci_secret_ocid is None:
        return None

    client = _build_oci_secrets_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        response = client.get_secret_bundle(secret_id=cache_settings.oci_secret_ocid)
    except Exception:
        return None

    bundle_data = getattr(response, "data", None)
    secret_bundle_content = getattr(bundle_data, "secret_bundle_content", None)
    encoded_payload = getattr(secret_bundle_content, "content", None)
    if not isinstance(encoded_payload, str) or not encoded_payload.strip():
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    try:
        raw_payload = base64.b64decode(encoded_payload, validate=True).decode("utf-8", errors="ignore")
    except Exception:
        return None

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_oci(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to OCI Vault secret as a new secret version."""
    if cache_settings.oci_secret_ocid is None:
        return False

    vault_client = _build_oci_vault_client(cache_settings=cache_settings)
    if vault_client is None:
        return False

    try:
        oci_module = importlib.import_module("oci")
    except Exception:
        return False

    # Pre-provisioned mode: require secret to already exist.
    try:
        vault_client.get_secret(secret_id=cache_settings.oci_secret_ocid)
    except Exception:
        return False

    vault_models = getattr(getattr(oci_module, "vault", None), "models", None)
    base64_content_cls = getattr(vault_models, "Base64SecretContentDetails", None)
    update_secret_details_cls = getattr(vault_models, "UpdateSecretDetails", None)
    if base64_content_cls is None or update_secret_details_cls is None:
        return False

    payload = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    encoded_payload = base64.b64encode(serialized_payload).decode("ascii")

    try:
        secret_content = base64_content_cls(content_type="BASE64", content=encoded_payload)
        update_secret_details = update_secret_details_cls(secret_content=secret_content)
        vault_client.update_secret(
            secret_id=cache_settings.oci_secret_ocid,
            update_secret_details=update_secret_details,
        )
    except Exception:
        return False
    return True


def _load_oauth_persistent_cache_entries_from_doppler(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Doppler secret value; bypass on any provider error."""
    payload = _read_oauth_cache_payload_from_doppler(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_doppler(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Doppler secret value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_doppler(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_doppler(cache_settings=cache_settings, entries=persistent_entries)


def _build_doppler_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Doppler API client for OAuth cache backend."""
    token_env_name = cache_settings.doppler_token_env or "DOPPLER_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.doppler_api_url or _DOPPLER_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _read_doppler_secrets_map(client: httpx.Client, cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read Doppler config secrets as key-value map."""
    if cache_settings.doppler_project is None or cache_settings.doppler_config is None:
        return None

    try:
        response = client.get(
            "/v3/configs/config/secrets/download",
            params={
                "project": cache_settings.doppler_project,
                "config": cache_settings.doppler_config,
                "format": "json",
            },
        )
    except Exception:
        return None

    if response.status_code == 404:
        return {}
    try:
        response.raise_for_status()
    except Exception:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _read_oauth_cache_payload_from_doppler(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from Doppler pre-provisioned secret value."""
    if (
        cache_settings.doppler_project is None
        or cache_settings.doppler_config is None
        or cache_settings.doppler_secret_name is None
    ):
        return None

    client = _build_doppler_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        secrets_map = _read_doppler_secrets_map(client=client, cache_settings=cache_settings)
    finally:
        client.close()

    if secrets_map is None:
        return None

    raw_payload = secrets_map.get(cache_settings.doppler_secret_name)
    if not isinstance(raw_payload, str) or not raw_payload.strip():
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_doppler(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Doppler secret value."""
    if (
        cache_settings.doppler_project is None
        or cache_settings.doppler_config is None
        or cache_settings.doppler_secret_name is None
    ):
        return False

    client = _build_doppler_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        secrets_map = _read_doppler_secrets_map(client=client, cache_settings=cache_settings)
        if secrets_map is None:
            return False

        # Pre-provisioned mode: require secret key to already exist.
        if cache_settings.doppler_secret_name not in secrets_map:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.post(
                "/v3/configs/config/secrets",
                json={
                    "project": cache_settings.doppler_project,
                    "config": cache_settings.doppler_config,
                    "secrets": {cache_settings.doppler_secret_name: serialized_payload},
                },
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_onepassword_connect(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from 1Password Connect item field; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_onepassword_connect(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_onepassword_connect(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to 1Password Connect item field; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_onepassword_connect(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_onepassword_connect(cache_settings=cache_settings, entries=persistent_entries)


def _build_onepassword_connect_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create 1Password Connect API client for OAuth cache backend."""
    token_env_name = cache_settings.op_connect_token_env or "OP_CONNECT_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    host_url = (cache_settings.op_connect_host or "").strip().rstrip("/")
    if not host_url:
        return None

    try:
        return httpx.Client(
            base_url=host_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _read_onepassword_connect_item(client: httpx.Client, cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read a single pre-provisioned 1Password Connect item from configured vault/item IDs."""
    if cache_settings.op_vault_id is None or cache_settings.op_item_id is None:
        return None

    path = f"/v1/vaults/{cache_settings.op_vault_id}/items/{cache_settings.op_item_id}"
    try:
        response = client.get(path)
    except Exception:
        return None

    if response.status_code == 404:
        return {}
    try:
        response.raise_for_status()
    except Exception:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _read_oauth_cache_payload_from_onepassword_connect(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from 1Password Connect pre-provisioned item field."""
    if cache_settings.op_vault_id is None or cache_settings.op_item_id is None:
        return None
    field_label = cache_settings.op_field_label or "oauth_cache"

    client = _build_onepassword_connect_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        item_payload = _read_onepassword_connect_item(client=client, cache_settings=cache_settings)
    finally:
        client.close()

    if item_payload is None:
        return None
    if not item_payload:
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    fields = item_payload.get("fields")
    if not isinstance(fields, list):
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    field_value: str | None = None
    for raw_field in fields:
        if not isinstance(raw_field, dict):
            continue
        label_value = raw_field.get("label")
        id_value = raw_field.get("id")
        if label_value == field_label or id_value == field_label:
            value = raw_field.get("value")
            if isinstance(value, str) and value.strip():
                field_value = value
            break

    if field_value is None:
        return {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "entries": {},
        }

    try:
        payload = json.loads(field_value)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _write_oauth_cache_payload_to_onepassword_connect(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing 1Password Connect item field."""
    if cache_settings.op_vault_id is None or cache_settings.op_item_id is None:
        return False
    field_label = cache_settings.op_field_label or "oauth_cache"

    client = _build_onepassword_connect_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        item_payload = _read_onepassword_connect_item(client=client, cache_settings=cache_settings)
        if item_payload is None:
            return False

        # Pre-provisioned mode: require item and field to already exist.
        fields = item_payload.get("fields")
        if not item_payload or not isinstance(fields, list):
            return False

        target_index: int | None = None
        for index, raw_field in enumerate(fields):
            if not isinstance(raw_field, dict):
                continue
            label_value = raw_field.get("label")
            id_value = raw_field.get("id")
            if label_value == field_label or id_value == field_label:
                target_index = index
                break
        if target_index is None:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        updated_item_payload = dict(item_payload)
        updated_fields: list[dict[str, Any]] = []
        for raw_field in fields:
            if isinstance(raw_field, dict):
                updated_fields.append(dict(raw_field))
            else:
                updated_fields.append({})
        updated_fields[target_index]["value"] = serialized_payload
        updated_item_payload["fields"] = updated_fields

        path = f"/v1/vaults/{cache_settings.op_vault_id}/items/{cache_settings.op_item_id}"
        try:
            response = client.put(path, json=updated_item_payload)
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_bitwarden(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Bitwarden secret value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_bitwarden(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_bitwarden(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Bitwarden secret value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_bitwarden(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_bitwarden(cache_settings=cache_settings, entries=persistent_entries)


def _build_bitwarden_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Bitwarden API client for OAuth cache backend."""
    token_env_name = cache_settings.bw_access_token_env or "BWS_ACCESS_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.bw_api_url or _BITWARDEN_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _read_oauth_cache_payload_from_bitwarden(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from Bitwarden pre-provisioned secret value."""
    if cache_settings.bw_secret_id is None:
        return None

    client = _build_bitwarden_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    path = f"/public/secrets/{cache_settings.bw_secret_id}"
    try:
        try:
            response = client.get(path)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("data")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_bitwarden(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Bitwarden secret value."""
    if cache_settings.bw_secret_id is None:
        return False

    client = _build_bitwarden_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    path = f"/public/secrets/{cache_settings.bw_secret_id}"
    try:
        # Pre-provisioned mode: require secret to already exist.
        try:
            preflight_response = client.get(path)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.put(path, json={"value": serialized_payload})
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_infisical(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Infisical secret value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_infisical(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_infisical(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Infisical secret value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_infisical(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_infisical(cache_settings=cache_settings, entries=persistent_entries)


def _build_infisical_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Infisical API client for OAuth cache backend."""
    token_env_name = cache_settings.infisical_token_env or "INFISICAL_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.infisical_api_url or _INFISICAL_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _read_oauth_cache_payload_from_infisical(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from Infisical pre-provisioned secret value."""
    if (
        cache_settings.infisical_project_id is None
        or cache_settings.infisical_environment is None
        or cache_settings.infisical_secret_name is None
    ):
        return None

    client = _build_infisical_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    path = f"/v3/secrets/raw/{cache_settings.infisical_secret_name}"
    params = {
        "workspaceId": cache_settings.infisical_project_id,
        "environment": cache_settings.infisical_environment,
    }

    try:
        try:
            response = client.get(path, params=params)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("secretValue")
        if not isinstance(raw_payload, str):
            raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            secret_payload = payload.get("secret")
            if isinstance(secret_payload, dict):
                raw_payload = secret_payload.get("secretValue")
                if not isinstance(raw_payload, str):
                    raw_payload = secret_payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("data")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("secretValue")
                if not isinstance(raw_payload, str):
                    raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_infisical(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Infisical secret value."""
    if (
        cache_settings.infisical_project_id is None
        or cache_settings.infisical_environment is None
        or cache_settings.infisical_secret_name is None
    ):
        return False

    client = _build_infisical_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    read_path = f"/v3/secrets/raw/{cache_settings.infisical_secret_name}"
    params = {
        "workspaceId": cache_settings.infisical_project_id,
        "environment": cache_settings.infisical_environment,
    }
    write_path = f"/v3/secrets/{cache_settings.infisical_secret_name}"

    try:
        # Pre-provisioned mode: require secret to already exist.
        try:
            preflight_response = client.get(read_path, params=params)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.post(
                write_path,
                json={
                    "workspaceId": cache_settings.infisical_project_id,
                    "environment": cache_settings.infisical_environment,
                    "secretValue": serialized_payload,
                },
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_akeyless(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Akeyless secret value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_akeyless(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_akeyless(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Akeyless secret value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_akeyless(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_akeyless(cache_settings=cache_settings, entries=persistent_entries)


def _build_akeyless_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Akeyless API client for OAuth cache backend."""
    token_env_name = cache_settings.akeyless_token_env or "AKEYLESS_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.akeyless_api_url or _AKEYLESS_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
    except Exception:
        return None


def _read_oauth_cache_payload_from_akeyless(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from Akeyless pre-provisioned secret value."""
    if cache_settings.akeyless_secret_name is None:
        return None

    client = _build_akeyless_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    path = "/api/v2/get-secret-value"
    try:
        try:
            response = client.post(path, json={"name": cache_settings.akeyless_secret_name})
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        raw_payload: Any = None
        if isinstance(payload, str):
            raw_payload = payload
        elif isinstance(payload, dict):
            raw_payload = payload.get("value")
            if not isinstance(raw_payload, str):
                raw_payload = payload.get("secretValue")
            if not isinstance(raw_payload, str):
                raw_payload = payload.get("secret_value")
            if not isinstance(raw_payload, str):
                data_payload = payload.get("data")
                if isinstance(data_payload, dict):
                    raw_payload = data_payload.get("value")
        else:
            return None

        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_akeyless(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Akeyless secret value."""
    if cache_settings.akeyless_secret_name is None:
        return False

    client = _build_akeyless_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    read_path = "/api/v2/get-secret-value"
    write_path = "/api/v2/set-secret-value"
    try:
        # Pre-provisioned mode: require secret to already exist.
        try:
            preflight_response = client.post(read_path, json={"name": cache_settings.akeyless_secret_name})
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.post(
                write_path,
                json={
                    "name": cache_settings.akeyless_secret_name,
                    "value": serialized_payload,
                },
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_gitlab(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from GitLab CI variable value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_gitlab(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_gitlab(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to GitLab CI variable value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_gitlab(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_gitlab(cache_settings=cache_settings, entries=persistent_entries)


def _build_gitlab_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create GitLab API client for OAuth cache backend."""
    token_env_name = cache_settings.gitlab_token_env or "GITLAB_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.gitlab_api_url or _GITLAB_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "PRIVATE-TOKEN": token_value,
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _build_gitlab_variable_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build GitLab variable API path from validated cache settings."""
    capability = _GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES.get(cache_settings.backend)
    if capability is None or cache_settings.gitlab_variable_key is None:
        return None

    key_segment = quote(cache_settings.gitlab_variable_key, safe="")
    if capability.identifier_field is None:
        return f"{capability.path_prefix}/variables/{key_segment}"

    identifier_value = getattr(cache_settings, capability.identifier_field)
    if not isinstance(identifier_value, str) or not identifier_value.strip():
        return None
    return f"{capability.path_prefix}/{quote(identifier_value.strip(), safe='')}/variables/{key_segment}"


def _resolve_gitlab_environment_scope(
    cache_settings: OAuthCacheSettings, capability: GitLabOAuthCacheBackendCapability
) -> str | None:
    """Resolve GitLab environment scope only for backends that support scope filtering."""
    if not capability.supports_environment_scope:
        return None
    scope = (cache_settings.gitlab_environment_scope or "*").strip()
    return scope or None


def _build_gitlab_variable_query_params(cache_settings: OAuthCacheSettings) -> dict[str, str] | None:
    """Build query params for GitLab variable API access from validated cache settings."""
    capability = _GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES.get(cache_settings.backend)
    if capability is None:
        return None
    if not capability.supports_environment_scope:
        return {}
    scope = _resolve_gitlab_environment_scope(cache_settings=cache_settings, capability=capability)
    if scope is None:
        return None
    return {"filter[environment_scope]": scope}


def _read_oauth_cache_payload_from_gitlab(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from GitLab pre-provisioned CI variable value."""
    path = _build_gitlab_variable_path(cache_settings=cache_settings)
    if path is None:
        return None
    params = _build_gitlab_variable_query_params(cache_settings=cache_settings)
    if params is None:
        return None

    client = _build_gitlab_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path, params=params)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("variable")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_gitlab(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing GitLab CI variable value."""
    capability = _GITLAB_OAUTH_CACHE_BACKEND_CAPABILITIES.get(cache_settings.backend)
    if capability is None:
        return False
    path = _build_gitlab_variable_path(cache_settings=cache_settings)
    if path is None:
        return False
    params = _build_gitlab_variable_query_params(cache_settings=cache_settings)
    if params is None:
        return False

    client = _build_gitlab_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require variable to already exist.
        try:
            preflight_response = client.get(path, params=params)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        request_payload: dict[str, str] = {"value": serialized_payload}
        if capability.supports_environment_scope:
            environment_scope = _resolve_gitlab_environment_scope(cache_settings=cache_settings, capability=capability)
            if environment_scope is None:
                return False
            request_payload["environment_scope"] = environment_scope

        try:
            response = client.put(
                path,
                params=params,
                data=request_payload,
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_github(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from GitHub Actions variable value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_github(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_github(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to GitHub Actions variable value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_github(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_github(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_github_environment(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from GitHub environment variable value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_github_environment(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_github_environment(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to GitHub environment variable value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_github_environment(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_github_environment(cache_settings=cache_settings, entries=persistent_entries)


def _load_oauth_persistent_cache_entries_from_github_organization(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from GitHub organization variable value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_github_organization(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_github_organization(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to GitHub organization variable value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_github_organization(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_github_organization(cache_settings=cache_settings, entries=persistent_entries)


def _build_github_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create GitHub API client for OAuth cache backend."""
    token_env_name = cache_settings.github_token_env or "GITHUB_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.github_api_url or _GITHUB_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
    except Exception:
        return None


def _build_github_variable_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build GitHub Actions variable API path from validated cache settings."""
    if cache_settings.github_repository is None or cache_settings.github_variable_name is None:
        return None
    variable_name = quote(cache_settings.github_variable_name, safe="")
    return f"/repos/{cache_settings.github_repository}/actions/variables/{variable_name}"


def _build_github_environment_variable_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build GitHub environment variable API path from validated cache settings."""
    if (
        cache_settings.github_repository is None
        or cache_settings.github_environment_name is None
        or cache_settings.github_variable_name is None
    ):
        return None
    environment_name = quote(cache_settings.github_environment_name, safe="")
    variable_name = quote(cache_settings.github_variable_name, safe="")
    return f"/repos/{cache_settings.github_repository}/environments/{environment_name}/variables/{variable_name}"


def _build_github_organization_variable_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build GitHub organization variable API path from validated cache settings."""
    if cache_settings.github_organization is None or cache_settings.github_variable_name is None:
        return None
    organization = quote(cache_settings.github_organization, safe="")
    variable_name = quote(cache_settings.github_variable_name, safe="")
    return f"/orgs/{organization}/actions/variables/{variable_name}"


def _read_oauth_cache_payload_from_github(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from GitHub pre-provisioned Actions variable value."""
    path = _build_github_variable_path(cache_settings=cache_settings)
    if path is None:
        return None

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("variable")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_github(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing GitHub Actions variable value."""
    path = _build_github_variable_path(cache_settings=cache_settings)
    if path is None:
        return False

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require variable to already exist.
        try:
            preflight_response = client.get(path)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.patch(
                path,
                json={
                    "name": cache_settings.github_variable_name,
                    "value": serialized_payload,
                },
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _read_oauth_cache_payload_from_github_environment(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from GitHub pre-provisioned environment variable value."""
    path = _build_github_environment_variable_path(cache_settings=cache_settings)
    if path is None:
        return None

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("variable")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_github_environment(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing GitHub environment variable value."""
    path = _build_github_environment_variable_path(cache_settings=cache_settings)
    if path is None:
        return False

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require variable to already exist.
        try:
            preflight_response = client.get(path)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.patch(
                path,
                json={
                    "name": cache_settings.github_variable_name,
                    "value": serialized_payload,
                },
            )
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _read_oauth_cache_payload_from_github_organization(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from GitHub pre-provisioned organization variable value."""
    path = _build_github_organization_variable_path(cache_settings=cache_settings)
    if path is None:
        return None

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            payload = response.json()
        except ValueError:
            return None
        if not isinstance(payload, dict):
            return None

        raw_payload = payload.get("value")
        if not isinstance(raw_payload, str):
            data_payload = payload.get("variable")
            if isinstance(data_payload, dict):
                raw_payload = data_payload.get("value")
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_github_organization(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing GitHub organization variable value."""
    path = _build_github_organization_variable_path(cache_settings=cache_settings)
    if path is None:
        return False

    client = _build_github_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require variable to already exist.
        try:
            preflight_response = client.get(path)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False
        try:
            preflight_payload = preflight_response.json()
        except ValueError:
            return False
        if not isinstance(preflight_payload, dict):
            return False
        variable_payload = preflight_payload.get("variable")
        if isinstance(variable_payload, dict):
            preflight_payload = variable_payload

        visibility = preflight_payload.get("visibility")
        if not isinstance(visibility, str) or visibility not in {"all", "private", "selected"}:
            return False

        selected_repository_ids: list[int] | None = None
        if visibility == "selected":
            selected_repositories_url = preflight_payload.get("selected_repositories_url")
            if not isinstance(selected_repositories_url, str) or not selected_repositories_url.strip():
                return False

            try:
                selected_repositories_response = client.get(selected_repositories_url.strip())
            except Exception:
                return False
            if selected_repositories_response.status_code == 404:
                return False
            try:
                selected_repositories_response.raise_for_status()
            except Exception:
                return False

            try:
                selected_repositories_payload = selected_repositories_response.json()
            except ValueError:
                return False
            if not isinstance(selected_repositories_payload, dict):
                return False
            repositories_value = selected_repositories_payload.get("repositories")
            if not isinstance(repositories_value, list):
                return False

            selected_repository_ids = []
            for repository_entry in repositories_value:
                if not isinstance(repository_entry, dict):
                    return False
                repository_id = repository_entry.get("id")
                if not isinstance(repository_id, int):
                    return False
                selected_repository_ids.append(repository_id)

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        request_payload: dict[str, Any] = {
            "name": cache_settings.github_variable_name,
            "value": serialized_payload,
            "visibility": visibility,
        }
        if selected_repository_ids is not None:
            request_payload["selected_repository_ids"] = selected_repository_ids

        try:
            response = client.patch(path, json=request_payload)
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_consul(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Consul KV value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_consul(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_consul(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Consul KV value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_consul(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_consul(cache_settings=cache_settings, entries=persistent_entries)


def _build_consul_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Consul API client for OAuth cache backend."""
    token_env_name = cache_settings.consul_token_env or "CONSUL_HTTP_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.consul_api_url or _CONSUL_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "X-Consul-Token": token_value,
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _build_consul_kv_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build Consul KV API path from validated cache settings."""
    if cache_settings.consul_key_path is None:
        return None
    normalized_key = cache_settings.consul_key_path.strip().strip("/")
    if not normalized_key:
        return None
    encoded_key = quote(normalized_key, safe="/")
    return f"/v1/kv/{encoded_key}"


def _read_oauth_cache_payload_from_consul(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from pre-provisioned Consul KV key value."""
    path = _build_consul_kv_path(cache_settings=cache_settings)
    if path is None:
        return None

    client = _build_consul_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path, params={"raw": "true"})
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        raw_payload = response.text
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_consul(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Consul KV key value."""
    path = _build_consul_kv_path(cache_settings=cache_settings)
    if path is None:
        return False

    client = _build_consul_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require key to already exist.
        try:
            preflight_response = client.get(path, params={"raw": "true"})
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.put(path, content=serialized_payload)
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_redis(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Redis key value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_redis(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_redis(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Redis key value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_redis(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_redis(cache_settings=cache_settings, entries=persistent_entries)


def _build_redis_client(cache_settings: OAuthCacheSettings) -> Any | None:
    """Create Redis client for OAuth cache backend."""
    try:
        redis_module = importlib.import_module("redis")
    except Exception:
        return None

    redis_url = (cache_settings.redis_url or _REDIS_DEFAULT_URL).strip()
    if not redis_url:
        return None

    token_env_name = cache_settings.redis_password_env or "REDIS_PASSWORD"
    password_value = os.getenv(token_env_name, "").strip()
    password = password_value if password_value else None

    try:
        redis_client_cls = getattr(redis_module, "Redis", None)
        if redis_client_cls is None:
            return None
        return redis_client_cls.from_url(
            redis_url,
            password=password,
            socket_timeout=10.0,
            socket_connect_timeout=10.0,
            decode_responses=False,
        )
    except Exception:
        return None


def _build_redis_key(cache_settings: OAuthCacheSettings) -> str | None:
    """Build Redis key name from validated cache settings."""
    if cache_settings.redis_key is None:
        return None
    normalized_key = cache_settings.redis_key.strip().strip("/")
    if not normalized_key:
        return None
    return normalized_key


def _close_redis_client(client: Any) -> None:
    """Close Redis client safely when close method exists."""
    close_method = getattr(client, "close", None)
    if callable(close_method):
        try:
            close_method()
        except Exception:
            pass


def _read_oauth_cache_payload_from_redis(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from pre-provisioned Redis key value."""
    key_name = _build_redis_key(cache_settings=cache_settings)
    if key_name is None:
        return None

    client = _build_redis_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            raw_payload = client.get(key_name)
        except Exception:
            return None

        if raw_payload is None:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        if isinstance(raw_payload, bytes):
            payload_text = raw_payload.decode("utf-8", errors="ignore")
        elif isinstance(raw_payload, str):
            payload_text = raw_payload
        else:
            return None

        if not payload_text.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(payload_text)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        _close_redis_client(client)


def _write_oauth_cache_payload_to_redis(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to existing Redis key value."""
    key_name = _build_redis_key(cache_settings=cache_settings)
    if key_name is None:
        return False

    client = _build_redis_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require key to already exist.
        try:
            preflight_value = client.get(key_name)
        except Exception:
            return False
        if preflight_value is None:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            write_result = client.set(key_name, serialized_payload)
        except Exception:
            return False
        if not bool(write_result):
            return False
        return True
    finally:
        _close_redis_client(client)


def _load_oauth_persistent_cache_entries_from_cloudflare(
    cache_settings: OAuthCacheSettings,
) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from Cloudflare KV value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_cloudflare(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_cloudflare(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to Cloudflare KV value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_cloudflare(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_cloudflare(cache_settings=cache_settings, entries=persistent_entries)


def _build_cloudflare_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create Cloudflare API client for OAuth cache backend."""
    token_env_name = cache_settings.cf_api_token_env or "CLOUDFLARE_API_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    if not token_value:
        return None

    api_url = (cache_settings.cf_api_url or _CLOUDFLARE_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers={
                "Authorization": f"Bearer {token_value}",
                "Accept": "application/json",
            },
        )
    except Exception:
        return None


def _build_cloudflare_kv_path(cache_settings: OAuthCacheSettings) -> str | None:
    """Build Cloudflare KV value endpoint path from validated cache settings."""
    if (
        cache_settings.cf_account_id is None
        or cache_settings.cf_namespace_id is None
        or cache_settings.cf_kv_key is None
    ):
        return None
    account_id = cache_settings.cf_account_id.strip()
    namespace_id = cache_settings.cf_namespace_id.strip()
    kv_key = cache_settings.cf_kv_key.strip()
    if not account_id or not namespace_id or not kv_key:
        return None

    encoded_account = quote(account_id, safe="")
    encoded_namespace = quote(namespace_id, safe="")
    encoded_key = quote(kv_key, safe="")
    return f"/accounts/{encoded_account}/storage/kv/namespaces/{encoded_namespace}/values/{encoded_key}"


def _read_oauth_cache_payload_from_cloudflare(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from pre-provisioned Cloudflare KV key value."""
    path = _build_cloudflare_kv_path(cache_settings=cache_settings)
    if path is None:
        return None

    client = _build_cloudflare_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    try:
        try:
            response = client.get(path)
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            response.raise_for_status()
        except Exception:
            return None

        raw_payload = response.text
        if not isinstance(raw_payload, str) or not raw_payload.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(raw_payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_cloudflare(
    cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]
) -> bool:
    """Write OAuth cache payload envelope to existing Cloudflare KV key value."""
    path = _build_cloudflare_kv_path(cache_settings=cache_settings)
    if path is None:
        return False

    client = _build_cloudflare_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    try:
        # Pre-provisioned mode: require key to already exist.
        try:
            preflight_response = client.get(path)
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)

        try:
            response = client.put(path, content=serialized_payload, headers={"content-type": "application/json"})
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _load_oauth_persistent_cache_entries_from_etcd(cache_settings: OAuthCacheSettings) -> dict[str, dict[str, Any]]:
    """Read persistent OAuth cache entries from etcd v3 KV value; bypass on provider errors."""
    payload = _read_oauth_cache_payload_from_etcd(cache_settings=cache_settings)
    if payload is None:
        return {}
    entries, _ = _parse_oauth_cache_entries_from_payload(payload)
    return entries


def _persist_oauth_cache_entry_etcd(cache_key: str, cache_settings: OAuthCacheSettings) -> None:
    """Persist one in-memory OAuth cache entry to etcd v3 KV value; bypass on provider errors."""
    persistent_entries = _load_oauth_persistent_cache_entries_from_etcd(cache_settings=cache_settings)
    in_memory_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if isinstance(in_memory_entry, dict):
        persistent_entries[cache_key] = dict(in_memory_entry)
    else:
        persistent_entries.pop(cache_key, None)

    _write_oauth_cache_payload_to_etcd(cache_settings=cache_settings, entries=persistent_entries)


def _build_etcd_http_client(cache_settings: OAuthCacheSettings) -> httpx.Client | None:
    """Create etcd v3 JSON API client for OAuth cache backend."""
    api_url = (cache_settings.etcd_api_url or _ETCD_DEFAULT_API_URL).strip().rstrip("/")
    if not api_url:
        return None

    token_env_name = cache_settings.etcd_token_env or "ETCD_TOKEN"
    token_value = os.getenv(token_env_name, "").strip()
    headers: dict[str, str] = {
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if token_value:
        headers["Authorization"] = f"Bearer {token_value}"

    try:
        return httpx.Client(
            base_url=api_url,
            timeout=10.0,
            headers=headers,
        )
    except Exception:
        return None


def _build_etcd_kv_key(cache_settings: OAuthCacheSettings) -> str | None:
    """Build etcd key from validated cache settings."""
    if cache_settings.etcd_key is None:
        return None
    normalized_key = cache_settings.etcd_key.strip().strip("/")
    if not normalized_key:
        return None
    return normalized_key


def _read_oauth_cache_payload_from_etcd(cache_settings: OAuthCacheSettings) -> dict[str, Any] | None:
    """Read OAuth cache payload envelope from pre-provisioned etcd v3 key value."""
    key_name = _build_etcd_kv_key(cache_settings=cache_settings)
    if key_name is None:
        return None

    client = _build_etcd_http_client(cache_settings=cache_settings)
    if client is None:
        return None

    encoded_key = base64.b64encode(key_name.encode("utf-8")).decode("utf-8")
    try:
        try:
            response = client.post("/v3/kv/range", json={"key": encoded_key})
        except Exception:
            return None

        if response.status_code == 404:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        try:
            response.raise_for_status()
        except Exception:
            return None

        try:
            response_body = response.json()
        except Exception:
            return None
        if not isinstance(response_body, dict):
            return None

        kvs_value = response_body.get("kvs")
        if not isinstance(kvs_value, list) or not kvs_value:
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }
        first_kv = kvs_value[0]
        if not isinstance(first_kv, dict):
            return None
        encoded_payload_value = first_kv.get("value")
        if not isinstance(encoded_payload_value, str) or not encoded_payload_value.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            payload_text = base64.b64decode(encoded_payload_value.encode("utf-8")).decode("utf-8")
        except Exception:
            return None
        if not payload_text.strip():
            return {
                "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
                "entries": {},
            }

        try:
            envelope = json.loads(payload_text)
        except json.JSONDecodeError:
            return None
        if not isinstance(envelope, dict):
            return None
        return envelope
    finally:
        client.close()


def _write_oauth_cache_payload_to_etcd(cache_settings: OAuthCacheSettings, entries: dict[str, dict[str, Any]]) -> bool:
    """Write OAuth cache payload envelope to existing etcd v3 key value."""
    key_name = _build_etcd_kv_key(cache_settings=cache_settings)
    if key_name is None:
        return False

    client = _build_etcd_http_client(cache_settings=cache_settings)
    if client is None:
        return False

    encoded_key = base64.b64encode(key_name.encode("utf-8")).decode("utf-8")
    try:
        # Pre-provisioned mode: require key to already exist.
        try:
            preflight_response = client.post("/v3/kv/range", json={"key": encoded_key})
        except Exception:
            return False
        if preflight_response.status_code == 404:
            return False
        try:
            preflight_response.raise_for_status()
        except Exception:
            return False
        try:
            preflight_body = preflight_response.json()
        except Exception:
            return False
        if not isinstance(preflight_body, dict):
            return False
        preflight_kvs = preflight_body.get("kvs")
        if not isinstance(preflight_kvs, list) or not preflight_kvs:
            return False

        payload = {
            "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "entries": entries,
        }
        serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        encoded_payload = base64.b64encode(serialized_payload.encode("utf-8")).decode("utf-8")

        try:
            response = client.post("/v3/kv/put", json={"key": encoded_key, "value": encoded_payload})
        except Exception:
            return False
        if response.status_code == 404:
            return False
        try:
            response.raise_for_status()
        except Exception:
            return False
        return True
    finally:
        client.close()


def _rotate_oauth_persistent_cache_key() -> dict[str, Any]:
    """Rotate persistent OAuth cache encryption key and re-encrypt existing entries."""
    lock_handle, lock_error = _acquire_oauth_cache_lock()
    if lock_handle is None:
        raise RuntimeError(lock_error or "Unable to acquire OAuth cache lock.")
    try:
        current_key_set = _resolve_oauth_cache_key_set(create_if_missing=False)
        if _OAUTH_PERSISTENT_CACHE_FILE.exists():
            if current_key_set is None:
                raise RuntimeError("OAuth cache exists but cache key could not be resolved.")
            current_entries, load_error = _load_oauth_cache_entries_locked(
                key_set=current_key_set,
                recover_corrupt=False,
            )
            if load_error is not None:
                raise RuntimeError(load_error)
        else:
            current_entries = {}

        next_active_key = _generate_oauth_cache_key_material()
        next_historical_keys: list[OAuthCacheKeyMaterial] = []
        if current_key_set is not None:
            next_historical_keys.append(current_key_set.active)
            next_historical_keys.extend(current_key_set.historical)
        pruned_historical = _prune_oauth_historical_keys(next_historical_keys)

        next_key_set = OAuthCacheKeySet(
            active=next_active_key,
            historical=pruned_historical,
            source="generated",
        )
        stored_key_set = _store_oauth_cache_key_set(next_key_set)
        if stored_key_set is None:
            raise RuntimeError("Failed to store rotated cache key.")

        if not _write_oauth_cache_entries_locked(key_set=stored_key_set, entries=current_entries):
            raise RuntimeError("Failed to write encrypted cache payload with rotated key.")

        return {
            "source": stored_key_set.source,
            "key_id": stored_key_set.active.key_id,
            "entry_count": len(current_entries),
        }
    finally:
        _release_oauth_cache_lock(lock_handle)


def _load_oauth_cache_entries_locked(
    key_set: OAuthCacheKeySet | None = None,
    recover_corrupt: bool = False,
    key_material: OAuthCacheKeyMaterial | None = None,
) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Read and normalize encrypted cache entries while lock is held."""
    resolved_key_set = key_set
    if resolved_key_set is None and key_material is not None:
        resolved_key_set = OAuthCacheKeySet(
            active=key_material,
            historical=(),
            source=key_material.source,
        )
    if resolved_key_set is None:
        return {}, "OAuth cache key set is required."

    try:
        encrypted_payload = _OAUTH_PERSISTENT_CACHE_FILE.read_bytes()
    except FileNotFoundError:
        return {}, None
    except OSError:
        return {}, "Unable to read OAuth cache file."

    _ensure_file_mode(_OAUTH_PERSISTENT_CACHE_FILE, mode=0o600)
    payload = _decrypt_oauth_cache_payload_with_key_set(
        encrypted_payload=encrypted_payload,
        key_set=resolved_key_set,
    )
    if payload is None:
        if recover_corrupt:
            _quarantine_oauth_cache_file_locked()
            return {}, "OAuth cache payload is corrupt or undecryptable."
        return {}, "OAuth cache payload is corrupt or undecryptable."

    entries, parse_error = _parse_oauth_cache_entries_from_payload(payload)
    if parse_error is not None:
        if recover_corrupt:
            _quarantine_oauth_cache_file_locked()
            return {}, parse_error
        return {}, parse_error
    return entries, None


def _write_oauth_cache_entries_locked(key_set: OAuthCacheKeySet, entries: dict[str, dict[str, Any]]) -> bool:
    """Write encrypted cache entries while lock is held."""
    encrypted_payload = _encrypt_oauth_cache_payload(
        entries=entries,
        key_material=key_set.active,
    )
    if encrypted_payload is None:
        return False
    return _atomic_write_bytes(path=_OAUTH_PERSISTENT_CACHE_FILE, data=encrypted_payload, mode=0o600)


def _parse_oauth_cache_entries_from_payload(payload: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Parse cache payload entries from v1/v2 envelope shapes."""
    schema_version = payload.get("schema_version")
    if schema_version not in {_OAUTH_CACHE_SCHEMA_VERSION_V1, _OAUTH_CACHE_SCHEMA_VERSION_V2}:
        return {}, "OAuth cache payload schema_version is unsupported."

    entries_value = payload.get("entries")
    if not isinstance(entries_value, dict):
        return {}, "OAuth cache payload must include an object 'entries' field."

    normalized_entries: dict[str, dict[str, Any]] = {}
    for entry_key, entry_value in entries_value.items():
        if not isinstance(entry_key, str) or not isinstance(entry_value, dict):
            continue
        normalized_entries[entry_key] = dict(entry_value)
    return normalized_entries, None


def _resolve_oauth_cache_key_set(create_if_missing: bool) -> OAuthCacheKeySet | None:
    """Resolve cache key set from keyring first, then fallback key file."""
    key_set = _read_oauth_cache_key_set_from_keyring()
    if key_set is not None:
        return key_set

    key_set = _read_oauth_cache_key_set_from_file()
    if key_set is not None:
        return key_set

    if not create_if_missing:
        return None

    generated_key = _generate_oauth_cache_key_material()
    generated_key_set = OAuthCacheKeySet(active=generated_key, historical=(), source="generated")
    return _store_oauth_cache_key_set(generated_key_set)


def _store_oauth_cache_key_set(key_set: OAuthCacheKeySet) -> OAuthCacheKeySet | None:
    """Persist key set to preferred store and return resolved source."""
    sanitized_set = OAuthCacheKeySet(
        active=key_set.active,
        historical=_prune_oauth_historical_keys(list(key_set.historical)),
        source=key_set.source,
    )
    if _write_oauth_cache_key_set_to_keyring(sanitized_set):
        return OAuthCacheKeySet(
            active=sanitized_set.active,
            historical=sanitized_set.historical,
            source="keyring",
        )
    if _write_oauth_cache_key_set_to_file(sanitized_set):
        return OAuthCacheKeySet(
            active=sanitized_set.active,
            historical=sanitized_set.historical,
            source="file",
        )
    return None


def _read_oauth_cache_key_set_from_keyring() -> OAuthCacheKeySet | None:
    """Read cache key-set metadata from OS keyring."""
    try:
        keyring_module = cast(Any, importlib.import_module("keyring"))
    except Exception:
        return None

    try:
        raw_value = keyring_module.get_password(
            _OAUTH_PERSISTENT_KEYRING_SERVICE,
            _OAUTH_PERSISTENT_KEYRING_USERNAME,
        )
    except Exception:
        return None

    return _parse_oauth_cache_key_set(raw_value, source="keyring")


def _write_oauth_cache_key_set_to_keyring(key_set: OAuthCacheKeySet) -> bool:
    """Store cache key-set metadata in keyring when possible."""
    try:
        keyring_module = cast(Any, importlib.import_module("keyring"))
    except Exception:
        return False

    serialized_value = _serialize_oauth_cache_key_set(key_set)
    if serialized_value is None:
        return False

    try:
        keyring_module.set_password(
            _OAUTH_PERSISTENT_KEYRING_SERVICE,
            _OAUTH_PERSISTENT_KEYRING_USERNAME,
            serialized_value,
        )
    except Exception:
        return False
    return True


def _read_oauth_cache_key_set_from_file() -> OAuthCacheKeySet | None:
    """Read cache key-set metadata from fallback key file."""
    try:
        raw_value = _OAUTH_PERSISTENT_KEY_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError:
        return None

    _ensure_file_mode(_OAUTH_PERSISTENT_KEY_FILE, mode=0o600)
    return _parse_oauth_cache_key_set(raw_value, source="file")


def _write_oauth_cache_key_set_to_file(key_set: OAuthCacheKeySet) -> bool:
    """Write cache key-set metadata to fallback file with strict file mode."""
    serialized_value = _serialize_oauth_cache_key_set(key_set)
    if serialized_value is None:
        return False
    return _atomic_write_bytes(path=_OAUTH_PERSISTENT_KEY_FILE, data=serialized_value.encode("utf-8"), mode=0o600)


def _parse_oauth_cache_key_set(raw_value: Any, source: str) -> OAuthCacheKeySet | None:
    """Parse key-set metadata with backward-compatible legacy key formats."""
    if isinstance(raw_value, bytes):
        normalized_value = raw_value.decode("utf-8", errors="ignore").strip()
    elif isinstance(raw_value, str):
        normalized_value = raw_value.strip()
    else:
        return None

    if not normalized_value:
        return None

    parsed_value: Any
    try:
        parsed_value = json.loads(normalized_value)
    except json.JSONDecodeError:
        parsed_value = None

    if isinstance(parsed_value, dict):
        active_payload = parsed_value.get("active")
        historical_payload = parsed_value.get("historical")
        if isinstance(active_payload, dict):
            active_key = _parse_oauth_cache_key_material_from_dict(active_payload, source=source)
            if active_key is None:
                return None
            historical_keys: list[OAuthCacheKeyMaterial] = []
            if isinstance(historical_payload, list):
                for item in historical_payload:
                    if not isinstance(item, dict):
                        continue
                    parsed_historical = _parse_oauth_cache_key_material_from_dict(item, source=source)
                    if parsed_historical is not None and parsed_historical.key_id != active_key.key_id:
                        historical_keys.append(parsed_historical)
            return OAuthCacheKeySet(
                active=active_key,
                historical=_prune_oauth_historical_keys(historical_keys),
                source=source,
            )

        legacy_active = _parse_oauth_cache_key_material_from_dict(parsed_value, source=source)
        if legacy_active is not None:
            return OAuthCacheKeySet(active=legacy_active, historical=(), source=source)

    parsed_raw_key = _coerce_fernet_key(normalized_value)
    if parsed_raw_key is None:
        return None
    return OAuthCacheKeySet(
        active=OAuthCacheKeyMaterial(
            key_id=f"legacy-{source}",
            fernet_key=parsed_raw_key,
            source=source,
        ),
        historical=(),
        source=source,
    )


def _parse_oauth_cache_key_material_from_dict(value: dict[str, Any], source: str) -> OAuthCacheKeyMaterial | None:
    """Parse one key-material object with key_id + fernet_key."""
    key_id_value = value.get("key_id")
    fernet_key_value = value.get("fernet_key")
    if not isinstance(key_id_value, str) or not key_id_value.strip():
        return None
    parsed_fernet_key = _coerce_fernet_key(fernet_key_value)
    if parsed_fernet_key is None:
        return None
    return OAuthCacheKeyMaterial(
        key_id=key_id_value.strip(),
        fernet_key=parsed_fernet_key,
        source=source,
    )


def _serialize_oauth_cache_key_set(key_set: OAuthCacheKeySet) -> str | None:
    """Serialize key-set metadata envelope for keyring/file storage."""
    active_payload = _serialize_oauth_cache_key_material_payload(key_set.active)
    if active_payload is None:
        return None

    historical_payload: list[dict[str, str]] = []
    for item in _prune_oauth_historical_keys(list(key_set.historical)):
        if item.key_id == key_set.active.key_id:
            continue
        serialized_item = _serialize_oauth_cache_key_material_payload(item)
        if serialized_item is not None:
            historical_payload.append(serialized_item)

    payload = {
        "active": active_payload,
        "historical": historical_payload,
    }
    return json.dumps(payload, ensure_ascii=True, sort_keys=True)


def _serialize_oauth_cache_key_material_payload(key_material: OAuthCacheKeyMaterial) -> dict[str, str] | None:
    """Serialize key material to dict payload."""
    if not key_material.key_id.strip():
        return None
    try:
        encoded_key = key_material.fernet_key.decode("ascii")
    except UnicodeDecodeError:
        return None
    return {
        "key_id": key_material.key_id,
        "fernet_key": encoded_key,
    }


def _prune_oauth_historical_keys(values: list[OAuthCacheKeyMaterial]) -> tuple[OAuthCacheKeyMaterial, ...]:
    """Deduplicate historical keys and keep newest-first entries up to configured limit."""
    deduped: list[OAuthCacheKeyMaterial] = []
    seen_ids: set[str] = set()
    for item in values:
        key_id = item.key_id.strip()
        if not key_id or key_id in seen_ids:
            continue
        seen_ids.add(key_id)
        deduped.append(item)
    return tuple(deduped[:_OAUTH_HISTORICAL_KEY_LIMIT])


def _build_oauth_decrypt_candidates(key_set: OAuthCacheKeySet) -> list[OAuthCacheKeyMaterial]:
    """Build deterministic decrypt candidates: active first, then historical."""
    candidates = [key_set.active, *list(key_set.historical)]
    deduped: list[OAuthCacheKeyMaterial] = []
    seen_ids: set[str] = set()
    for item in candidates:
        key_id = item.key_id.strip()
        if not key_id or key_id in seen_ids:
            continue
        seen_ids.add(key_id)
        deduped.append(item)
    return deduped


def _decrypt_oauth_cache_payload_with_key_set(
    encrypted_payload: bytes,
    key_set: OAuthCacheKeySet,
) -> dict[str, Any] | None:
    """Decrypt payload using active/historical keys, preferring key_id match when present."""
    fallback_payload: dict[str, Any] | None = None
    for candidate in _build_oauth_decrypt_candidates(key_set):
        payload = _decrypt_oauth_cache_payload(
            encrypted_payload=encrypted_payload,
            encryption_key=candidate.fernet_key,
        )
        if payload is None:
            continue
        payload_key_id = _optional_non_empty_text(payload.get("key_id"))
        if payload_key_id is not None and payload_key_id == candidate.key_id:
            return payload
        if fallback_payload is None:
            fallback_payload = payload
    return fallback_payload


def _resolve_oauth_cache_key_material(create_if_missing: bool) -> OAuthCacheKeyMaterial | None:
    """Backward-compatible resolver returning active key material."""
    key_set = _resolve_oauth_cache_key_set(create_if_missing=create_if_missing)
    if key_set is None:
        return None
    return key_set.active


def _store_oauth_cache_key_material(key_material: OAuthCacheKeyMaterial) -> OAuthCacheKeyMaterial | None:
    """Backward-compatible store for single key material."""
    key_set = OAuthCacheKeySet(active=key_material, historical=(), source=key_material.source)
    stored = _store_oauth_cache_key_set(key_set)
    if stored is None:
        return None
    return OAuthCacheKeyMaterial(
        key_id=stored.active.key_id,
        fernet_key=stored.active.fernet_key,
        source=stored.source,
    )


def _read_oauth_cache_key_material_from_keyring() -> OAuthCacheKeyMaterial | None:
    """Backward-compatible keyring reader returning active key material."""
    key_set = _read_oauth_cache_key_set_from_keyring()
    if key_set is None:
        return None
    return key_set.active


def _write_oauth_cache_key_material_to_keyring(key_material: OAuthCacheKeyMaterial) -> bool:
    """Backward-compatible keyring writer for one key material."""
    return _write_oauth_cache_key_set_to_keyring(OAuthCacheKeySet(active=key_material, historical=()))


def _read_oauth_cache_key_material_from_file() -> OAuthCacheKeyMaterial | None:
    """Backward-compatible file reader returning active key material."""
    key_set = _read_oauth_cache_key_set_from_file()
    if key_set is None:
        return None
    return key_set.active


def _write_oauth_cache_key_material_to_file(key_material: OAuthCacheKeyMaterial) -> bool:
    """Backward-compatible file writer for one key material."""
    return _write_oauth_cache_key_set_to_file(OAuthCacheKeySet(active=key_material, historical=()))


def _parse_oauth_cache_key_material(raw_value: Any, source: str) -> OAuthCacheKeyMaterial | None:
    """Backward-compatible key parser returning active key material."""
    key_set = _parse_oauth_cache_key_set(raw_value, source=source)
    if key_set is None:
        return None
    return key_set.active


def _serialize_oauth_cache_key_material(key_material: OAuthCacheKeyMaterial) -> str | None:
    """Backward-compatible key serializer for one active key."""
    return _serialize_oauth_cache_key_set(OAuthCacheKeySet(active=key_material, historical=()))


def _resolve_oauth_cache_encryption_key() -> bytes | None:
    """Backward-compatible helper returning only resolved key bytes."""
    key_material = _resolve_oauth_cache_key_material(create_if_missing=True)
    if key_material is None:
        return None
    return key_material.fernet_key


def _read_oauth_cache_key_from_keyring() -> bytes | None:
    """Backward-compatible keyring reader returning raw key bytes."""
    key_material = _read_oauth_cache_key_material_from_keyring()
    if key_material is None:
        return None
    return key_material.fernet_key


def _read_or_create_oauth_cache_key_file() -> bytes | None:
    """Backward-compatible file reader/writer returning raw key bytes."""
    key_material = _read_oauth_cache_key_material_from_file()
    if key_material is not None:
        return key_material.fernet_key

    generated_material = _generate_oauth_cache_key_material()
    stored_material = _store_oauth_cache_key_material(generated_material)
    if stored_material is None:
        return None
    return stored_material.fernet_key


def _generate_oauth_cache_key_material() -> OAuthCacheKeyMaterial:
    """Generate new key material envelope."""
    generated_key = _generate_fernet_key()
    if generated_key is None:
        raise RuntimeError("Failed to generate Fernet key.")
    return OAuthCacheKeyMaterial(
        key_id=f"k_{secrets.token_hex(8)}",
        fernet_key=generated_key,
        source="generated",
    )


def _coerce_fernet_key(value: Any) -> bytes | None:
    """Normalize candidate Fernet key and verify shape."""
    if isinstance(value, str):
        raw_key = value.strip().encode("ascii", errors="ignore")
    elif isinstance(value, bytes):
        raw_key = value.strip()
    else:
        return None

    if not raw_key:
        return None

    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None

    try:
        Fernet(raw_key)
    except Exception:
        return None
    return raw_key


def _generate_fernet_key() -> bytes | None:
    """Generate Fernet key bytes."""
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None
    return Fernet.generate_key()


def _decrypt_oauth_cache_payload(encrypted_payload: bytes, encryption_key: bytes) -> dict[str, Any] | None:
    """Decrypt OAuth cache payload and parse JSON object."""
    if not encrypted_payload:
        return None

    try:
        from cryptography.fernet import Fernet, InvalidToken
    except Exception:
        return None

    try:
        plaintext_payload = Fernet(encryption_key).decrypt(encrypted_payload)
    except (InvalidToken, ValueError, TypeError):
        return None

    try:
        parsed_payload = json.loads(plaintext_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(parsed_payload, dict):
        return None
    return parsed_payload


def _encrypt_oauth_cache_payload(
    entries: dict[str, dict[str, Any]],
    key_material: OAuthCacheKeyMaterial,
) -> bytes | None:
    """Encrypt OAuth cache entries with versioned payload."""
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None

    payload: dict[str, Any] = {
        "schema_version": _OAUTH_CACHE_SCHEMA_VERSION_V2,
        "key_id": key_material.key_id,
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "entries": entries,
    }
    serialized_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

    try:
        return Fernet(key_material.fernet_key).encrypt(serialized_payload)
    except Exception:
        return None


def _atomic_write_bytes(path: Path, data: bytes, mode: int) -> bool:
    """Write bytes atomically by temp file + replace."""
    temp_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", delete=False, dir=path.parent) as temp_file:
            temp_file.write(data)
            temp_path = Path(temp_file.name)
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
        _ensure_file_mode(path, mode=mode)
        return True
    except OSError:
        return False
    finally:
        if temp_path is not None and temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass


def _acquire_oauth_cache_lock() -> tuple[tuple[Any, Any] | None, str | None]:
    """Acquire exclusive lock for persistent cache operations."""
    try:
        fcntl_module = cast(Any, importlib.import_module("fcntl"))
    except Exception:
        return None, "POSIX file lock is unavailable; persistent cache is bypassed."

    try:
        _OAUTH_PERSISTENT_CACHE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        lock_file_handle = _OAUTH_PERSISTENT_CACHE_LOCK_FILE.open("a+b")
    except OSError as exc:
        return None, f"Unable to open cache lock file: {exc}"

    deadline = time.monotonic() + _OAUTH_CACHE_LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl_module.flock(lock_file_handle.fileno(), fcntl_module.LOCK_EX | fcntl_module.LOCK_NB)
            return (lock_file_handle, fcntl_module), None
        except OSError as exc:
            err_no = getattr(exc, "errno", None)
            if err_no not in {11, 13}:
                try:
                    lock_file_handle.close()
                except OSError:
                    pass
                return None, f"Unable to lock OAuth cache file: {exc}"
            if time.monotonic() >= deadline:
                try:
                    lock_file_handle.close()
                except OSError:
                    pass
                return (
                    None,
                    f"Timed out acquiring OAuth cache lock after {_OAUTH_CACHE_LOCK_TIMEOUT_SECONDS:.1f}s.",
                )
            time.sleep(_OAUTH_CACHE_LOCK_RETRY_SECONDS)


def _release_oauth_cache_lock(lock_handle: tuple[Any, Any] | None) -> None:
    """Release previously acquired OAuth cache lock."""
    if lock_handle is None:
        return

    lock_file_handle, fcntl_module = lock_handle
    try:
        fcntl_module.flock(lock_file_handle.fileno(), fcntl_module.LOCK_UN)
    except OSError:
        pass
    try:
        lock_file_handle.close()
    except OSError:
        pass


def _quarantine_oauth_cache_file_locked() -> None:
    """Rename corrupt cache payload to a timestamped quarantine file."""
    if not _OAUTH_PERSISTENT_CACHE_FILE.exists():
        return

    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    base_name = f"{_OAUTH_PERSISTENT_CACHE_FILE.name}.corrupt.{timestamp}"
    quarantine_path = _OAUTH_PERSISTENT_CACHE_FILE.with_name(base_name)
    counter = 1
    while quarantine_path.exists():
        quarantine_path = _OAUTH_PERSISTENT_CACHE_FILE.with_name(f"{base_name}.{counter}")
        counter += 1

    try:
        os.replace(_OAUTH_PERSISTENT_CACHE_FILE, quarantine_path)
    except OSError:
        return
    _ensure_file_mode(quarantine_path, mode=0o600)


def _ensure_file_mode(path: Path, mode: int) -> None:
    """Best-effort chmod hardening for cache/key artifacts."""
    try:
        if path.exists():
            os.chmod(path, mode)
    except OSError:
        pass


def _get_cached_oauth_token(cache_key: str) -> str | None:
    """Return cached access token when TTL is valid."""
    cached_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached_entry is None:
        return None

    token_value = cached_entry.get("access_token")
    if not isinstance(token_value, str) or not token_value.strip():
        _OAUTH_TOKEN_CACHE.pop(cache_key, None)
        return None

    expires_at_value = cached_entry.get("expires_at")
    if expires_at_value is None:
        return token_value.strip()
    if not isinstance(expires_at_value, (int, float)):
        _OAUTH_TOKEN_CACHE.pop(cache_key, None)
        return None

    if _oauth_now() >= float(expires_at_value):
        refresh_token = cached_entry.get("refresh_token")
        if isinstance(refresh_token, str) and refresh_token.strip():
            return None
        _OAUTH_TOKEN_CACHE.pop(cache_key, None)
        return None

    return token_value.strip()


def _get_cached_oauth_refresh_token(cache_key: str) -> str | None:
    """Return cached refresh token when available."""
    cached_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached_entry is None:
        return None
    refresh_token = cached_entry.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        return None
    return refresh_token.strip()


def _get_cached_oauth_token_type(cache_key: str) -> str | None:
    """Return cached token_type when available."""
    cached_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if cached_entry is None:
        return None
    token_type = cached_entry.get("token_type")
    if not isinstance(token_type, str) or not token_type.strip():
        return None
    return token_type.strip()


def _drop_oauth_refresh_token(
    cache_key: str,
    persistent: bool = False,
    cache_settings: OAuthCacheSettings | None = None,
) -> None:
    """Remove cached refresh token to force a one-time primary grant fallback."""
    cached_entry = _OAUTH_TOKEN_CACHE.get(cache_key)
    if not isinstance(cached_entry, dict):
        return
    cached_entry.pop("refresh_token", None)
    if not cached_entry:
        _OAUTH_TOKEN_CACHE.pop(cache_key, None)
    should_persist = cache_settings.persistent if cache_settings is not None else persistent
    if should_persist:
        if cache_settings is None:
            _persist_oauth_cache_entry(cache_key)
        else:
            _persist_oauth_cache_entry(cache_key, cache_settings=cache_settings)


def _store_oauth_token_cache(
    cache_key: str,
    token: str,
    expires_in: float | None,
    refresh_token: str | None = None,
    token_type: str | None = None,
    persistent: bool = False,
    cache_settings: OAuthCacheSettings | None = None,
) -> None:
    """Store token in in-memory cache with optional TTL and safety skew."""
    expires_at: float | None = None
    if expires_in is not None:
        ttl_seconds = max(0.0, expires_in - _OAUTH_TOKEN_CACHE_SKEW_SECONDS)
        expires_at = _oauth_now() + ttl_seconds

    entry: dict[str, Any] = {
        "access_token": token,
        "expires_at": expires_at,
    }
    if isinstance(refresh_token, str) and refresh_token.strip():
        entry["refresh_token"] = refresh_token.strip()
    if isinstance(token_type, str) and token_type.strip():
        entry["token_type"] = token_type.strip()

    _OAUTH_TOKEN_CACHE[cache_key] = entry
    should_persist = cache_settings.persistent if cache_settings is not None else persistent
    if should_persist:
        if cache_settings is None:
            _persist_oauth_cache_entry(cache_key)
        else:
            _persist_oauth_cache_entry(cache_key, cache_settings=cache_settings)


def _clear_oauth_token_cache() -> None:
    """Clear in-memory OAuth token cache."""
    _OAUTH_TOKEN_CACHE.clear()


def _build_scan_failure_finding(server_name: str, raw_server_config: Any, error: Exception) -> Finding:
    """Create finding for runtime scan failures while processing config entries."""
    transport = "unknown"
    if isinstance(raw_server_config, dict):
        transport_value = raw_server_config.get("transport", raw_server_config.get("type", "stdio"))
        normalized_transport = _normalize_transport_name(transport_value)
        if normalized_transport is not None:
            transport = normalized_transport
        elif isinstance(transport_value, str):
            transport = transport_value.lower()

    return Finding(
        analyzer_name="config_scanner",
        severity=Severity.HIGH,
        category="scan_failure",
        title=f"Failed to scan server {server_name}",
        description="Server scan failed and was skipped; this creates an unscanned security gap.",
        evidence=f"transport={transport}; error={error}; config={_safe_json_dump(raw_server_config)}",
        owasp_id="LLM10",
        remediation="Fix server startup/connectivity and rerun config scan.",
        metadata={"server_name": server_name, "transport": transport},
    )


def _mutation_to_finding(mutation: dict[str, Any]) -> Finding:
    """Convert one mutation record into a Finding instance."""
    mutation_type = str(mutation.get("type"))
    tool_name = str(mutation.get("tool_name"))

    baseline = mutation.get("baseline")
    current = mutation.get("current")
    changed_fields = mutation.get("changed_fields", [])

    if mutation_type == "added":
        severity = Severity.MEDIUM
        category = "tool_added"
        title = f"Tool added since baseline: {tool_name}"
        description = "A new tool exists in current server but did not exist in baseline snapshot."
        remediation = "Review and approve new tools before deployment."
    elif mutation_type == "removed":
        severity = Severity.HIGH
        category = "tool_removed"
        title = f"Tool removed since baseline: {tool_name}"
        description = "A baseline tool is missing from current server snapshot."
        remediation = "Verify removal is intentional and update baseline if approved."
    else:
        severity = Severity.HIGH
        category = "tool_changed"
        title = f"Tool changed since baseline: {tool_name}"
        description = "A tool hash changed compared to baseline, indicating potential rug-pull mutation."
        remediation = "Review schema/description diff and re-approve before rollout."

    evidence = _safe_json_dump(
        {
            "mutation_type": mutation_type,
            "tool_name": tool_name,
            "changed_fields": changed_fields,
            "baseline_overall_hash": baseline.get("overall_hash") if isinstance(baseline, dict) else None,
            "current_overall_hash": current.get("overall_hash") if isinstance(current, dict) else None,
        }
    )

    return Finding(
        analyzer_name="baseline_compare",
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=evidence,
        owasp_id="LLM05",
        remediation=remediation,
        tool_name=tool_name,
        metadata={"mutation_type": mutation_type},
    )


def _write_report(report: ScanReport, output_format: str, output_path: str | None) -> None:
    """Write report to output file or print to stdout."""
    generator = ReportGenerator()
    if output_path:
        generator.save_report(report, output_path, output_format)
        return

    output = generator.generate(report, output_format)
    click.echo(output)


def _safe_json_dump(value: Any) -> str:
    """Serialize unknown payloads for evidence fields without raising."""
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return repr(value)


def _normalize_transport_name(value: Any) -> str | None:
    """Normalize transport aliases to canonical names."""
    if not isinstance(value, str):
        return None

    transport = value.strip().lower()
    if transport == "streamable_http":
        return "streamable-http"

    if transport in {"stdio", "sse", "streamable-http"}:
        return transport

    return None


def _derive_server_name(command: str) -> str:
    """Derive a compact display name from a command string."""
    stripped = command.strip()
    if not stripped:
        return "mcp-server"

    parsed = urlparse(stripped)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed.netloc

    first_token = stripped.split()[0]
    return Path(first_token).name or "mcp-server"


def _parse_severity_threshold(severity: str) -> Severity | None:
    """Parse CLI severity threshold. Returns None when no filtering is requested."""
    if severity == "all":
        return None
    return Severity(severity)


def _filter_findings(findings: list[Finding], threshold: Severity | None) -> list[Finding]:
    """Filter findings by severity threshold (inclusive)."""
    if threshold is None:
        return findings
    return [finding for finding in findings if finding.severity >= threshold]


if __name__ == "__main__":
    main()
