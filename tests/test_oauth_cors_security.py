"""
Security regression tests for the OAuth CORS decision.

Covers:
  SNOW-3697274 [CWE-1188] OAUTH_ALLOWED_ORIGINS never enforced; 'development' CORS
                          active in production, so the operator had no mitigation lever
  SNOW-3687336 [CWE-942]  permissive localhost-prefix CORS lets any local page read
                          GOOGLE_OAUTH_CLIENT_SECRET

These matter because /oauth2/register and /oauth2/token return the confidential
client_secret, so a reflected Access-Control-Allow-Origin is a secret-exfiltration
primitive.
"""

import importlib

import pytest

import auth.oauth_config as oauth_config_module
from auth.oauth_config import OAuthConfig
from auth.oauth_error_handling import get_development_cors_headers


@pytest.fixture(autouse=True)
def reset_global_config():
    """The config is a process-global singleton; clear it between tests."""
    oauth_config_module._oauth_config = None
    yield
    oauth_config_module._oauth_config = None


def _config(monkeypatch, **env):
    for key in (
        "OAUTH_ALLOWED_ORIGINS",
        "OAUTH_ALLOW_LOCALHOST_ORIGINS",
        "WORKSPACE_EXTERNAL_URL",
        "WORKSPACE_MCP_BASE_URI",
        "PORT",
        "WORKSPACE_MCP_PORT",
        "MCP_ENABLE_OAUTH21",
        "WORKSPACE_MCP_STATELESS_MODE",
    ):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return OAuthConfig()


# --- SNOW-3697274: the allow-list must actually be consulted --------------------


def test_configured_origin_is_allowed(monkeypatch):
    cfg = _config(monkeypatch, OAUTH_ALLOWED_ORIGINS="https://bob-ide.example")

    assert cfg.is_origin_allowed("https://bob-ide.example") is True


def test_unconfigured_origin_is_denied(monkeypatch):
    cfg = _config(monkeypatch, OAUTH_ALLOWED_ORIGINS="https://bob-ide.example")

    assert cfg.is_origin_allowed("https://attacker.example") is False


def test_operators_strict_allowlist_excludes_localhost_in_production(monkeypatch):
    """
    The finding's narrative: Bob deploys behind TLS with a strict allow-list, and a
    malicious local page on http://localhost:43117 must NOT be able to read the
    client_secret.
    """
    cfg = _config(
        monkeypatch,
        OAUTH_ALLOWED_ORIGINS="https://bob-ide.example",
        WORKSPACE_EXTERNAL_URL="https://mcp.bob.example",
    )

    assert cfg.allow_localhost_origins is False
    assert cfg.is_origin_allowed("http://localhost:43117") is False
    assert cfg.is_origin_allowed("http://127.0.0.1:43117") is False
    assert cfg.is_origin_allowed("https://bob-ide.example") is True


def test_multiple_configured_origins_are_parsed(monkeypatch):
    cfg = _config(
        monkeypatch,
        OAUTH_ALLOWED_ORIGINS="https://a.example, https://b.example ,https://c.example",
    )

    for origin in ("https://a.example", "https://b.example", "https://c.example"):
        assert cfg.is_origin_allowed(origin) is True
    assert cfg.is_origin_allowed("https://d.example") is False


def test_allow_localhost_origins_reported_in_summary(monkeypatch):
    cfg = _config(monkeypatch, WORKSPACE_EXTERNAL_URL="https://mcp.bob.example")

    assert cfg.get_environment_summary()["allow_localhost_origins"] is False


# --- SNOW-3687336: localhost allowance must be gated and precise ----------------


def test_localhost_allowed_by_default_for_local_dev(monkeypatch):
    """With no external URL configured, this is a local dev deployment."""
    cfg = _config(monkeypatch)

    assert cfg.allow_localhost_origins is True
    assert cfg.is_origin_allowed("http://localhost:6274") is True
    assert cfg.is_origin_allowed("http://127.0.0.1:6274") is True


def test_localhost_can_be_explicitly_disabled(monkeypatch):
    cfg = _config(monkeypatch, OAUTH_ALLOW_LOCALHOST_ORIGINS="false")

    assert cfg.is_origin_allowed("http://localhost:6274") is False


def test_localhost_can_be_explicitly_enabled_behind_proxy(monkeypatch):
    cfg = _config(
        monkeypatch,
        WORKSPACE_EXTERNAL_URL="https://mcp.bob.example",
        OAUTH_ALLOW_LOCALHOST_ORIGINS="true",
    )

    assert cfg.is_origin_allowed("http://localhost:6274") is True


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost.evil.com",
        "http://localhost.evil.com:8000",
        "http://127.0.0.1.evil.com",
        "https://evil.com/?x=http://localhost:8000",
        "http://evil.com#http://localhost:8000",
        "http://notlocalhost:8000",
        "http://localhostx:8000",
    ],
)
def test_lookalike_hosts_are_rejected(monkeypatch, origin):
    """
    The old implementation used startswith('http://localhost:'), so it rejected
    these by luck. A host-parsing check must reject them by construction.
    """
    cfg = _config(monkeypatch)  # localhost allowance ON, worst case

    assert cfg.is_origin_allowed(origin) is False


def test_non_http_scheme_loopback_rejected(monkeypatch):
    cfg = _config(monkeypatch)

    assert cfg.is_origin_allowed("file://localhost") is False
    assert cfg.is_origin_allowed("ftp://localhost:21") is False


def test_null_and_empty_origin_denied(monkeypatch):
    cfg = _config(monkeypatch)

    assert cfg.is_origin_allowed(None) is False
    assert cfg.is_origin_allowed("") is False
    # The literal "null" origin sent by sandboxed iframes / file:// pages.
    assert cfg.is_origin_allowed("null") is False


def test_vscode_webview_scheme_prefix_still_works(monkeypatch):
    cfg = _config(monkeypatch)

    assert cfg.is_origin_allowed("vscode-webview://abc123") is True


# --- the header helper must honour the decision ---------------------------------


def test_cors_headers_emitted_for_allowed_origin(monkeypatch):
    monkeypatch.setenv("OAUTH_ALLOWED_ORIGINS", "https://bob-ide.example")
    monkeypatch.delenv("WORKSPACE_EXTERNAL_URL", raising=False)

    headers = get_development_cors_headers("https://bob-ide.example")

    assert headers["Access-Control-Allow-Origin"] == "https://bob-ide.example"
    assert headers["Vary"] == "Origin"


def test_no_cors_headers_for_denied_origin(monkeypatch):
    monkeypatch.setenv("OAUTH_ALLOWED_ORIGINS", "https://bob-ide.example")
    monkeypatch.setenv("WORKSPACE_EXTERNAL_URL", "https://mcp.bob.example")

    assert get_development_cors_headers("http://localhost:43117") == {}
    assert get_development_cors_headers("https://attacker.example") == {}


def test_no_cors_headers_without_origin(monkeypatch):
    assert get_development_cors_headers(None) == {}
    assert get_development_cors_headers("") == {}


def test_allowed_origins_is_no_longer_dead_code():
    """
    Regression guard for the root cause: the live CORS path must reference the
    allow-list rather than making its own hard-coded decision.
    """
    import inspect

    source = inspect.getsource(get_development_cors_headers)

    assert "is_origin_allowed" in source
    assert "startswith(\"http://localhost:\")" not in source
