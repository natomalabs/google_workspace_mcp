"""
Security regression tests for auth/oauth_responses.py.

Covers SNOW-3697272 [CWE-209]: unescaped exception text in
create_server_error_response led to information disclosure and a secondary
reflected XSS on /oauth2callback.
"""

import html

import pytest

from auth.oauth_responses import (
    create_error_response,
    create_server_error_response,
    create_success_response,
    new_error_reference,
)

XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    "</p><script>fetch('/oauth2/register')</script><p>",
    "<svg/onload=alert(document.domain)>",
    "' onmouseover='alert(1)",
    "</script><script>alert(1)</script>",
]


def _body(response):
    return response.body.decode()


# --- escaping -------------------------------------------------------------------


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_error_response_escapes_payload(payload):
    body = _body(create_error_response(payload))

    # The payload must appear only in escaped form. Asserting "<script" is absent
    # would be wrong: these pages carry a legitimate inline auto-close script.
    assert payload not in body
    assert html.escape(payload, quote=True) in body


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_server_error_response_rejects_non_reference_values(payload):
    """Anything that isn't a well-formed reference token is dropped entirely."""
    body = _body(create_server_error_response(payload))

    assert payload not in body
    assert html.escape(payload, quote=True) not in body
    assert "Reference:" not in body


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_success_response_escapes_user_id(payload):
    body = _body(create_success_response(payload))

    assert payload not in body
    assert html.escape(payload, quote=True) in body


def test_error_response_escapes_angle_brackets_and_quotes():
    body = _body(create_error_response("<b>x</b> \"q\" 'p' &"))

    assert "&lt;b&gt;" in body
    assert "&quot;" in body
    assert "&amp;" in body
    assert "<b>" not in body


# --- information disclosure -----------------------------------------------------


def test_server_error_response_does_not_render_exception_text():
    """The whole point of the finding: exception detail must not reach the browser."""
    leaky = (
        "invalid_scope: /Users/bob/secrets/client_secret.json redirect_uri="
        "http://localhost:8000/oauth2callback scope=https://www.googleapis.com/auth/gmail.readonly"
    )
    body = _body(create_server_error_response(leaky))

    assert "client_secret.json" not in body
    assert "/Users/bob/secrets" not in body
    assert "redirect_uri" not in body
    assert "googleapis.com" not in body
    assert "invalid_scope" not in body


def test_server_error_response_renders_reference_when_given():
    reference = "abc123def456"
    body = _body(create_server_error_response(reference))

    assert reference in body
    assert "Reference:" in body


def test_server_error_response_without_reference_is_still_valid():
    body = _body(create_server_error_response())

    assert "Reference:" not in body
    assert "unexpected error occurred" in body


def test_server_error_response_status_is_500():
    assert create_server_error_response("ref").status_code == 500


def test_new_error_reference_is_opaque_and_unique():
    a, b = new_error_reference(), new_error_reference()

    assert a != b
    assert len(a) == 12
    assert a.isalnum()


# --- defence-in-depth headers ---------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        create_error_response("x"),
        create_success_response("bob@corp.com"),
        create_server_error_response("ref"),
    ],
)
def test_responses_carry_restrictive_csp(response):
    csp = response.headers.get("content-security-policy")

    assert csp is not None
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp


@pytest.mark.parametrize(
    "response",
    [
        create_error_response("x"),
        create_success_response("bob@corp.com"),
        create_server_error_response("ref"),
    ],
)
def test_responses_carry_nosniff_and_no_store(response):
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("cache-control") == "no-store"


def test_success_response_still_shows_legitimate_email():
    body = _body(create_success_response("bob@corp.com"))
    assert "bob@corp.com" in body


def test_success_response_defaults_when_no_user():
    body = _body(create_success_response(None))
    assert "Google User" in body
