"""
Security regression tests for auth/google_remote_auth_provider.py.

Covers SNOW-3697308 [CWE-287]: verify_token() accepted the Google 'email' claim as
a verified identity without checking email_verified, allowing an attacker holding a
Google account whose email claim equals a victim's address (but is unverified) to
authenticate as that victim.
"""

import pytest

from auth.google_remote_auth_provider import _is_email_verified


# --- the verified-email predicate ----------------------------------------------


@pytest.mark.parametrize(
    "claims",
    [
        {"email_verified": True},
        {"email_verified": "true"},
        {"email_verified": "True"},
        {"email_verified": "TRUE"},
        {"email_verified": " true "},
    ],
)
def test_verified_values_accepted(claims):
    """tokeninfo returns the JSON string "true"; ID tokens use a real boolean."""
    assert _is_email_verified(claims) is True


@pytest.mark.parametrize(
    "claims",
    [
        {},                                 # claim absent entirely
        {"email_verified": False},
        {"email_verified": "false"},
        {"email_verified": "False"},
        {"email_verified": None},
        {"email_verified": ""},
        {"email_verified": 0},
        {"email_verified": 1},              # int 1 is not an accepted encoding
        {"email_verified": "yes"},
        {"email_verified": "1"},
        {"email_verified": []},
        {"email_verified": {}},
        {"email": "victim@corp.com"},       # the exploit shape: email but no flag
    ],
)
def test_unverified_or_malformed_values_rejected(claims):
    assert _is_email_verified(claims) is False


def test_attacker_claim_shape_is_rejected():
    """
    The exact tokeninfo payload from the finding's narrative: correct audience,
    live token, victim's address, but email_verified=false.
    """
    token_info = {
        "aud": "server-client-id.apps.googleusercontent.com",
        "email": "carol@corp.com",
        "email_verified": "false",
        "expires_in": "3599",
        "sub": "1234567890",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    }

    assert _is_email_verified(token_info) is False


def test_legitimate_claim_shape_is_accepted():
    token_info = {
        "aud": "server-client-id.apps.googleusercontent.com",
        "email": "carol@corp.com",
        "email_verified": "true",
        "expires_in": "3599",
        "sub": "1234567890",
    }

    assert _is_email_verified(token_info) is True


def test_predicate_is_used_in_both_verify_token_branches():
    """
    Guard against a regression that reintroduces the gap in only one branch:
    both the ya29 tokeninfo path and the JWT path must consult the predicate.
    """
    import inspect

    from auth.google_remote_auth_provider import GoogleRemoteAuthProvider

    source = inspect.getsource(GoogleRemoteAuthProvider.verify_token)

    assert source.count("_is_email_verified") >= 2, (
        "email_verified must be enforced in both the ya29 tokeninfo branch and "
        "the JWT branch"
    )
