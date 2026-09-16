"""
Security regression tests for PKCE and state verification in the legacy OAuth flow.

Covers the second half of SNOW-3697295 [CWE-367]: the authorization request sent a
PKCE code_challenge but the code_verifier was discarded, so the token exchange
never proved possession of it; and the generated state was never persisted, so it
could not be verified on the callback (oauthlib skips the check when the expected
value is None).
"""

import asyncio
import os
import time
from urllib.parse import parse_qs, urlparse

import pytest

os.environ.setdefault("OAUTHLIB_INSECURE_TRANSPORT", "1")
os.environ.setdefault("GOOGLE_OAUTH_CLIENT_ID", "test-client.apps.googleusercontent.com")
os.environ.setdefault("GOOGLE_OAUTH_CLIENT_SECRET", "GOCSPX-test")

from auth.google_auth import (  # noqa: E402
    _extract_state,
    create_oauth_flow,
    handle_auth_callback,
    start_auth_flow,
)
from auth.oauth_state_store import OAuthStateStore, get_oauth_state_store  # noqa: E402

REDIRECT = "http://localhost:8000/oauth2callback"


@pytest.fixture(autouse=True)
def clean_store():
    get_oauth_state_store().clear()
    yield
    get_oauth_state_store().clear()


def _auth_url():
    msg = asyncio.run(start_auth_flow("bob@corp.com", "Gmail", REDIRECT))
    for line in msg.splitlines():
        if line.startswith("Authorization URL:"):
            return line.split(" ", 2)[2]
    raise AssertionError("no authorization URL in start_auth_flow output")


# --- PKCE is complete, not just requested ---------------------------------------


def test_authorization_url_sends_s256_challenge():
    q = parse_qs(urlparse(_auth_url()).query)

    assert q["code_challenge_method"] == ["S256"]
    assert len(q["code_challenge"][0]) > 20


def test_code_verifier_is_retained_for_the_token_exchange():
    """The core defect: the verifier used to be discarded after authorization."""
    q = parse_qs(urlparse(_auth_url()).query)
    state = q["state"][0]

    record = get_oauth_state_store().consume(state)

    assert record is not None, "no pending authorization was stored"
    assert record["code_verifier"], "code_verifier was not retained"
    assert len(record["code_verifier"]) >= 43  # RFC 7636 minimum


def test_stored_verifier_matches_the_challenge_that_was_sent():
    """Verify the S256 relationship, not just that some verifier exists."""
    import base64
    import hashlib

    q = parse_qs(urlparse(_auth_url()).query)
    challenge_sent = q["code_challenge"][0]
    verifier = get_oauth_state_store().consume(q["state"][0])["code_verifier"]

    digest = hashlib.sha256(verifier.encode()).digest()
    expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")

    assert challenge_sent == expected


def test_callback_flow_is_built_with_verifier_and_expected_state():
    flow = create_oauth_flow(
        scopes=["openid"], redirect_uri=REDIRECT, state="abc123", code_verifier="v" * 64
    )

    assert flow.code_verifier == "v" * 64
    # oauthlib only validates state when the session carries an expected value.
    assert flow.oauth2session._state == "abc123"


def test_flow_without_expected_state_would_not_verify():
    """Documents why state must be passed: absent it, oauthlib skips the check."""
    flow = create_oauth_flow(scopes=["openid"], redirect_uri=REDIRECT)

    assert flow.oauth2session._state is None


# --- state extraction -----------------------------------------------------------


def test_extract_state_reads_the_parameter():
    assert _extract_state(f"{REDIRECT}?state=xyz&code=4/0A") == "xyz"


@pytest.mark.parametrize(
    "url",
    [
        f"{REDIRECT}?code=4/0A",           # absent
        f"{REDIRECT}?state=&code=4/0A",    # empty
        REDIRECT,                          # no query at all
    ],
)
def test_extract_state_returns_none_when_unusable(url):
    assert _extract_state(url) is None


def test_extract_state_rejects_duplicate_parameters():
    """A repeated state must not be silently resolved to the first value."""
    url = f"{REDIRECT}?state=good&state=evil&code=4/0A"

    assert _extract_state(url) is None


# --- the callback rejects unverifiable states -----------------------------------


def test_callback_without_state_is_rejected():
    with pytest.raises(ValueError, match="missing the 'state' parameter"):
        handle_auth_callback(
            scopes=["openid"],
            authorization_response=f"{REDIRECT}?code=4/0A-stolen",
            redirect_uri=REDIRECT,
        )


def test_callback_with_unknown_state_is_rejected():
    """An attacker-minted state was never issued by us, so it cannot be honoured."""
    with pytest.raises(ValueError, match="unrecognised, expired or already-used"):
        handle_auth_callback(
            scopes=["openid"],
            authorization_response=f"{REDIRECT}?state=attackerchosen&code=4/0A-stolen",
            redirect_uri=REDIRECT,
        )


def test_callback_state_cannot_be_replayed():
    """
    A captured callback URL must not work twice: the pending entry is single-use.
    The second attempt fails before any network call.
    """
    state = _auth_url()
    state = parse_qs(urlparse(state).query)["state"][0]
    store = get_oauth_state_store()

    assert store.consume(state) is not None  # first use

    with pytest.raises(ValueError, match="unrecognised, expired or already-used"):
        handle_auth_callback(
            scopes=["openid"],
            authorization_response=f"{REDIRECT}?state={state}&code=4/0A",
            redirect_uri=REDIRECT,
        )


# --- the pending-authorization store -------------------------------------------


def test_store_entries_are_single_use():
    store = OAuthStateStore()
    store.put("s1", "verifier", REDIRECT, ["openid"])

    assert store.consume("s1") is not None
    assert store.consume("s1") is None


def test_store_entries_expire():
    store = OAuthStateStore(ttl_seconds=0)
    store.put("s1", "verifier", REDIRECT, ["openid"])
    time.sleep(0.01)

    assert store.consume("s1") is None


def test_store_is_bounded_and_evicts_oldest():
    store = OAuthStateStore(max_entries=3)
    for i in range(5):
        store.put(f"s{i}", "v", REDIRECT, ["openid"])
        time.sleep(0.001)  # keep created_at ordering distinct

    assert len(store) <= 3
    # The oldest states were evicted; the newest survives.
    assert store.consume("s0") is None
    assert store.consume("s4") is not None


def test_store_rejects_empty_state():
    store = OAuthStateStore()
    with pytest.raises(ValueError):
        store.put("", "v", REDIRECT, ["openid"])


def test_store_consume_of_empty_state_is_none():
    assert OAuthStateStore().consume("") is None


def test_new_state_is_unguessable_and_unique():
    a, b = OAuthStateStore.new_state(), OAuthStateStore.new_state()

    assert a != b
    assert len(a) == 64  # 32 random bytes, hex encoded
    assert int(a, 16) >= 0  # valid hex


def test_states_from_separate_flows_are_distinct():
    s1 = parse_qs(urlparse(_auth_url()).query)["state"][0]
    s2 = parse_qs(urlparse(_auth_url()).query)["state"][0]

    assert s1 != s2
    assert len(get_oauth_state_store()) == 2
