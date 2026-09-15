"""
Security regression tests for auth/oauth21_session_store.py.

Covers:
  SNOW-3697276 [CWE-613] stale _mcp_session_mapping entries survive remove_session()
  SNOW-3697308 [CWE-287] session-store poisoning destroys the victim's refresh_token
"""

import pytest

from auth.oauth21_session_store import OAuth21SessionStore


@pytest.fixture
def store():
    return OAuth21SessionStore()


# --- SNOW-3697276: revocation must purge every historical session id ------------


def test_remove_session_purges_all_historical_mcp_session_ids(store):
    """Bob connects from three clients; logout must invalidate all three ids."""
    for uuid in ("uuid_1", "uuid_2", "uuid_3"):
        store.store_session(
            user_email="bob@corp.com",
            access_token=f"token-{uuid}",
            session_id=f"google_{uuid}",
            mcp_session_id=uuid,
        )

    # All three are live before revocation.
    for uuid in ("uuid_1", "uuid_2", "uuid_3"):
        assert store.get_user_by_mcp_session(uuid) == "bob@corp.com"

    store.remove_session("bob@corp.com")

    for uuid in ("uuid_1", "uuid_2", "uuid_3"):
        assert store.get_user_by_mcp_session(uuid) is None, f"{uuid} survived revocation"
        assert store.has_mcp_session(uuid) is False


def test_stale_id_cannot_be_revived_by_reauthentication(store):
    """
    The core of the finding: after logout and re-auth, an old leaked uuid must not
    resolve to the victim's fresh credentials.
    """
    store.store_session(
        user_email="bob@corp.com",
        access_token="old",
        session_id="google_1",
        mcp_session_id="uuid_1",
    )
    store.store_session(
        user_email="bob@corp.com",
        access_token="newer",
        session_id="google_2",
        mcp_session_id="uuid_2",
    )

    store.remove_session("bob@corp.com")

    # Bob re-authenticates with a brand new session.
    store.store_session(
        user_email="bob@corp.com",
        access_token="fresh",
        refresh_token="1//fresh-refresh",
        session_id="google_3",
        mcp_session_id="uuid_3",
    )

    # The attacker's captured uuid_1 must still be dead.
    assert store.get_user_by_mcp_session("uuid_1") is None
    assert store.get_credentials_by_mcp_session("uuid_1") is None
    # The legitimate new session works.
    assert store.get_user_by_mcp_session("uuid_3") == "bob@corp.com"


def test_remove_session_purges_oauth_session_bindings(store):
    store.store_session(
        user_email="bob@corp.com",
        access_token="t1",
        session_id="google_a",
        mcp_session_id="uuid_a",
    )
    store.store_session(
        user_email="bob@corp.com",
        access_token="t2",
        session_id="google_b",
        mcp_session_id="uuid_b",
    )

    store.remove_session("bob@corp.com")

    assert store._session_auth_binding == {}
    assert store._mcp_session_mapping == {}
    assert store._user_session_ids == {}


def test_remove_session_does_not_disturb_other_users(store):
    store.store_session(
        user_email="bob@corp.com",
        access_token="bob",
        session_id="google_bob",
        mcp_session_id="uuid_bob",
    )
    store.store_session(
        user_email="carol@corp.com",
        access_token="carol",
        session_id="google_carol",
        mcp_session_id="uuid_carol",
    )

    store.remove_session("bob@corp.com")

    assert store.get_user_by_mcp_session("uuid_bob") is None
    assert store.get_user_by_mcp_session("uuid_carol") == "carol@corp.com"
    assert store.has_session("carol@corp.com") is True


def test_reverse_sweep_cleans_orphans_not_in_tracking_set(store):
    """Ids predating the tracking set (e.g. after an upgrade) must still be purged."""
    store.store_session(
        user_email="bob@corp.com",
        access_token="t",
        session_id="google_1",
        mcp_session_id="uuid_1",
    )
    # Simulate a pre-upgrade orphan: present in the maps, absent from the set.
    store._mcp_session_mapping["legacy_uuid"] = "bob@corp.com"
    store._session_auth_binding["legacy_uuid"] = "bob@corp.com"
    store._user_session_ids["bob@corp.com"].discard("legacy_uuid")

    store.remove_session("bob@corp.com")

    assert store.get_user_by_mcp_session("legacy_uuid") is None
    assert "legacy_uuid" not in store._session_auth_binding


def test_remove_session_for_unknown_user_is_a_noop(store):
    store.remove_session("nobody@corp.com")  # must not raise
    assert store.has_session("nobody@corp.com") is False


# --- SNOW-3697308: overwrite must not destroy long-lived credentials ------------


def test_reverification_does_not_wipe_refresh_token(store):
    """
    verify_token() re-stores a session with only the bearer token on every /mcp
    request. That must not null out the refresh_token saved by /oauth2callback.
    """
    store.store_session(
        user_email="bob@corp.com",
        access_token="access-1",
        refresh_token="1//long-lived",
        client_id="cid",
        client_secret="csecret",
        session_id="google_1",
        mcp_session_id="uuid_1",
    )

    # Simulate the verify_token() path: access token only.
    store.store_session(
        user_email="bob@corp.com",
        access_token="access-2",
        session_id="google_1",
        mcp_session_id="uuid_1",
    )

    info = store.get_session_info("bob@corp.com")
    assert info["access_token"] == "access-2"
    assert info["refresh_token"] == "1//long-lived"
    assert info["client_id"] == "cid"
    assert info["client_secret"] == "csecret"


def test_explicit_new_refresh_token_still_replaces_the_old_one(store):
    store.store_session(
        user_email="bob@corp.com", access_token="a1", refresh_token="1//old"
    )
    store.store_session(
        user_email="bob@corp.com", access_token="a2", refresh_token="1//new"
    )

    assert store.get_session_info("bob@corp.com")["refresh_token"] == "1//new"


def test_rebinding_a_session_to_a_different_user_is_rejected(store):
    """The pre-existing immutable-binding guard must remain intact."""
    store.store_session(
        user_email="bob@corp.com", access_token="t", mcp_session_id="uuid_1"
    )

    with pytest.raises(ValueError):
        store.store_session(
            user_email="alice@evil.com", access_token="t", mcp_session_id="uuid_1"
        )
