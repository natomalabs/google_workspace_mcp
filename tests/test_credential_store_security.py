"""
Security regression tests for auth/credential_store.py.

Covers:
  SNOW-3697285 [CWE-732] world-readable plaintext OAuth refresh_token + client_secret
  SNOW-3697292 [CWE-22]  path traversal via tool-supplied user_google_email
"""

import json
import os
import stat

import pytest
from google.oauth2.credentials import Credentials

from auth.credential_store import (
    CredentialStoreError,
    LocalDirectoryCredentialStore,
    is_valid_user_email,
)


def _creds():
    return Credentials(
        token="ya29.access",
        refresh_token="1//refresh",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="cid.apps.googleusercontent.com",
        client_secret="GOCSPX-secret",
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )


@pytest.fixture
def store(tmp_path):
    return LocalDirectoryCredentialStore(base_dir=str(tmp_path / "creds"))


# --- SNOW-3697285: file and directory permissions -------------------------------


def test_stored_credential_file_is_owner_only(store):
    assert store.store_credential("bob@corp.com", _creds()) is True

    path = os.path.join(store.base_dir, "bob@corp.com.json")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"credential file is {mode:04o}, expected 0600"


def test_credential_directory_is_owner_only(store):
    store.store_credential("bob@corp.com", _creds())

    mode = stat.S_IMODE(os.stat(store.base_dir).st_mode)
    assert mode == 0o700, f"credential dir is {mode:04o}, expected 0700"


def test_file_mode_is_not_affected_by_permissive_umask(store):
    """mkstemp + explicit chmod must be immune to the process umask."""
    old = os.umask(0o000)
    try:
        store.store_credential("bob@corp.com", _creds())
    finally:
        os.umask(old)

    path = os.path.join(store.base_dir, "bob@corp.com.json")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_preexisting_world_readable_files_are_tightened(tmp_path):
    """Files written by an older version at 0644 must be re-permissioned."""
    base = tmp_path / "creds"
    base.mkdir(mode=0o755)
    legacy = base / "old@corp.com.json"
    legacy.write_text(json.dumps({"token": "t", "client_secret": "s"}))
    os.chmod(legacy, 0o644)

    store = LocalDirectoryCredentialStore(base_dir=str(base))
    # Any operation that touches the directory triggers the sweep.
    store.get_credential("old@corp.com")

    assert stat.S_IMODE(os.stat(legacy).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(base).st_mode) == 0o700


def test_roundtrip_still_works(store):
    store.store_credential("bob@corp.com", _creds())
    loaded = store.get_credential("bob@corp.com")

    assert loaded is not None
    assert loaded.refresh_token == "1//refresh"
    assert loaded.client_secret == "GOCSPX-secret"


def test_no_temp_files_left_behind(store):
    store.store_credential("bob@corp.com", _creds())
    leftovers = [f for f in os.listdir(store.base_dir) if f.endswith(".tmp")]
    assert leftovers == []


# --- SNOW-3697292: path traversal ----------------------------------------------


TRAVERSAL_PAYLOADS = [
    "../../../tmp/oauth@stash",
    "../oauth@stash",
    "/etc/passwd@x",
    "..@..",
    "sub/dir/bob@corp.com",
    "bob@corp.com/../../escape",
    "bob\\@corp.com",
    "bob@corp.com\x00.json",
    ".hidden@corp.com",
]


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_traversal_payloads_rejected_by_validator(payload):
    assert is_valid_user_email(payload) is False


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_get_credential_path_raises_on_traversal(store, payload):
    with pytest.raises(CredentialStoreError):
        store._get_credential_path(payload)


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_public_api_fails_closed_on_traversal(store, payload):
    """Public methods must fail closed, not raise into unrelated callers."""
    assert store.get_credential(payload) is None
    assert store.store_credential(payload, _creds()) is False
    assert store.delete_credential(payload) is False


def test_traversal_write_does_not_escape_base_dir(tmp_path):
    base = tmp_path / "creds"
    outside = tmp_path / "outside"
    outside.mkdir()

    store = LocalDirectoryCredentialStore(base_dir=str(base))
    assert store.store_credential("../outside/pwned@x", _creds()) is False

    assert list(outside.iterdir()) == []


def test_symlink_in_base_dir_cannot_redirect_write(tmp_path):
    """A symlinked credential name must not let the write land outside base_dir."""
    base = tmp_path / "creds"
    base.mkdir(mode=0o700)
    outside = tmp_path / "outside"
    outside.mkdir()

    # Plant a symlink where the credential file would go.
    link = base / "victim@corp.com.json"
    target = outside / "captured.json"
    os.symlink(target, link)

    store = LocalDirectoryCredentialStore(base_dir=str(base))
    # The realpath containment check resolves the symlink, sees it points outside
    # base_dir, and refuses the operation.
    assert store.store_credential("victim@corp.com", _creds()) is False

    assert not target.exists(), "write followed the symlink out of base_dir"
    assert list(outside.iterdir()) == []


@pytest.mark.parametrize(
    "email",
    [
        "bob@corp.com",
        "bob.smith@corp.co.uk",
        "bob+tag@corp.com",
        "bob_smith@sub.corp.com",
        "b@c.io",
    ],
)
def test_legitimate_emails_accepted(store, email):
    assert is_valid_user_email(email) is True
    assert store.store_credential(email, _creds()) is True
    assert store.get_credential(email) is not None


def test_list_users_ignores_temp_and_non_json(store):
    store.store_credential("bob@corp.com", _creds())
    (open(os.path.join(store.base_dir, ".cred-abc.tmp"), "w")).close()
    (open(os.path.join(store.base_dir, "notes.txt"), "w")).close()

    assert store.list_users() == ["bob@corp.com"]
