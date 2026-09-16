"""
Credential Store API for Google Workspace MCP

This module provides a standardized interface for credential storage and retrieval,
supporting multiple backends configurable via environment variables.
"""

import os
import re
import json
import logging
import stat
import tempfile
from abc import ABC, abstractmethod
from typing import Optional, List
from datetime import datetime
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)

# Directory mode for the credential store: owner-only rwx. The store holds
# long-lived OAuth refresh_tokens and the application's confidential
# client_secret, so no group/other access is ever appropriate.
_CREDENTIAL_DIR_MODE = 0o700

# File mode for individual credential files: owner-only rw.
_CREDENTIAL_FILE_MODE = 0o600

# A credential filename is derived from the user's email, which on the OAuth 2.1
# tool surface is caller-supplied. Only accept addresses built from characters
# that cannot escape the store directory or alter the resolved path. '/' and '\\'
# are deliberately excluded even though '/' is legal in an RFC 5322 local part,
# because the value is used as a path component.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+=?^_`{|}~.-]+@[A-Za-z0-9.-]+$")


class CredentialStoreError(ValueError):
    """Raised when a credential store operation is rejected as unsafe."""


def is_valid_user_email(user_email: str) -> bool:
    """
    Return True if user_email is a plain email address safe to use as a filename.

    Shared with the auth layer so the /mcp trust boundary and the credential
    store agree on what a valid principal looks like. A bare `'@' in value`
    check is not sufficient — it accepts path-traversal payloads such as
    '../../../tmp/oauth@stash'.
    """
    if not user_email or not isinstance(user_email, str):
        return False
    if not _EMAIL_RE.fullmatch(user_email):
        return False
    return os.path.basename(user_email) == user_email and not user_email.startswith(".")


class CredentialStore(ABC):
    """Abstract base class for credential storage."""

    @abstractmethod
    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """
        Get credentials for a user by email.

        Args:
            user_email: User's email address

        Returns:
            Google Credentials object or None if not found
        """
        pass

    @abstractmethod
    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """
        Store credentials for a user.

        Args:
            user_email: User's email address
            credentials: Google Credentials object to store

        Returns:
            True if successfully stored, False otherwise
        """
        pass

    @abstractmethod
    def delete_credential(self, user_email: str) -> bool:
        """
        Delete credentials for a user.

        Args:
            user_email: User's email address

        Returns:
            True if successfully deleted, False otherwise
        """
        pass

    @abstractmethod
    def list_users(self) -> List[str]:
        """
        List all users with stored credentials.

        Returns:
            List of user email addresses
        """
        pass


class LocalDirectoryCredentialStore(CredentialStore):
    """Credential store that uses local JSON files for storage."""

    def __init__(self, base_dir: Optional[str] = None):
        """
        Initialize the local JSON credential store.

        Args:
            base_dir: Base directory for credential files. If None, uses the directory
                     configured by the GOOGLE_MCP_CREDENTIALS_DIR environment variable,
                     or defaults to ~/.google_workspace_mcp/credentials if the environment
                     variable is not set.
        """
        if base_dir is None:
            if os.getenv("GOOGLE_MCP_CREDENTIALS_DIR"):
                base_dir = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")
            else:
                home_dir = os.path.expanduser("~")
                if home_dir and home_dir != "~":
                    base_dir = os.path.join(
                        home_dir, ".google_workspace_mcp", "credentials"
                    )
                else:
                    base_dir = os.path.join(os.getcwd(), ".credentials")

        self.base_dir = base_dir
        self._perms_swept = False
        logger.info(f"LocalJsonCredentialStore initialized with base_dir: {base_dir}")

    @staticmethod
    def _validate_user_email(user_email: str) -> str:
        """
        Reject any user_email that cannot safely be used as a path component.

        The value reaches this store straight from tool arguments on the /mcp
        surface, so a bare `'@' in user_email` check is not sufficient — it is
        satisfied by payloads like '../../../tmp/oauth@stash'.

        Raises:
            CredentialStoreError: if the value is not a plain email address.
        """
        if not user_email or not isinstance(user_email, str):
            raise CredentialStoreError("user_email must be a non-empty string")

        if not is_valid_user_email(user_email):
            raise CredentialStoreError(
                "user_email is not a valid email address and cannot be used "
                "as a credential filename"
            )

        return user_email

    def _ensure_base_dir(self) -> None:
        """Create the credential directory owner-only, and tighten it if it exists."""
        if not os.path.isdir(self.base_dir):
            # mode= is subject to umask, so chmod explicitly afterwards.
            os.makedirs(self.base_dir, mode=_CREDENTIAL_DIR_MODE, exist_ok=True)
            logger.info(f"Created credentials directory: {self.base_dir}")

        try:
            current = stat.S_IMODE(os.stat(self.base_dir).st_mode)
            if current & 0o077:
                os.chmod(self.base_dir, _CREDENTIAL_DIR_MODE)
                logger.warning(
                    f"Tightened permissions on credentials directory {self.base_dir} "
                    f"from {current:04o} to {_CREDENTIAL_DIR_MODE:04o}"
                )
        except OSError as e:
            logger.error(f"Could not verify permissions on {self.base_dir}: {e}")

        self._tighten_existing_files()

    def _tighten_existing_files(self) -> None:
        """
        Re-permission credential files left world-readable by earlier versions.

        Runs at most once per store instance. Files written before this fix were
        created 0644, so upgrading the code alone would leave already-issued
        refresh_tokens and the client_secret readable by every local user.
        """
        if self._perms_swept:
            return
        self._perms_swept = True

        try:
            entries = os.listdir(self.base_dir)
        except OSError as e:
            logger.error(f"Could not scan {self.base_dir} for stale permissions: {e}")
            return

        for filename in entries:
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.base_dir, filename)
            try:
                if not os.path.isfile(path):
                    continue
                current = stat.S_IMODE(os.stat(path).st_mode)
                if current & 0o077:
                    os.chmod(path, _CREDENTIAL_FILE_MODE)
                    logger.warning(
                        f"Tightened permissions on {path} from {current:04o} to "
                        f"{_CREDENTIAL_FILE_MODE:04o}. This credential was previously "
                        f"readable by other local users; rotating it is recommended."
                    )
            except OSError as e:
                logger.error(f"Could not tighten permissions on {path}: {e}")

    def _get_credential_path(self, user_email: str) -> str:
        """
        Get the file path for a user's credentials.

        Raises:
            CredentialStoreError: if user_email is unsafe or the resolved path
                would fall outside the credential directory.
        """
        user_email = self._validate_user_email(user_email)
        self._ensure_base_dir()

        creds_path = os.path.join(self.base_dir, f"{user_email}.json")

        # Final containment check: resolve symlinks and confirm the result is
        # still inside the store directory.
        base_real = os.path.realpath(self.base_dir)
        creds_real = os.path.realpath(creds_path)
        if os.path.dirname(creds_real) != base_real:
            raise CredentialStoreError(
                "resolved credential path escapes the credential directory"
            )

        return creds_path

    def get_credential(self, user_email: str) -> Optional[Credentials]:
        """Get credentials from local JSON file."""
        try:
            creds_path = self._get_credential_path(user_email)
        except CredentialStoreError as e:
            logger.warning(f"Rejected credential lookup for {user_email!r}: {e}")
            return None

        if not os.path.exists(creds_path):
            logger.debug(f"No credential file found for {user_email} at {creds_path}")
            return None

        try:
            with open(creds_path, "r") as f:
                creds_data = json.load(f)

            # Parse expiry if present
            expiry = None
            if creds_data.get("expiry"):
                try:
                    expiry = datetime.fromisoformat(creds_data["expiry"])
                    # Ensure timezone-naive datetime for Google auth library compatibility
                    if expiry.tzinfo is not None:
                        expiry = expiry.replace(tzinfo=None)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse expiry time for {user_email}: {e}")

            credentials = Credentials(
                token=creds_data.get("token"),
                refresh_token=creds_data.get("refresh_token"),
                token_uri=creds_data.get("token_uri"),
                client_id=creds_data.get("client_id"),
                client_secret=creds_data.get("client_secret"),
                scopes=creds_data.get("scopes"),
                expiry=expiry,
            )

            logger.debug(f"Loaded credentials for {user_email} from {creds_path}")
            return credentials

        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.error(
                f"Error loading credentials for {user_email} from {creds_path}: {e}"
            )
            return None

    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        """Store credentials to local JSON file with owner-only permissions."""
        try:
            creds_path = self._get_credential_path(user_email)
        except CredentialStoreError as e:
            logger.warning(f"Rejected credential store for {user_email!r}: {e}")
            return False

        creds_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
        }

        # Write to a temp file in the same directory with owner-only permissions,
        # then atomically rename into place. This keeps the secret off disk with
        # a permissive mode even briefly, and avoids a truncated file if the
        # process dies mid-write. mkstemp() creates the file 0600 regardless of umask.
        tmp_fd, tmp_path = None, None
        try:
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=os.path.dirname(creds_path), prefix=".cred-", suffix=".tmp"
            )
            with os.fdopen(tmp_fd, "w") as f:
                tmp_fd = None  # now owned by the file object
                json.dump(creds_data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.chmod(tmp_path, _CREDENTIAL_FILE_MODE)
            os.replace(tmp_path, creds_path)
            tmp_path = None

            logger.info(f"Stored credentials for {user_email} to {creds_path}")
            return True
        except OSError as e:
            logger.error(
                f"Error storing credentials for {user_email} to {creds_path}: {e}"
            )
            return False
        finally:
            if tmp_fd is not None:
                os.close(tmp_fd)
            if tmp_path is not None and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def delete_credential(self, user_email: str) -> bool:
        """Delete credential file for a user."""
        try:
            creds_path = self._get_credential_path(user_email)
        except CredentialStoreError as e:
            logger.warning(f"Rejected credential delete for {user_email!r}: {e}")
            return False

        try:
            if os.path.exists(creds_path):
                os.remove(creds_path)
                logger.info(f"Deleted credentials for {user_email} from {creds_path}")
                return True
            else:
                logger.debug(
                    f"No credential file to delete for {user_email} at {creds_path}"
                )
                return True  # Consider it a success if file doesn't exist
        except IOError as e:
            logger.error(
                f"Error deleting credentials for {user_email} from {creds_path}: {e}"
            )
            return False

    def list_users(self) -> List[str]:
        """List all users with credential files."""
        if not os.path.exists(self.base_dir):
            return []

        users = []
        try:
            for filename in os.listdir(self.base_dir):
                if filename.endswith(".json"):
                    user_email = filename[:-5]  # Remove .json extension
                    users.append(user_email)
            logger.debug(
                f"Found {len(users)} users with credentials in {self.base_dir}"
            )
        except OSError as e:
            logger.error(f"Error listing credential files in {self.base_dir}: {e}")

        return sorted(users)


# Global credential store instance
_credential_store: Optional[CredentialStore] = None


def get_credential_store() -> CredentialStore:
    """
    Get the global credential store instance.

    Returns:
        Configured credential store instance
    """
    global _credential_store

    if _credential_store is None:
        # always use LocalJsonCredentialStore as the default
        # Future enhancement: support other backends via environment variables
        _credential_store = LocalDirectoryCredentialStore()
        logger.info(f"Initialized credential store: {type(_credential_store).__name__}")

    return _credential_store


def set_credential_store(store: CredentialStore):
    """
    Set the global credential store instance.

    Args:
        store: Credential store instance to use
    """
    global _credential_store
    _credential_store = store
    logger.info(f"Set credential store: {type(store).__name__}")
