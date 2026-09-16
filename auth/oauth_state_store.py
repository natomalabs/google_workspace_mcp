"""
Server-side store for in-flight OAuth authorization attempts.

The legacy (OAuth 2.0) authorization flow generates a ``state`` value and a PKCE
``code_verifier`` when it builds the Google authorization URL, but the token
exchange happens later, in a different function, on a different HTTP request.
Both values therefore have to be held server-side in between, keyed by ``state``.

Without this store the flow was broken in two ways (SNOW-3697295):

* the ``code_verifier`` was discarded, so although ``authorization_url()``
  sent a ``code_challenge``, the token exchange never proved possession of the
  matching verifier — PKCE was half-implemented and provided no protection;
* the generated ``state`` was never persisted, so it could not be verified on
  the way back. oauthlib only checks ``state`` when it is given an expected
  value, and it was given ``None``.

Entries are single-use and time-limited: consuming one removes it, so a captured
callback URL cannot be replayed.

Scope note: this is an in-process store, which matches the legacy flow's existing
constraints (that flow already keeps credentials in process memory and on the
local filesystem, and stateless mode requires OAuth 2.1). A server restart
invalidates in-flight authorizations, and the user simply re-runs the auth step.
"""

import logging
import os
import time
from threading import RLock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# How long a user has to complete the Google consent screen before the pending
# authorization expires.
DEFAULT_TTL_SECONDS = 600

# Upper bound on concurrently pending authorizations. Each entry is created by an
# unauthenticated caller triggering an auth prompt, so the store must not grow
# without limit. Oldest entries are evicted first.
DEFAULT_MAX_ENTRIES = 256


class OAuthStateStore:
    """Thread-safe, TTL-bounded, single-use store of pending OAuth attempts."""

    def __init__(
        self,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._pending: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    @staticmethod
    def new_state() -> str:
        """Generate an unguessable state value."""
        return os.urandom(32).hex()

    def put(
        self,
        state: str,
        code_verifier: Optional[str],
        redirect_uri: str,
        scopes: List[str],
    ) -> None:
        """Record a pending authorization keyed by its state value."""
        if not state:
            raise ValueError("state must be a non-empty string")

        with self._lock:
            self._prune_locked()

            if len(self._pending) >= self._max_entries:
                # Evict the oldest entry rather than refusing new authorizations,
                # so a flood of abandoned attempts cannot lock out real users.
                oldest = min(
                    self._pending, key=lambda k: self._pending[k]["created_at"]
                )
                del self._pending[oldest]
                logger.warning(
                    "Pending OAuth state store is full (%d entries); evicted the "
                    "oldest pending authorization.",
                    self._max_entries,
                )

            self._pending[state] = {
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "scopes": list(scopes or []),
                "created_at": time.monotonic(),
            }
            logger.debug(
                "Recorded pending OAuth authorization (%d now pending)",
                len(self._pending),
            )

    def consume(self, state: str) -> Optional[Dict[str, Any]]:
        """
        Atomically look up and remove a pending authorization.

        Returns None if the state is unknown, already used, or expired — all of
        which must be treated as authorization failures by the caller.
        """
        if not state:
            return None

        with self._lock:
            self._prune_locked()
            record = self._pending.pop(state, None)

        if record is None:
            logger.warning(
                "OAuth callback presented an unknown, expired or already-used state value"
            )
        return record

    def __len__(self) -> int:
        with self._lock:
            self._prune_locked()
            return len(self._pending)

    def clear(self) -> None:
        with self._lock:
            self._pending.clear()

    def _prune_locked(self) -> None:
        """Drop expired entries. Caller must hold the lock."""
        now = time.monotonic()
        expired = [
            state
            for state, record in self._pending.items()
            if now - record["created_at"] > self._ttl
        ]
        for state in expired:
            del self._pending[state]
        if expired:
            logger.debug("Pruned %d expired pending OAuth authorization(s)", len(expired))


_state_store: Optional[OAuthStateStore] = None
_state_store_lock = RLock()


def get_oauth_state_store() -> OAuthStateStore:
    """Get the process-wide pending-authorization store."""
    global _state_store
    with _state_store_lock:
        if _state_store is None:
            _state_store = OAuthStateStore()
        return _state_store
