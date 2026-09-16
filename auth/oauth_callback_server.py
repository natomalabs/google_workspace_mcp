"""
Transport-aware OAuth callback handling.

In streamable-http mode: Uses the existing FastAPI server
In stdio mode: Starts a minimal HTTP server just for OAuth callbacks
"""

import asyncio
import logging
import threading
import time
import socket
import uvicorn

from fastapi import FastAPI, Request
from typing import Optional
from urllib.parse import urlparse

from auth.scopes import SCOPES, get_current_scopes # noqa
from auth.oauth_responses import create_error_response, create_success_response, create_server_error_response, new_error_reference
from auth.google_auth import handle_auth_callback, check_client_secrets
from auth.oauth_config import get_oauth_redirect_uri

logger = logging.getLogger(__name__)

class MinimalOAuthServer:
    """
    Minimal HTTP server for OAuth callbacks in stdio mode.
    Only starts when needed and uses the same port (8000) as streamable-http mode.
    """

    def __init__(self, port: int = 8000, base_uri: str = "http://localhost"):
        self.port = port
        self.base_uri = base_uri
        self.app = FastAPI()
        self.server = None
        self.server_thread = None
        self.is_running = False

        # Setup the callback route
        self._setup_callback_route()

    def _setup_callback_route(self):
        """Setup the OAuth callback route."""

        @self.app.get("/oauth2callback")
        async def oauth_callback(request: Request):
            """Handle OAuth callback - same logic as in core/server.py"""
            state = request.query_params.get("state")
            code = request.query_params.get("code")
            error = request.query_params.get("error")

            if error:
                # Attacker-controllable; log it but do not reflect it to the browser.
                logger.error(
                    f"Authentication failed: Google returned an error: {error!r}. State: {state!r}."
                )
                return create_error_response(
                    "Authentication failed: Google returned an error. "
                    "Please close this window and try again."
                )

            if not code:
                error_message = "Authentication failed: No authorization code received from Google."
                logger.error(error_message)
                return create_error_response(error_message)

            try:
                # Check if we have credentials available (environment variables or file)
                error_message = check_client_secrets()
                if error_message:
                    # Embeds CONFIG_CLIENT_SECRETS_PATH; log it, don't serve it.
                    reference = new_error_reference()
                    logger.error(
                        f"OAuth callback misconfiguration [{reference}]: {error_message}"
                    )
                    return create_server_error_response(reference)

                logger.info(f"OAuth callback: Received code (state: {state!r}). Attempting to exchange for tokens.")

                # Session ID tracking removed - not needed

                # Exchange code for credentials
                redirect_uri = get_oauth_redirect_uri()
                verified_user_id, credentials = handle_auth_callback(
                    scopes=get_current_scopes(),
                    authorization_response=str(request.url),
                    redirect_uri=redirect_uri,
                    session_id=None
                )

                logger.info(f"OAuth callback: Successfully authenticated user: {verified_user_id} (state: {state!r}).")

                # Return success page using shared template
                return create_success_response(verified_user_id)

            except Exception as e:
                # Never render str(e): library exception text embeds the request
                # URL, configured scopes and partial token-endpoint responses.
                reference = new_error_reference()
                logger.error(
                    f"Error processing OAuth callback [{reference}] (state: {state!r}): {str(e)}",
                    exc_info=True,
                )
                return create_server_error_response(reference)

    def start(self) -> tuple[bool, str]:
        """
        Start the minimal OAuth server.

        The port is bound once, up front, and the already-bound socket is handed to
        uvicorn. The previous implementation bound a probe socket, closed it, then
        let uvicorn bind again later from a background thread, and treated "something
        is listening on this port" as success. A co-resident unprivileged process
        running a tight bind() loop reliably won that gap, so the server would report
        success while the attacker owned the port — and then hand the user a Google
        consent URL whose redirect_uri pointed at the attacker's listener
        (SNOW-3697295). Holding the socket from check to use removes the window
        entirely: if we cannot bind, we fail.

        Returns:
            Tuple of (success: bool, error_message: str)
        """
        if self.is_running:
            logger.info("Minimal OAuth server is already running")
            return True, ""

        # Extract hostname from base_uri (e.g., "http://localhost" -> "localhost")
        try:
            parsed_uri = urlparse(self.base_uri)
            hostname = parsed_uri.hostname or 'localhost'
        except Exception:
            hostname = 'localhost'

        # Bind every address family the hostname resolves to, so that an attacker
        # squatting on ::1 while we bind 127.0.0.1 (or vice versa) cannot receive
        # the callback on a dual-stack host.
        sockets, error_msg = self._bind_sockets(hostname)
        if not sockets:
            logger.error(error_msg)
            return False, error_msg

        startup_error: list[str] = []

        def run_server():
            """Run the server in a separate thread using the pre-bound sockets."""
            try:
                config = uvicorn.Config(
                    self.app,
                    log_level="warning",
                    access_log=False
                )
                self.server = uvicorn.Server(config)
                # serve(sockets=...) adopts the sockets we already hold, so the
                # port is never released between the bind and the listen.
                asyncio.run(self.server.serve(sockets=sockets))

            except Exception as e:
                logger.error(f"Minimal OAuth server error: {e}", exc_info=True)
                startup_error.append(str(e))
                self.is_running = False

        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()

        # Readiness must confirm that *our* server is serving, not merely that some
        # process is listening on the port. uvicorn sets Server.started once its
        # startup completes.
        max_wait = 5.0
        deadline = time.time() + max_wait
        while time.time() < deadline:
            if startup_error:
                msg = (
                    f"Minimal OAuth server failed to start on {hostname}:{self.port}: "
                    f"{startup_error[0]}"
                )
                logger.error(msg)
                self._close_sockets(sockets)
                return False, msg

            if self.server is not None and getattr(self.server, "started", False):
                self.is_running = True
                logger.info(f"Minimal OAuth server started on {hostname}:{self.port}")
                return True, ""

            time.sleep(0.05)

        error_msg = (
            f"Failed to start minimal OAuth server on {hostname}:{self.port} - "
            f"server did not report readiness within {max_wait}s"
        )
        logger.error(error_msg)
        self._close_sockets(sockets)
        return False, error_msg

    def _bind_sockets(self, hostname: str) -> tuple[list, str]:
        """
        Bind and listen on every address family ``hostname`` resolves to.

        Returns:
            Tuple of (sockets, error_message). ``sockets`` is empty on failure.
        """
        try:
            addr_infos = socket.getaddrinfo(
                hostname, self.port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
            )
        except socket.gaierror as e:
            return [], f"Could not resolve {hostname}: {e}"

        # Deduplicate by (family, sockaddr); getaddrinfo often repeats entries.
        seen = set()
        sockets = []
        for family, socktype, proto, _canonname, sockaddr in addr_infos:
            key = (family, sockaddr)
            if key in seen:
                continue
            seen.add(key)

            sock = socket.socket(family, socktype, proto)
            try:
                # Deliberately NOT setting SO_REUSEADDR/SO_REUSEPORT: we want the
                # bind to fail loudly if anything else already holds this port.
                if family == socket.AF_INET6:
                    # Bind v6 only, so the v4 socket below is not shadowed by a
                    # dual-stack v6 socket (and vice versa).
                    try:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    except (AttributeError, OSError):
                        pass
                sock.bind(sockaddr)
                sock.listen(128)
                sock.set_inheritable(True)
            except OSError as e:
                sock.close()
                self._close_sockets(sockets)
                return [], (
                    f"Port {self.port} is already in use on {hostname} "
                    f"({sockaddr}): {e}. Cannot start minimal OAuth server. "
                    f"Another process may be squatting the OAuth callback port."
                )
            sockets.append(sock)

        if not sockets:
            return [], f"No usable address found for {hostname}:{self.port}"

        return sockets, ""

    @staticmethod
    def _close_sockets(sockets) -> None:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

    def stop(self):
        """Stop the minimal OAuth server."""
        if not self.is_running:
            return

        try:
            if self.server:
                if hasattr(self.server, 'should_exit'):
                    self.server.should_exit = True

            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=3.0)

            self.is_running = False
            logger.info("Minimal OAuth server stopped")

        except Exception as e:
            logger.error(f"Error stopping minimal OAuth server: {e}", exc_info=True)


# Global instance for stdio mode
_minimal_oauth_server: Optional[MinimalOAuthServer] = None

def ensure_oauth_callback_available(transport_mode: str = "stdio", port: int = 8000, base_uri: str = "http://localhost") -> tuple[bool, str]:
    """
    Ensure OAuth callback endpoint is available for the given transport mode.

    For streamable-http: Assumes the main server is already running
    For stdio: Starts a minimal server if needed

    Args:
        transport_mode: "stdio" or "streamable-http"
        port: Port number (default 8000)
        base_uri: Base URI (default "http://localhost")

    Returns:
        Tuple of (success: bool, error_message: str)
    """
    global _minimal_oauth_server

    if transport_mode == "streamable-http":
        # In streamable-http mode, the main FastAPI server should handle callbacks
        logger.debug("Using existing FastAPI server for OAuth callbacks (streamable-http mode)")
        return True, ""

    elif transport_mode == "stdio":
        # In stdio mode, start minimal server if not already running
        if _minimal_oauth_server is None:
            logger.info(f"Creating minimal OAuth server instance for {base_uri}:{port}")
            _minimal_oauth_server = MinimalOAuthServer(port, base_uri)

        if not _minimal_oauth_server.is_running:
            logger.info("Starting minimal OAuth server for stdio mode")
            success, error_msg = _minimal_oauth_server.start()
            if success:
                logger.info(f"Minimal OAuth server successfully started on {base_uri}:{port}")
                return True, ""
            else:
                logger.error(f"Failed to start minimal OAuth server on {base_uri}:{port}: {error_msg}")
                return False, error_msg
        else:
            logger.info("Minimal OAuth server is already running")
            return True, ""

    else:
        error_msg = f"Unknown transport mode: {transport_mode}"
        logger.error(error_msg)
        return False, error_msg

def cleanup_oauth_callback_server():
    """Clean up the minimal OAuth server if it was started."""
    global _minimal_oauth_server
    if _minimal_oauth_server:
        _minimal_oauth_server.stop()
        _minimal_oauth_server = None
