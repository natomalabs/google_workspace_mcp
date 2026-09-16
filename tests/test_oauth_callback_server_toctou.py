"""
Security regression tests for auth/oauth_callback_server.py.

Covers SNOW-3697295 [CWE-367]: the loopback port-bind TOCTOU. start() used to bind
a probe socket, close it, and then let uvicorn bind again later from a background
thread, accepting "something is listening" as success. A co-resident process could
win that gap and receive the victim's Google authorization code.
"""

import socket
import threading
import time

import pytest

from auth.oauth_callback_server import MinimalOAuthServer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server_factory():
    created = []

    def make(port, base_uri="http://localhost"):
        srv = MinimalOAuthServer(port=port, base_uri=base_uri)
        created.append(srv)
        return srv

    yield make

    for srv in created:
        try:
            srv.stop()
        except Exception:
            pass


# --- the squatter must lose ------------------------------------------------------


def test_start_fails_when_port_already_held(server_factory):
    """
    The attack precondition: another local process already owns the callback port.
    start() must refuse rather than report success against a foreign listener.
    """
    port = _free_port()

    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.bind(("127.0.0.1", port))
    squatter.listen(1)
    try:
        srv = server_factory(port, base_uri="http://127.0.0.1")
        ok, err = srv.start()

        assert ok is False, "start() reported success while an attacker held the port"
        assert srv.is_running is False
        assert "already in use" in err
    finally:
        squatter.close()


def test_start_does_not_accept_a_foreign_listener_as_readiness(server_factory):
    """
    The old readiness probe was connect_ex() == 0, which any listener satisfies.
    Readiness must be tied to our own uvicorn instance.
    """
    port = _free_port()

    # A listener that accepts connections but is not our server.
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.bind(("127.0.0.1", port))
    squatter.listen(5)

    stop = threading.Event()

    def accept_loop():
        squatter.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = squatter.accept()
                conn.close()
            except (socket.timeout, OSError):
                pass

    t = threading.Thread(target=accept_loop, daemon=True)
    t.start()
    try:
        srv = server_factory(port, base_uri="http://127.0.0.1")
        ok, err = srv.start()

        assert ok is False
        assert err != ""
    finally:
        stop.set()
        t.join(timeout=2)
        squatter.close()


def test_no_bind_release_window_between_check_and_use(server_factory):
    """
    Regression guard on the mechanism: start() must not bind-then-close a probe
    socket. A tight bind loop racing start() must never succeed in taking the port.
    """
    port = _free_port()
    srv = server_factory(port, base_uri="http://127.0.0.1")

    stolen = threading.Event()
    stop = threading.Event()

    def steal_loop():
        while not stop.is_set():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
                s.listen(1)
                stolen.set()
                s.close()
                return
            except OSError:
                s.close()
            time.sleep(0.0005)

    t = threading.Thread(target=steal_loop, daemon=True)
    t.start()
    try:
        ok, err = srv.start()
        # Either we started (and the squatter never got in), or we cleanly failed.
        # What must never happen is: we report success while the squatter holds it.
        if ok:
            assert stolen.is_set() is False, (
                "the attacker acquired the port while start() reported success"
            )
    finally:
        stop.set()
        t.join(timeout=2)


# --- happy path -----------------------------------------------------------------


def test_start_succeeds_on_a_free_port_and_serves(server_factory):
    port = _free_port()
    srv = server_factory(port, base_uri="http://127.0.0.1")

    ok, err = srv.start()

    assert ok is True, f"start() failed on a free port: {err}"
    assert err == ""
    assert srv.is_running is True

    # Confirm it is really our server answering.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(2)
        assert s.connect_ex(("127.0.0.1", port)) == 0


def test_start_is_idempotent(server_factory):
    port = _free_port()
    srv = server_factory(port, base_uri="http://127.0.0.1")

    assert srv.start()[0] is True
    assert srv.start() == (True, "")


def test_stop_releases_the_port(server_factory):
    port = _free_port()
    srv = server_factory(port, base_uri="http://127.0.0.1")
    assert srv.start()[0] is True

    srv.stop()
    assert srv.is_running is False

    # The port must be rebindable afterwards.
    deadline = time.time() + 5
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return
        except OSError:
            s.close()
            time.sleep(0.1)
    pytest.fail("port was not released after stop()")


def test_failed_start_releases_sockets(server_factory):
    """A failed start must not leak the bound sockets."""
    port = _free_port()
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    squatter.bind(("127.0.0.1", port))
    squatter.listen(1)
    try:
        srv = server_factory(port, base_uri="http://127.0.0.1")
        assert srv.start()[0] is False
    finally:
        squatter.close()

    # After the squatter leaves, the port is free again.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", port))
    finally:
        s.close()


def test_unresolvable_hostname_fails_cleanly(server_factory):
    srv = server_factory(_free_port(), base_uri="http://this-host-does-not-exist.invalid")

    ok, err = srv.start()

    assert ok is False
    assert err != ""
    assert srv.is_running is False


# --- mechanism guards -----------------------------------------------------------


def test_start_does_not_use_connect_ex_readiness():
    import inspect

    source = inspect.getsource(MinimalOAuthServer.start)

    assert "connect_ex" not in source, (
        "readiness must not be 'something is listening'; that is the TOCTOU sink"
    )
    assert "started" in source


def test_bind_sockets_does_not_set_reuseaddr():
    """SO_REUSEADDR would let us bind alongside a squatter instead of failing."""
    import inspect

    source = inspect.getsource(MinimalOAuthServer._bind_sockets)
    # Strip comments so the explanatory note about NOT setting these doesn't match.
    code = "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )

    assert "SO_REUSEADDR" not in code
    assert "SO_REUSEPORT" not in code


def test_bind_sockets_covers_all_address_families():
    """IPv6 must not be ignored: an attacker on ::1 would otherwise be undetected."""
    import inspect

    source = inspect.getsource(MinimalOAuthServer._bind_sockets)

    assert "getaddrinfo" in source
    assert "AF_INET6" in source
