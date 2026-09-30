import socket
from origo.endpoints import _SafeHTTPSConnection


def test_safe_https_connection_default_timeout_sentinel_dos():
    """
    self.timeout defaults to socket._GLOBAL_DEFAULT_TIMEOUT (a sentinel object,
    not a number). Passing it straight to sock.settimeout() raises a TypeError,
    which is the other half of the DoS this PR fixes alongside the missing
    _tunnel_host attribute.
    """
    conn = _SafeHTTPSConnection("example.com")
    assert conn.timeout is socket._GLOBAL_DEFAULT_TIMEOUT

    class MockSocket:
        def setsockopt(self, *args): pass
        def connect(self, *args): pass
        def close(self): pass
        def settimeout(self, *args):
            raise AssertionError("settimeout() must not be called with the default-timeout sentinel")

    class MockContext:
        def wrap_socket(self, sock, server_hostname=None):
            return sock

    conn._context = MockContext()

    original_getaddrinfo = socket.getaddrinfo
    original_socket = socket.socket

    try:
        socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        socket.socket = lambda *args: MockSocket()

        # This should not raise a TypeError, and must not call settimeout()
        # with the sentinel object.
        conn.connect()
    finally:
        socket.getaddrinfo = original_getaddrinfo
        socket.socket = original_socket


def test_safe_https_connection_no_tunnel_host_dos():
    """
    In Python 3.12+, http.client.HTTPSConnection does not initialize `_tunnel_host`
    if no proxy is used. Accessing `self._tunnel_host` directly raises an
    AttributeError which results in a DoS (500 Server Error).
    This test verifies that `_SafeHTTPSConnection` handles missing `_tunnel_host` safely.
    """
    conn = _SafeHTTPSConnection("example.com")

    # Simulate environment where `_tunnel_host` is missing (e.g. Python 3.12+)
    if hasattr(conn, "_tunnel_host"):
        del conn._tunnel_host

    class MockSocket:
        def setsockopt(self, *args): pass
        def connect(self, *args): pass
        def close(self): pass
        def settimeout(self, *args): pass

    class MockContext:
        def wrap_socket(self, sock, server_hostname=None):
            assert server_hostname == "example.com"
            return sock

    conn._context = MockContext()

    # Patch socket to avoid actual network calls
    original_getaddrinfo = socket.getaddrinfo
    original_socket = socket.socket

    try:
        socket.getaddrinfo = lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        socket.socket = lambda *args: MockSocket()

        # This should not raise an AttributeError
        conn.connect()
    finally:
        socket.getaddrinfo = original_getaddrinfo
        socket.socket = original_socket
