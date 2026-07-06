"""Default-deny filtering egress proxy.

A local forwarding proxy that every sandboxed server's traffic is routed
through. Enforces the network policy (reserved-range block + domain allowlist),
brokers secret headers/query params into plaintext requests, records observed
domains for learning, logs every decision, and supports human-in-the-loop
approval of new domains.

Connections are made only to a resolved address that is re-checked against the
reserved ranges (defeating DNS rebinding). HTTPS is tunnelled via CONNECT: the
proxy allows/denies by target host but does not decrypt (header injection into
TLS needs the future intercept tier).
"""

from __future__ import annotations

import logging
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, List, Optional, Tuple
from urllib.parse import urlencode, urlsplit

from . import broker, netfilter
from .profile import HostRule, Network, SecretRule

_log = logging.getLogger(__name__)

ApprovalFn = Callable[[str, int], bool]

MAX_BODY_BYTES = 32 * 1024 * 1024


def split_hostport(authority: str, default_port: int) -> Tuple[str, int]:
    a = (authority or "").strip()
    if a.startswith("["):
        host, _, rest = a[1:].partition("]")
        port_s = rest[1:] if rest.startswith(":") else ""
    else:
        host, sep, port_s = a.rpartition(":")
        if not sep:
            host, port_s = port_s, ""
    return host, int(port_s) if port_s.isdigit() else default_port


class EgressPolicy:
    def __init__(
        self,
        network: Network,
        secrets: Optional[List[SecretRule]] = None,
        approval: Optional[ApprovalFn] = None,
        record_observed: bool = False,
    ) -> None:
        self.network = network
        self.secrets = secrets or []
        self.approval = approval
        self.record_observed = record_observed
        self.seen_new: set = set()
        self.decisions: List[tuple] = []
        self.observed_domains: set = set()

    def decide(self, host: str, port: Optional[int]) -> tuple:
        allowed, reason = netfilter.decide(
            host,
            port,
            self.network.allow,
            block_reserved=self.network.block_reserved,
            default=self.network.default,
        )
        if not allowed and reason == "not in allowlist":
            allowed, reason = self._handle_new_domain(host, port)
        self.decisions.append((host, port, allowed, reason))
        if self.record_observed and not netfilter.is_ip_literal(host):
            self.observed_domains.add(netfilter.normalize_host(host).lower())
        _log.info("egress %s %s:%s (%s)", "ALLOW" if allowed else "DENY", host, port, reason)
        return allowed, reason

    def _handle_new_domain(self, host: str, port: Optional[int]) -> tuple:
        mode = self.network.on_new_domain
        if mode == "allow_once":
            return True, "new domain allowed once"
        if mode == "ask" and self.approval is not None:
            key = (host, port)
            if key not in self.seen_new:
                self.seen_new.add(key)
                try:
                    if self.approval(host, port or 0):
                        self.network.allow.append(HostRule(host=host, ports=[port] if port else []))
                        return True, "approved by user"
                except Exception:
                    pass
        return False, "not in allowlist"


def _safe_connect(host: str, port: int, block_reserved: bool, timeout: int = 15) -> socket.socket:
    targets = netfilter.resolve_targets(host, port, block_reserved=block_reserved)
    if not targets:
        raise OSError("no non-reserved address for host")
    last: Optional[OSError] = None
    for family, socktype, proto, sockaddr in targets:
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError as exc:
            last = exc
            continue
    raise last or OSError("connect failed")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def policy(self) -> EgressPolicy:
        return self.server.policy

    def log_message(self, fmt, *args):
        return

    def _deny(self, host: str, reason: str) -> None:
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Connection", "close")
        body = f"egress blocked: {host} ({reason})".encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_CONNECT(self) -> None:
        host, port = split_hostport(self.path, 443)
        allowed, reason = self.policy.decide(host, port)
        if not allowed:
            self._deny(host, reason)
            return
        try:
            upstream = _safe_connect(host, port, self.policy.network.block_reserved)
        except OSError as exc:
            self._deny(host, f"connect failed: {exc}")
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        _tunnel(self.connection, upstream)

    def _handle_forward(self) -> None:
        parts = urlsplit(self.path)
        host = parts.hostname or ""
        port = parts.port or 80
        allowed, reason = self.policy.decide(host, port)
        if not allowed:
            self._deny(host, reason)
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_BYTES:
            self._deny(host, "request body exceeds limit")
            return
        body = self.rfile.read(length) if length else None

        headers = {k: v for k, v in self.headers.items() if k.lower() != "proxy-connection"}
        headers.update(broker.header_injections(self.policy.secrets, host))

        path = parts.path or "/"
        query = parts.query
        extra_q = broker.query_injections(self.policy.secrets, host)
        if extra_q:
            joined = urlencode(extra_q)
            query = f"{query}&{joined}" if query else joined
        if query:
            path = f"{path}?{query}"

        try:
            upstream = _safe_connect(host, port, self.policy.network.block_reserved)
            conn = _HTTPOnSocket(host, upstream)
            conn.request(self.command, path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read(MAX_BODY_BYTES + 1)
        except OSError as exc:
            self._deny(host, f"forward failed: {exc}")
            return
        if len(data) > MAX_BODY_BYTES:
            self._deny(host, "response exceeds limit")
            return

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in ("transfer-encoding", "connection", "content-length"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(data)
        except OSError:
            pass

    do_GET = _handle_forward
    do_POST = _handle_forward
    do_PUT = _handle_forward
    do_DELETE = _handle_forward
    do_PATCH = _handle_forward
    do_HEAD = _handle_forward


class _HTTPOnSocket:
    """Minimal HTTP/1.1 client over an already-vetted socket (no re-resolution)."""

    def __init__(self, host: str, sock: socket.socket) -> None:
        import http.client

        self._conn = http.client.HTTPConnection(host)
        self._conn.sock = sock

    def request(self, method, path, body=None, headers=None):
        self._conn.request(method, path, body=body, headers=headers or {})

    def getresponse(self):
        return self._conn.getresponse()


def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
    sockets = [client, upstream]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional or not readable:
                break
            for sock in readable:
                other = upstream if sock is client else client
                data = sock.recv(65536)
                if not data:
                    return
                other.sendall(data)
    except OSError:
        return
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


class EgressProxy:
    def __init__(self, policy: EgressPolicy, host: str = "127.0.0.1", port: int = 0) -> None:
        self.policy = policy
        self._server = ThreadingHTTPServer((host, port), _Handler)
        self._server.policy = policy
        self._server.daemon_threads = True
        self._thread: Optional[threading.Thread] = None

    @property
    def address(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "EgressProxy":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass

    def proxy_env(self) -> dict:
        addr = self.address
        return {"HTTP_PROXY": addr, "HTTPS_PROXY": addr, "http_proxy": addr, "https_proxy": addr, "ALL_PROXY": addr}
