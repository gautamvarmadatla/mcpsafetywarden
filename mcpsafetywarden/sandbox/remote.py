"""Remote (sse/http) server verification: endpoint match, cert pinning, SSRF.

A remote MCP server cannot be process-sandboxed (we do not run it). The controls
that apply are: refuse to connect to an unexpected endpoint, pin its TLS
certificate against tampering/MITM, and refuse endpoints that resolve to
reserved/metadata ranges.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from typing import Any, Dict
from urllib.parse import urlsplit

from . import netfilter
from .profile import SandboxProfile

_log = logging.getLogger(__name__)


class RemoteVerificationError(RuntimeError):
    pass


def _cert_sha256(host: str, port: int) -> str:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return "sha256:" + hashlib.sha256(der or b"").hexdigest()


def verify_remote(server: Dict[str, Any], profile: SandboxProfile) -> None:
    res = profile.resources
    if profile.assurance.required != "process" or any(
        v is not None for v in (res.cpu, res.memory, res.wall_time, res.max_processes, res.max_open_files)
    ):
        _log.warning(
            "sandbox '%s': remote (%s) server cannot be process-sandboxed; assurance/resource/filesystem/syscall "
            "controls are ignored - only endpoint and cert pinning apply",
            profile.name,
            profile.transport(),
        )

    url = server.get("url")
    if not url:
        return
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    net = profile.network

    if net.block_reserved:
        for cand in netfilter.candidate_ips(host):
            if netfilter.is_reserved_ip(cand):
                raise RemoteVerificationError(f"remote endpoint {host} is a reserved address")
        if not netfilter.is_ip_literal(host) and not netfilter.resolve_targets(host, port, block_reserved=True):
            raise RemoteVerificationError(f"remote endpoint {host} resolves only to reserved addresses")

    if net.endpoint:
        ep = urlsplit(net.endpoint)
        ep_host = ep.hostname or ""
        ep_port = ep.port or (443 if ep.scheme == "https" else 80)
        if (ep_host.lower(), ep_port) != (host.lower(), port):
            raise RemoteVerificationError(f"remote endpoint {host}:{port} does not match pinned {ep_host}:{ep_port}")

    if net.pin_cert and parts.scheme == "https":
        try:
            actual = _cert_sha256(host, port)
        except OSError as exc:
            raise RemoteVerificationError(f"could not fetch cert for {host}: {exc}") from exc
        if actual.lower() != net.pin_cert.strip().lower():
            raise RemoteVerificationError(f"remote cert {actual} does not match pinned {net.pin_cert}")
    _log.info("sandbox '%s': remote endpoint %s verified", profile.name, host)
