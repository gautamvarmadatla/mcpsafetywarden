"""Egress decision engine: reserved-range blocking and allowlist matching.

Security-critical. Naive string checks on IPs are bypassable via octal, hex,
integer, and short-form encodings, IPv4-mapped IPv6, zone ids, trailing dots,
and non-ASCII digits. This module canonicalises a host to every IP it could mean
and blocks if any is reserved. resolve_targets defends against DNS rebinding by
re-checking the actually-resolved address before a connection is made.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Tuple

from .profile import HostRule

METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})


def normalize_host(host: str) -> str:
    h = (host or "").strip().strip("[]")
    if "%" in h:
        h = h.split("%", 1)[0]
    return h.rstrip(".")


def parse_ipv4_relaxed(host: str) -> Optional[ipaddress.IPv4Address]:
    """Expand octal/hex/decimal/short-form IPv4 the way inet_aton would."""
    s = normalize_host(host)
    if not s or "/" in s or " " in s or not s.isascii():
        return None
    parts = s.split(".")
    if len(parts) > 4:
        return None
    try:
        nums = [_parse_int_part(p) for p in parts]
    except ValueError:
        return None
    if any(n is None for n in nums):
        return None

    if len(nums) == 1:
        value = nums[0]
    elif len(nums) == 2:
        if nums[0] > 0xFF or nums[1] > 0xFFFFFF:
            return None
        value = (nums[0] << 24) | nums[1]
    elif len(nums) == 3:
        if nums[0] > 0xFF or nums[1] > 0xFF or nums[2] > 0xFFFF:
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | nums[2]
    else:
        if any(n > 0xFF for n in nums):
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]

    if value < 0 or value > 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Address(value)


def _parse_int_part(p: str) -> Optional[int]:
    if p == "" or not p.isascii():
        return None
    low = p.lower()
    if low.startswith("0x"):
        return int(low, 16)
    if p.startswith("0") and len(p) > 1:
        return int(p, 8)
    if not p.isdigit():
        raise ValueError(p)
    return int(p, 10)


def candidate_ips(host: str) -> List[ipaddress._BaseAddress]:
    """Every IP the host string could resolve to without DNS."""
    out: List[ipaddress._BaseAddress] = []
    h = normalize_host(host)
    try:
        ip6 = ipaddress.IPv6Address(h)
        out.append(ip6)
        mapped = getattr(ip6, "ipv4_mapped", None)
        if mapped is not None:
            out.append(mapped)
        return out
    except ipaddress.AddressValueError:
        pass
    relaxed = parse_ipv4_relaxed(h)
    if relaxed is not None:
        out.append(relaxed)
    return out


_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def is_reserved_ip(ip: ipaddress._BaseAddress) -> bool:
    if str(ip) in METADATA_IPS:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT_V4:
        return True
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def is_ip_literal(host: str) -> bool:
    return len(candidate_ips(host)) > 0


def resolve_targets(host: str, port: int, block_reserved: bool = True):
    """Resolve host and return only sockaddrs whose IP is not reserved.

    Connecting to one of these instead of re-resolving defeats DNS rebinding.
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    except OSError:
        return []
    safe = []
    for family, socktype, proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0].split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if block_reserved and is_reserved_ip(addr):
            continue
        safe.append((family, socktype, proto, sockaddr))
    return safe


def _host_matches_rule(host: str, rule_host: str) -> bool:
    host = normalize_host(host).lower()
    rule = rule_host.lower().rstrip(".")
    if not host or ".." in host or host.startswith(".") or any(c in host for c in "#@ /?"):
        return False
    if rule.startswith("*."):
        suffix = rule[1:]
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == rule


def decide(
    host: str,
    port: Optional[int],
    allow: List[HostRule],
    block_reserved: bool = True,
    default: str = "deny",
) -> Tuple[bool, str]:
    """Return (allowed, reason)."""
    host = normalize_host(host)
    if not host:
        return False, "empty host"

    if block_reserved:
        for ip in candidate_ips(host):
            if is_reserved_ip(ip):
                return False, f"reserved/metadata address ({ip})"

    for rule in allow:
        if _host_matches_rule(host, rule.host):
            if rule.ports and port is not None and port not in rule.ports:
                continue
            return True, f"allowlisted ({rule.host})"

    if default == "allow":
        return True, "default allow"
    return False, "not in allowlist"
