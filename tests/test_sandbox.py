"""Tests for the sandbox layer: profile model, egress decisions, backends, broker."""

import socket

import pytest

from mcpsafetywarden.sandbox import (
    SandboxUnavailable,
    build_env,
    from_dict,
    load_profile,
    select_backend,
    set_secret_resolver,
    validate,
)
from mcpsafetywarden.sandbox import broker, netfilter
from mcpsafetywarden.sandbox.backends import BubblewrapBackend, SubprocessBackend
from mcpsafetywarden.sandbox.egress import EgressPolicy, EgressProxy
from mcpsafetywarden.sandbox.profile import HostRule, Network


def test_defaults_are_strict():
    p = from_dict({})
    assert p.network.default == "deny"
    assert p.network.block_reserved is True
    assert p.environment.scrub is True
    assert p.assurance.on_unavailable == "block"
    assert p.enforcement.mode == "enforce"
    assert "~/.ssh" in p.filesystem.deny


def test_validate_catches_bad_fields():
    assert any("schema_version" in e for e in validate({"schema_version": "9.0"}))
    assert any("enforcement.mode" in e for e in validate({"enforcement": {"mode": "nope"}}))
    assert any("network.default" in e for e in validate({"network": {"default": "maybe"}}))
    assert any("ref" in e for e in validate({"secrets": [{"inject_as": "header"}]}))
    assert validate({"name": "ok"}) == []


def test_tool_override_precedence():
    p = from_dict(
        {
            "network": {"allow": [{"host": "api.example.com"}]},
            "tools": {"nonet": {"network": {"default": "deny", "allow": []}}},
        }
    )
    assert len(p.network.allow) == 1
    effective = p.for_tool("nonet")
    assert effective.network.allow == []
    assert p.for_tool("other").network.allow[0].host == "api.example.com"


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.10",
        "172.16.5.5",
        "169.254.169.254",
        "2130706433",
        "0177.0.0.1",
        "0x7f.0.0.1",
        "127.1",
        "::1",
        "::ffff:169.254.169.254",
        "0.0.0.0",
    ],
)
def test_reserved_and_obfuscated_ips_blocked(host):
    allowed, reason = netfilter.decide(host, 443, [HostRule("anything.com")], block_reserved=True)
    assert allowed is False, f"{host} should be blocked but was allowed ({reason})"


def test_allowlist_and_wildcards():
    rules = [HostRule("api.example.com", [443]), HostRule("*.trusted.io")]
    assert netfilter.decide("api.example.com", 443, rules)[0] is True
    assert netfilter.decide("api.example.com", 80, rules)[0] is False
    assert netfilter.decide("a.trusted.io", 443, rules)[0] is True
    assert netfilter.decide("trusted.io", 443, rules)[0] is False
    assert netfilter.decide("evil.com", 443, rules)[0] is False


def test_default_allow_still_blocks_reserved():
    allowed, reason = netfilter.decide("169.254.169.254", 80, [], block_reserved=True, default="allow")
    assert allowed is False


def test_broker_header_and_env_injection():
    set_secret_resolver(lambda ref: "s3cr3t" if ref == "api_key" else None)
    p = from_dict(
        {
            "secrets": [
                {
                    "ref": "api_key",
                    "inject_as": "header",
                    "name": "Authorization",
                    "template": "Bearer {secret}",
                    "to": "api.example.com",
                },
                {"ref": "api_key", "inject_as": "env", "name": "API_KEY"},
            ]
        }
    )
    headers = broker.header_injections(p.secrets, "api.example.com")
    assert headers["Authorization"] == "Bearer s3cr3t"
    assert broker.header_injections(p.secrets, "other.com") == {}
    assert broker.env_injections(p.secrets)["API_KEY"] == "s3cr3t"
    set_secret_resolver(lambda ref: None)


def test_build_env_scrubs_secrets():
    p = from_dict({"environment": {"allow": ["PATH", "AWS_SECRET_ACCESS_KEY", "MYVAR"], "set": {"TZ": "UTC"}}})
    base = {"PATH": "/usr/bin", "AWS_SECRET_ACCESS_KEY": "leak", "MYVAR": "ok", "HOME": "/root"}
    env = build_env(p, base)
    assert env["PATH"] == "/usr/bin"
    assert env["MYVAR"] == "ok"
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["TZ"] == "UTC"
    assert "HOME" not in env


def test_backend_selection_and_fail_closed():
    p = from_dict({"assurance": {"required": "process"}})
    backend = select_backend(p)
    assert backend is not None

    strict = from_dict({"assurance": {"required": "microvm", "on_unavailable": "block"}})
    with pytest.raises(SandboxUnavailable):
        select_backend(strict)

    downgrade = from_dict({"assurance": {"required": "microvm", "on_unavailable": "downgrade"}})
    assert select_backend(downgrade) is not None


def test_subprocess_backend_passthrough():
    p = from_dict({})
    spawn = SubprocessBackend().wrap("python", ["-m", "server"], {"PATH": "/x"}, p)
    assert spawn.command == "python"
    assert spawn.args == ["-m", "server"]
    assert spawn.backend == "subprocess"


def test_bubblewrap_argv_shape():
    p = from_dict({"filesystem": {"workdir": "."}})
    spawn = BubblewrapBackend().wrap("python", ["-m", "server"], {}, p)
    assert "--die-with-parent" in spawn.args
    assert "--unshare-pid" in spawn.args
    assert spawn.args[-3:] == ["--", "python", "-m"] or spawn.args[-3:] == ["python", "-m", "server"]
    assert "python" in spawn.args and "server" in spawn.args


def test_load_profile_opt_in(monkeypatch):
    monkeypatch.delenv("MCP_SANDBOX", raising=False)
    assert load_profile({"server_id": "x", "transport": "stdio"}) is None
    assert load_profile({"server_id": "x", "transport": "stdio", "sandbox": {"name": "x"}}) is not None
    monkeypatch.setenv("MCP_SANDBOX", "strict")
    assert load_profile({"server_id": "x", "transport": "stdio"}) is not None


def test_egress_proxy_denies_reserved_connect():
    proxy = EgressProxy(EgressPolicy(Network(allow=[HostRule("example.com")]))).start()
    try:
        _, port = proxy._server.server_address[:2]
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"CONNECT 10.0.0.1:443 HTTP/1.1\r\nHost: 10.0.0.1:443\r\n\r\n")
        resp = s.recv(1024)
        s.close()
        assert b"403" in resp
    finally:
        proxy.stop()


def test_egress_proxy_denies_unlisted_connect():
    proxy = EgressProxy(EgressPolicy(Network(allow=[HostRule("example.com")], on_new_domain="deny"))).start()
    try:
        _, port = proxy._server.server_address[:2]
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(b"CONNECT evil.com:443 HTTP/1.1\r\nHost: evil.com:443\r\n\r\n")
        resp = s.recv(1024)
        s.close()
        assert b"403" in resp
    finally:
        proxy.stop()


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1.", "169.254.169.254.", "fe80::1%eth0", "[::1]", "１２７.0.0.1"],
)
def test_edgecase_hosts_not_treated_as_public(host):
    from mcpsafetywarden.sandbox import netfilter

    allowed, _ = netfilter.decide(host, 443, [HostRule("anything.com")], block_reserved=True)
    assert allowed is False


def test_split_hostport_ipv6_and_ipv4():
    from mcpsafetywarden.sandbox.egress import split_hostport

    assert split_hostport("[::1]:443", 443) == ("::1", 443)
    assert split_hostport("[2001:db8::5]:8443", 443) == ("2001:db8::5", 8443)
    assert split_hostport("example.com:8080", 443) == ("example.com", 8080)
    assert split_hostport("example.com", 443) == ("example.com", 443)


def test_safe_connect_rejects_rebind_to_reserved(monkeypatch):
    from mcpsafetywarden.sandbox import egress, netfilter

    monkeypatch.setattr(
        netfilter.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 80))],
    )
    with pytest.raises(OSError):
        egress._safe_connect("rebind.evil.com", 80, block_reserved=True)


def test_broker_strips_crlf():
    set_secret_resolver(lambda ref: "value\r\nX-Injected: evil" if ref == "k" else None)
    p = from_dict({"secrets": [{"ref": "k", "inject_as": "header", "name": "Authorization"}]})
    headers = broker.header_injections(p.secrets, "any.com")
    assert "\r" not in headers["Authorization"] and "\n" not in headers["Authorization"]
    set_secret_resolver(lambda ref: None)


def test_broker_query_injection():
    set_secret_resolver(lambda ref: "tok" if ref == "k" else None)
    p = from_dict({"secrets": [{"ref": "k", "inject_as": "query", "name": "api_key", "to": "api.example.com"}]})
    assert broker.query_injections(p.secrets, "api.example.com") == {"api_key": "tok"}
    assert broker.query_injections(p.secrets, "other.com") == {}
    set_secret_resolver(lambda ref: None)


def test_seatbelt_argv_shape():
    from mcpsafetywarden.sandbox.backends import SeatbeltBackend

    spawn = SeatbeltBackend().wrap("python", ["-m", "s"], {}, from_dict({"filesystem": {"workdir": "."}}))
    assert spawn.args[0] == "-p"
    assert "(deny default)" in spawn.args[1]
    assert spawn.args[-3:] == ["python", "-m", "s"]


def test_wasm_and_microvm_backends(monkeypatch):
    from mcpsafetywarden.sandbox.backends import MicroVMBackend, SandboxUnavailable, WasmBackend

    spawn = WasmBackend().wrap("tool.wasm", ["--flag"], {"X": "1"}, from_dict({}))
    assert spawn.args[:2] == ["run", "--dir"]
    assert "tool.wasm" in spawn.args
    with pytest.raises(SandboxUnavailable):
        WasmBackend().wrap("python", [], {}, from_dict({}))

    monkeypatch.setenv("MCP_SANDBOX_MICROVM_CMD", "krun run --root /r")
    spawn = MicroVMBackend().wrap("python", ["-m", "s"], {}, from_dict({}))
    assert spawn.command == "krun"
    assert spawn.args[:3] == ["run", "--root", "/r"] or spawn.args[0] == "run"
    assert "python" in spawn.args


def test_learning_synthesizes_allowlist():
    from mcpsafetywarden.sandbox import learning

    p = from_dict({"name": "x", "learning": {"mode": "suggest"}})
    suggested = learning.synthesize(p, {"api.example.com", "cdn.example.com"})
    hosts = {h["host"] for h in suggested["network"]["allow"]}
    assert hosts == {"api.example.com", "cdn.example.com"}
    assert suggested["network"]["default"] == "deny"
    assert suggested["enforcement"]["mode"] == "enforce"
