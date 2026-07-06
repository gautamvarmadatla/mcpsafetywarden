"""Orchestration: turn a server + profile into a sandboxed spawn.

Builds the scrubbed environment, starts the egress proxy, selects the strongest
available backend, and yields the wrapped command/args/env. Cleans up on exit.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from . import backends, broker, learning
from .egress import EgressPolicy, EgressProxy
from .profile import DEFAULT_SECRET_ENV_PATTERNS, SandboxProfile, from_dict

_log = logging.getLogger(__name__)


def load_profile(server: Dict[str, Any]) -> Optional[SandboxProfile]:
    raw = server.get("sandbox")
    if raw:
        profile = from_dict(raw if isinstance(raw, dict) else {})
        if not profile.name:
            profile.name = str(server.get("server_id", "unnamed"))
        if not profile.target.get("transport"):
            profile.target["transport"] = server.get("transport", "stdio")
        return profile
    if os.environ.get("MCP_SANDBOX", "").lower() in ("1", "strict", "on", "true"):
        profile = from_dict(
            {"name": str(server.get("server_id", "unnamed")), "target": {"transport": server.get("transport", "stdio")}}
        )
        return profile
    return None


def _is_secret_name(name: str) -> bool:
    upper = name.upper()
    return any(fnmatch.fnmatch(upper, pat) for pat in DEFAULT_SECRET_ENV_PATTERNS)


def build_env(profile: SandboxProfile, base_env: Dict[str, str]) -> Dict[str, str]:
    env: Dict[str, str] = {}
    for name in profile.environment.allow:
        if name in base_env:
            env[name] = base_env[name]
    if profile.environment.scrub:
        env = {k: v for k, v in env.items() if not _is_secret_name(k) or k in profile.environment.set}
    env.update(profile.environment.set)
    env.update(broker.env_injections(profile.secrets))
    return env


@contextmanager
def sandbox_session(
    command: str, args, base_env: Dict[str, str], profile: SandboxProfile
) -> Iterator[backends.WrappedSpawn]:
    env = build_env(profile, base_env)
    learn = profile.learning.mode in ("observe", "suggest")
    proxy: Optional[EgressProxy] = None
    if profile.transport() == "stdio":
        policy = EgressPolicy(profile.network, secrets=profile.secrets, record_observed=learn)
        proxy = EgressProxy(policy).start()
        env.update(proxy.proxy_env())
        _log.info("sandbox '%s': egress proxy at %s", profile.name, proxy.address)
    try:
        backend = backends.select_backend(profile)
        wrapped = backend.wrap(command, list(args or []), env, profile)
        if backend.name == "subprocess" and (profile.network.allow or profile.network.default == "deny"):
            _log.warning(
                "sandbox '%s': subprocess backend enforces egress by proxy env only (advisory); "
                "use bubblewrap/container/seatbelt for a server that may be hostile",
                profile.name,
            )
        _log.info("sandbox '%s': backend=%s %s", profile.name, wrapped.backend, "; ".join(wrapped.notes))
        _audit(profile, f"start backend={wrapped.backend}")
        yield wrapped
    finally:
        if proxy is not None:
            _audit(profile, f"egress decisions={len(proxy.policy.decisions)}")
            if learn and proxy.policy.observed_domains:
                suggested = learning.synthesize(profile, proxy.policy.observed_domains)
                learning.write_suggestion(profile, suggested)
            proxy.stop()


def _audit(profile: SandboxProfile, message: str) -> None:
    if not profile.audit.log:
        return
    path = profile.audit.path
    if not path:
        return
    try:
        expanded = os.path.expanduser(path)
        os.makedirs(os.path.dirname(expanded) or ".", exist_ok=True)
        with open(expanded, "a", encoding="utf-8") as fh:
            fh.write(f"[{profile.name}] {message}\n")
    except OSError:
        pass
