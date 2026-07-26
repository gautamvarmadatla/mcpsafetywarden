"""Credential broker: resolves secret refs and injects them at the edge.

The sandboxed server never receives raw secret values. Values are resolved
outside the sandbox and applied at the egress boundary (headers) or injected as
scoped env only when a rule explicitly requests it.
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Dict, List, Optional

from .netfilter import _host_matches_rule
from .profile import SecretRule

_log = logging.getLogger(__name__)

_resolver: Optional[Callable[[str], Optional[str]]] = None


def set_secret_resolver(fn: Callable[[str], Optional[str]]) -> None:
    global _resolver
    _resolver = fn


def resolve(ref: str) -> Optional[str]:
    if _resolver is not None:
        try:
            value = _resolver(ref)
            if value is not None:
                return value
        except Exception:
            pass
    try:
        from ..core.database import resolve_credential_ref

        value = resolve_credential_ref(ref)
        if value is not None:
            return value
    except Exception:
        pass
    return os.environ.get(ref)


def _sanitize(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def _render(rule: SecretRule) -> Optional[str]:
    secret = resolve(rule.ref)
    if secret is None:
        return None
    secret = _sanitize(secret)
    try:
        return _sanitize(rule.template.format(secret=secret))
    except (KeyError, IndexError, ValueError):
        _log.warning("secret template for ref '%s' is malformed; skipping injection", rule.ref)
        return None


def header_injections(secrets: List[SecretRule], dest_host: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rule in secrets:
        if rule.inject_as != "header" or not rule.name:
            continue
        if rule.to and not _host_matches_rule(dest_host, rule.to):
            continue
        rendered = _render(rule)
        if rendered is not None:
            out[rule.name] = rendered
    return out


def env_injections(secrets: List[SecretRule]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rule in secrets:
        if rule.inject_as != "env" or not rule.name:
            continue
        rendered = _render(rule)
        if rendered is not None:
            out[rule.name] = rendered
    return out


def query_injections(secrets: List[SecretRule], dest_host: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for rule in secrets:
        if rule.inject_as != "query" or not rule.name:
            continue
        if rule.to and not _host_matches_rule(dest_host, rule.to):
            continue
        rendered = _render(rule)
        if rendered is not None:
            out[rule.name] = rendered
    return out
