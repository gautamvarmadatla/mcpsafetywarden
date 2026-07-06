"""Observe-mode learning: propose a tight profile from observed behaviour.

Run a server in observe mode, watch which domains it actually reaches, then
synthesise the minimal network allowlist. The proposal is written for review;
it is never auto-enforced.
"""

from __future__ import annotations

import copy
import json
import logging
import os
from typing import Any, Dict, Iterable

from .profile import SandboxProfile

_log = logging.getLogger(__name__)


def synthesize(profile: SandboxProfile, observed_domains: Iterable[str]) -> Dict[str, Any]:
    domains = sorted({d for d in observed_domains if d})
    suggested = copy.deepcopy(profile._raw) if profile._raw else {}
    suggested.setdefault("name", profile.name)
    suggested.setdefault("target", dict(profile.target))
    net = suggested.setdefault("network", {})
    net["default"] = "deny"
    net["allow"] = [{"host": d} for d in domains]
    enforcement = suggested.setdefault("enforcement", {})
    enforcement["mode"] = "enforce"
    learning = suggested.setdefault("learning", {})
    learning["mode"] = "off"
    learning["observed"] = {"domains": domains}
    return suggested


def write_suggestion(profile: SandboxProfile, suggested: Dict[str, Any]) -> str:
    if profile.audit.path:
        base = os.path.dirname(os.path.expanduser(profile.audit.path)) or "."
    else:
        try:
            import platformdirs

            base = os.path.join(platformdirs.user_data_dir("mcpsafetywarden"), "suggestions")
        except Exception:
            base = "."
    safe_name = (profile.name or "server").replace("/", "_").replace(":", "_")
    path = os.path.join(base, f"{safe_name}.suggested.json")
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(suggested, fh, indent=2)
        _log.info("sandbox '%s': wrote suggested profile to %s", profile.name, path)
    except OSError as exc:
        _log.debug("could not write suggested profile: %s", exc)
    return path
