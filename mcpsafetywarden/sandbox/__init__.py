"""Durable sandbox layer for mcpsafetywarden.

Public API:
    load_profile(server)          -> Optional[SandboxProfile]
    sandbox_session(cmd, args, env, profile) -> context manager -> WrappedSpawn
    set_secret_resolver(fn)       register how secret refs resolve
    validate(dict)                -> list[str] of profile errors

The profile is the stable contract; backends implement it per platform.
"""

from . import learning
from .backends import SandboxUnavailable, WrappedSpawn, available_backends, enforce_controls, select_backend
from .broker import set_secret_resolver
from .manager import build_env, load_profile, sandbox_session
from .profile import SCHEMA_VERSION, SandboxProfile, from_dict, validate
from .remote import RemoteVerificationError, verify_remote

__all__ = [
    "SCHEMA_VERSION",
    "RemoteVerificationError",
    "SandboxProfile",
    "SandboxUnavailable",
    "WrappedSpawn",
    "available_backends",
    "build_env",
    "enforce_controls",
    "from_dict",
    "learning",
    "load_profile",
    "sandbox_session",
    "select_backend",
    "set_secret_resolver",
    "validate",
    "verify_remote",
]
