"""Pluggable enforcer backends and capability negotiation.

The profile says WHAT to enforce; a backend says HOW on a given platform. New
primitives (wasm, microvm) become new backends without touching policy. The
registry picks the strongest available backend that meets the required
assurance level, and fails closed when none does.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .profile import SandboxProfile, assurance_rank

_log = logging.getLogger(__name__)


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class WrappedSpawn:
    command: str
    args: List[str]
    env: Dict[str, str]
    backend: str = ""
    notes: List[str] = field(default_factory=list)


class SandboxBackend:
    name = "base"
    assurance = "process"

    def available(self) -> bool:
        raise NotImplementedError

    def wrap(self, command: str, args: List[str], env: Dict[str, str], profile: SandboxProfile) -> WrappedSpawn:
        raise NotImplementedError


class SubprocessBackend(SandboxBackend):
    """Floor: works everywhere. Env scrub + egress only, no FS/syscall jail."""

    name = "subprocess"
    assurance = "process"

    def available(self) -> bool:
        return True

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        return WrappedSpawn(
            command=command,
            args=list(args),
            env=env,
            backend=self.name,
            notes=["env-scrub + egress only; no filesystem/syscall isolation on this backend"],
        )


class BubblewrapBackend(SandboxBackend):
    name = "bubblewrap"
    assurance = "process"

    def available(self) -> bool:
        return platform.system() == "Linux" and shutil.which("bwrap") is not None

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        bwrap = shutil.which("bwrap") or "bwrap"
        workdir = os.path.abspath(os.path.expanduser(profile.filesystem.workdir or "./"))
        argv = [
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-cgroup",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        for base in ("/usr", "/bin", "/lib", "/lib64", "/etc/ssl", "/etc/resolv.conf"):
            if os.path.exists(base):
                argv += ["--ro-bind", base, base]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            if os.path.exists(resolved):
                argv += ["--ro-bind", resolved, resolved]
        argv += ["--bind", workdir, workdir]
        for path in profile.filesystem.write:
            resolved = os.path.abspath(os.path.expanduser(path))
            argv += ["--bind", resolved, resolved]
        argv += ["--chdir", workdir]
        argv += ["--", command, *args]
        return WrappedSpawn(
            command=bwrap,
            args=argv,
            env=env,
            backend=self.name,
            notes=["filesystem confined to workdir + declared reads; sensitive paths not bound"],
        )


class ContainerBackend(SandboxBackend):
    name = "container"
    assurance = "container"

    def _runtime(self) -> Optional[str]:
        for candidate in ("podman", "docker"):
            if shutil.which(candidate):
                return candidate
        return None

    def available(self) -> bool:
        return self._runtime() is not None and bool(self._image_for(None))

    def _image_for(self, profile: Optional[SandboxProfile]) -> Optional[str]:
        if profile is None:
            return os.environ.get("MCP_SANDBOX_IMAGE")
        return (profile.target.get("image") if profile.target else None) or os.environ.get("MCP_SANDBOX_IMAGE")

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        runtime = self._runtime() or "docker"
        image = self._image_for(profile)
        if not image:
            raise SandboxUnavailable("container backend requires target.image or MCP_SANDBOX_IMAGE")
        workdir = os.path.abspath(os.path.expanduser(profile.filesystem.workdir or "./"))
        argv = ["run", "--rm", "-i", "--network", "host", "-v", f"{workdir}:/work:rw", "-w", "/work"]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            argv += ["-v", f"{resolved}:{resolved}:ro"]
        if profile.resources.memory:
            argv += ["--memory", str(profile.resources.memory)]
        if profile.resources.cpu:
            argv += ["--cpus", str(profile.resources.cpu)]
        for key, value in env.items():
            argv += ["-e", f"{key}={value}"]
        argv += [image, command, *args]
        return WrappedSpawn(
            command=runtime,
            args=argv,
            env=env,
            backend=self.name,
            notes=[f"containerised via {runtime} image {image}"],
        )


class SeatbeltBackend(SandboxBackend):
    name = "seatbelt"
    assurance = "process"

    def available(self) -> bool:
        return platform.system() == "Darwin" and shutil.which("sandbox-exec") is not None

    def _profile_text(self, profile: SandboxProfile) -> str:
        workdir = os.path.abspath(os.path.expanduser(profile.filesystem.workdir or "./"))
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            "(allow process-exec)",
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            '(allow file-read* (subpath "/usr") (subpath "/System") (subpath "/bin") (subpath "/Library") (subpath "/private/etc"))',
            f'(allow file-read* file-write* (subpath "{workdir}") (subpath "/private/tmp") (subpath "/private/var/tmp"))',
            "(allow network*)",
        ]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            lines.append(f'(allow file-read* (subpath "{resolved}"))')
        return "\n".join(lines)

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        sbx = shutil.which("sandbox-exec") or "sandbox-exec"
        return WrappedSpawn(
            command=sbx,
            args=["-p", self._profile_text(profile), command, *args],
            env=env,
            backend=self.name,
            notes=["macOS seatbelt: deny-by-default filesystem, workdir writable"],
        )


class WasmBackend(SandboxBackend):
    name = "wasm"
    assurance = "container"

    def _is_wasm(self, command: str, profile: Optional[SandboxProfile]) -> bool:
        if profile is not None and profile.target.get("wasm"):
            return True
        return command.endswith(".wasm")

    def available(self) -> bool:
        return shutil.which("wasmtime") is not None

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        if not self._is_wasm(command, profile):
            raise SandboxUnavailable("wasm backend requires a .wasm module or target.wasm")
        runtime = shutil.which("wasmtime") or "wasmtime"
        workdir = os.path.abspath(os.path.expanduser(profile.filesystem.workdir or "./"))
        argv = ["run", "--dir", workdir]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            argv += ["--dir", resolved]
        for key, value in env.items():
            argv += ["--env", f"{key}={value}"]
        argv += [command, *args]
        return WrappedSpawn(
            command=runtime,
            args=argv,
            env=env,
            backend=self.name,
            notes=["wasi capability isolation: filesystem via preopened dirs only"],
        )


class MicroVMBackend(SandboxBackend):
    name = "microvm"
    assurance = "microvm"

    def _prefix(self) -> Optional[List[str]]:
        import shlex

        raw = os.environ.get("MCP_SANDBOX_MICROVM_CMD")
        if not raw:
            return None
        return shlex.split(raw)

    def available(self) -> bool:
        return self._prefix() is not None

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        prefix = self._prefix()
        if not prefix:
            raise SandboxUnavailable("microvm backend requires MCP_SANDBOX_MICROVM_CMD")
        return WrappedSpawn(
            command=prefix[0],
            args=[*prefix[1:], command, *args],
            env=env,
            backend=self.name,
            notes=[f"microvm via '{' '.join(prefix)}'"],
        )


_REGISTRY: List[SandboxBackend] = [
    MicroVMBackend(),
    ContainerBackend(),
    WasmBackend(),
    BubblewrapBackend(),
    SeatbeltBackend(),
    SubprocessBackend(),
]


def available_backends() -> List[SandboxBackend]:
    return [b for b in _REGISTRY if b.available()]


def select_backend(profile: SandboxProfile) -> SandboxBackend:
    required = profile.assurance.required
    req_rank = assurance_rank(required)
    usable = available_backends()

    meeting = [b for b in usable if assurance_rank(b.assurance) >= req_rank]
    if meeting:
        return max(meeting, key=lambda b: assurance_rank(b.assurance))

    on_unavailable = profile.assurance.on_unavailable
    best = max(usable, key=lambda b: assurance_rank(b.assurance)) if usable else None
    msg = f"no backend meets assurance '{required}' (have: {[b.name for b in usable]})"
    if on_unavailable == "block":
        raise SandboxUnavailable(msg)
    if best is None:
        raise SandboxUnavailable("no sandbox backend available at all")
    _log.warning("sandbox: %s -> %s with '%s'", msg, on_unavailable, best.name)
    return best
