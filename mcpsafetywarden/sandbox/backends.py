"""Pluggable enforcer backends and capability negotiation.

The profile says WHAT to enforce; a backend says HOW on a given platform. Every
backend declares exactly which controls it enforces via capabilities(), so the
manager can fail closed (never silently ignore) a control the profile requires
but the backend cannot deliver.

Controls: filesystem, egress, resources, envscrub. Syscall filtering is not
enforceable through the stdio spawn path here, so it is always surfaced as an
unmet control rather than silently dropped.
"""

from __future__ import annotations

import logging
import os
import platform
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .profile import Resources, SandboxProfile, assurance_rank

_log = logging.getLogger(__name__)

_POSIX = os.name == "posix"


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class WrappedSpawn:
    command: str
    args: List[str]
    env: Dict[str, str]
    backend: str = ""
    notes: List[str] = field(default_factory=list)


def enforced_no_egress(profile: SandboxProfile) -> bool:
    if profile.learning.mode in ("observe", "suggest"):
        return False
    net = profile.network
    return net.enforcement == "enforced" and net.default == "deny" and not net.allow


def _has_glob(path: str) -> bool:
    return any(c in path for c in "*?[")


def _under_any(path: str, bases: List[str]) -> bool:
    for base in bases:
        if path == base or path.startswith(base.rstrip(os.sep) + os.sep):
            return True
    return False


def _apply_posix_limits(command: str, args: List[str], resources: Resources):
    """Apply only safe, long-lived-process-compatible rlimits.

    Memory (ulimit -v) and wall_time (timeout) are deliberately excluded: -v caps
    virtual address space and kills modern runtimes, and a wall clock would kill
    a long-lived stdio server mid-session. Memory/CPU belong to cgroups
    (container backend).
    """
    if not _POSIX or shutil.which("sh") is None:
        return command, args
    limits: List[str] = []
    if resources.max_open_files:
        limits.append(f"ulimit -n {int(resources.max_open_files)}")
    if resources.max_processes:
        limits.append(f"ulimit -u {int(resources.max_processes)}")
    if not limits:
        return command, args
    script = "; ".join(limits + ['exec "$@"'])
    return "/bin/sh", ["-c", script, "sh", command, *args]


def _posix_resources_supported(resources: Resources) -> bool:
    return _POSIX and any(v is not None for v in (resources.max_open_files, resources.max_processes))


class SandboxBackend:
    name = "base"
    assurance = "process"

    def available(self) -> bool:
        raise NotImplementedError

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        return set()

    def wrap(self, command: str, args: List[str], env: Dict[str, str], profile: SandboxProfile) -> WrappedSpawn:
        raise NotImplementedError


class SubprocessBackend(SandboxBackend):
    """Floor: works everywhere. Env scrub only; egress is advisory, no FS jail."""

    name = "subprocess"
    assurance = "process"

    def available(self) -> bool:
        return True

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        caps = {"envscrub"}
        if _posix_resources_supported(profile.resources):
            caps.add("resources")
        return caps

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        command, args = _apply_posix_limits(command, list(args), profile.resources)
        return WrappedSpawn(
            command=command,
            args=list(args),
            env=env,
            backend=self.name,
            notes=["env-scrub only; no filesystem isolation; egress advisory (proxy env)"],
        )


class BubblewrapBackend(SandboxBackend):
    name = "bubblewrap"
    assurance = "process"

    def available(self) -> bool:
        return platform.system() == "Linux" and shutil.which("bwrap") is not None

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        caps = {"filesystem", "envscrub"}
        if enforced_no_egress(profile):
            caps.add("egress")
        if _posix_resources_supported(profile.resources):
            caps.add("resources")
        return caps

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
        no_egress = enforced_no_egress(profile)
        if no_egress:
            argv.append("--unshare-net")
        for base in ("/usr", "/bin", "/lib", "/lib64", "/etc/ssl", "/etc/resolv.conf"):
            if os.path.exists(base):
                argv += ["--ro-bind", base, base]
        bound = [workdir]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            if os.path.exists(resolved):
                argv += ["--ro-bind", resolved, resolved]
                bound.append(resolved)
        argv += ["--bind", workdir, workdir]
        for path in profile.filesystem.write:
            resolved = os.path.abspath(os.path.expanduser(path))
            argv += ["--bind", resolved, resolved]
            bound.append(resolved)
        for path in profile.filesystem.deny:
            if _has_glob(path):
                continue
            resolved = os.path.abspath(os.path.expanduser(path))
            if _under_any(resolved, bound):
                argv += ["--tmpfs", resolved]
        argv += ["--chdir", workdir]
        inner_cmd, inner_args = _apply_posix_limits(command, list(args), profile.resources)
        argv += ["--", inner_cmd, *inner_args]
        notes = ["filesystem confined to workdir + declared reads; deny paths masked with tmpfs"]
        notes.append("network isolated (--unshare-net): no egress" if no_egress else "network shared: egress advisory")
        return WrappedSpawn(command=bwrap, args=argv, env=env, backend=self.name, notes=notes)


class SeatbeltBackend(SandboxBackend):
    name = "seatbelt"
    assurance = "process"

    def available(self) -> bool:
        return platform.system() == "Darwin" and shutil.which("sandbox-exec") is not None

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        caps = {"filesystem", "envscrub"}
        if _posix_resources_supported(profile.resources):
            caps.add("resources")
        return caps

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
        for path in profile.filesystem.deny:
            if _has_glob(path):
                continue
            resolved = os.path.abspath(os.path.expanduser(path))
            lines.append(f'(deny file* (subpath "{resolved}"))')
        return "\n".join(lines)

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        sbx = shutil.which("sandbox-exec") or "sandbox-exec"
        inner_cmd, inner_args = _apply_posix_limits(command, list(args), profile.resources)
        return WrappedSpawn(
            command=sbx,
            args=["-p", self._profile_text(profile), inner_cmd, *inner_args],
            env=env,
            backend=self.name,
            notes=["macOS seatbelt: deny-by-default filesystem, workdir writable; egress advisory"],
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

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        caps = {"filesystem", "envscrub"}
        if enforced_no_egress(profile):
            caps.add("egress")
        return caps

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
        notes = ["wasi capability isolation: filesystem via preopened dirs only"]
        notes.append("no network granted: egress denied" if enforced_no_egress(profile) else "network via proxy env")
        return WrappedSpawn(command=runtime, args=argv, env=env, backend=self.name, notes=notes)


class ContainerBackend(SandboxBackend):
    name = "container"
    assurance = "container"

    def _runtime(self) -> Optional[str]:
        for candidate in ("podman", "docker"):
            if shutil.which(candidate):
                return candidate
        return None

    def _image_for(self, profile: Optional[SandboxProfile]) -> Optional[str]:
        if profile is None:
            return os.environ.get("MCP_SANDBOX_IMAGE")
        return (profile.target.get("image") if profile.target else None) or os.environ.get("MCP_SANDBOX_IMAGE")

    def available(self) -> bool:
        return self._runtime() is not None and bool(self._image_for(None))

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        caps = {"filesystem", "envscrub", "resources"}
        if enforced_no_egress(profile):
            caps.add("egress")
        return caps

    def wrap(self, command, args, env, profile) -> WrappedSpawn:
        runtime = self._runtime() or "docker"
        image = self._image_for(profile)
        if not image:
            raise SandboxUnavailable("container backend requires target.image or MCP_SANDBOX_IMAGE")
        workdir = os.path.abspath(os.path.expanduser(profile.filesystem.workdir or "./"))
        no_egress = enforced_no_egress(profile)
        network = "none" if no_egress else "bridge"
        argv = ["run", "--rm", "-i", "--network", network, "-v", f"{workdir}:/work:rw", "-w", "/work"]
        for path in profile.filesystem.read:
            resolved = os.path.abspath(os.path.expanduser(path))
            argv += ["-v", f"{resolved}:{resolved}:ro"]
        if profile.resources.memory:
            argv += ["--memory", str(profile.resources.memory)]
        if profile.resources.cpu:
            argv += ["--cpus", str(profile.resources.cpu)]
        if profile.resources.max_processes:
            argv += ["--pids-limit", str(int(profile.resources.max_processes))]
        if profile.resources.max_open_files:
            argv += ["--ulimit", f"nofile={int(profile.resources.max_open_files)}"]
        for key, value in env.items():
            argv += ["-e", f"{key}={value}"]
        argv += [image, command, *args]
        notes = [f"containerised via {runtime} image {image}"]
        notes.append("network=none: no egress" if no_egress else "network=bridge: egress advisory (proxy env)")
        return WrappedSpawn(command=runtime, args=argv, env=env, backend=self.name, notes=notes)


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

    def capabilities(self, profile: SandboxProfile) -> Set[str]:
        return {"filesystem", "envscrub"}

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
    if not (profile.target.get("wasm")):
        usable = [b for b in usable if b.name != "wasm"]

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


def enforce_controls(profile: SandboxProfile, backend: SandboxBackend) -> List[str]:
    """Raise or warn for requested controls the backend cannot enforce.

    Returns the list of controls that could not be enforced (after applying the
    profile's on_unavailable policy for block-level controls).
    """
    caps = backend.capabilities(profile)
    requested = profile.required_controls()
    unmet: List[str] = []
    for control, strictness in requested.items():
        if control in caps:
            continue
        unmet.append(control)
        if strictness == "block" and profile.enforcement.mode == "enforce":
            action = profile.assurance.on_unavailable
            detail = (
                f"backend '{backend.name}' cannot enforce '{control}' "
                f"(install bubblewrap/podman/docker, use assurance.on_unavailable=warn, "
                f"or network.enforcement=advisory)"
            )
            if action == "block":
                raise SandboxUnavailable(detail)
            _log.warning("sandbox: %s -> %s", detail, action)
        else:
            _log.warning("sandbox: backend '%s' does not enforce requested control '%s'", backend.name, control)
    return unmet
