"""Sandbox profile model: the stable, versioned policy contract.

Mechanisms (bubblewrap, seatbelt, containers, wasm) change; this schema is the
durable interface every backend implements. Omitted fields resolve to strict,
fail-closed defaults.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"

DEFAULT_FS_DENY: List[str] = [
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.config/gcloud",
    "~/.docker/config.json",
    "~/.netrc",
    "**/.env",
    "**/.env.*",
    "**/credentials",
]

DEFAULT_SECRET_ENV_PATTERNS: List[str] = [
    "*KEY*",
    "*TOKEN*",
    "*SECRET*",
    "*PASSWORD*",
    "*PASSWD*",
    "*CREDENTIAL*",
    "AWS_*",
    "GCP_*",
    "AZURE_*",
    "ANTHROPIC_*",
    "OPENAI_*",
    "GEMINI_*",
    "GITHUB_TOKEN",
]

_ASSURANCE_ORDER = ["process", "container", "microvm"]


def assurance_rank(level: str) -> int:
    try:
        return _ASSURANCE_ORDER.index(level)
    except ValueError:
        return 0


@dataclass
class HostRule:
    host: str
    ports: List[int] = field(default_factory=list)

    @staticmethod
    def from_any(raw: Any) -> "HostRule":
        if isinstance(raw, str):
            return HostRule(host=raw)
        if isinstance(raw, dict):
            ports: List[int] = []
            for p in raw.get("ports", []) or []:
                try:
                    ports.append(int(p))
                except (ValueError, TypeError):
                    continue
            return HostRule(host=str(raw.get("host", "")), ports=ports)
        return HostRule(host="")


@dataclass
class Assurance:
    required: str = "process"
    on_unavailable: str = "block"


@dataclass
class Enforcement:
    mode: str = "enforce"
    on_violation: str = "block"


@dataclass
class Filesystem:
    workdir: str = "./"
    temp: bool = True
    read: List[str] = field(default_factory=list)
    write: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=lambda: list(DEFAULT_FS_DENY))


@dataclass
class Network:
    default: str = "deny"
    allow: List[HostRule] = field(default_factory=list)
    block_reserved: bool = True
    on_new_domain: str = "ask"
    enforcement: str = "enforced"
    endpoint: Optional[str] = None
    pin_cert: Optional[str] = None


@dataclass
class Environment:
    allow: List[str] = field(default_factory=lambda: ["PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "TEMP", "TMP"])
    set: Dict[str, str] = field(default_factory=dict)
    scrub: bool = True


@dataclass
class SecretRule:
    ref: str
    inject_as: str = "header"
    name: str = ""
    template: str = "{secret}"
    to: Optional[str] = None


@dataclass
class Resources:
    cpu: Optional[str] = None
    memory: Optional[str] = None
    wall_time: Optional[str] = None
    max_processes: Optional[int] = None
    max_open_files: Optional[int] = None


@dataclass
class Syscalls:
    profile: str = "strict"
    deny_extra: List[str] = field(default_factory=list)
    allow_extra: List[str] = field(default_factory=list)


@dataclass
class Learning:
    mode: str = "off"
    observed: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Audit:
    log: bool = True
    path: Optional[str] = None


@dataclass
class SandboxProfile:
    schema_version: str = SCHEMA_VERSION
    name: str = ""
    target: Dict[str, Any] = field(default_factory=dict)
    assurance: Assurance = field(default_factory=Assurance)
    enforcement: Enforcement = field(default_factory=Enforcement)
    filesystem: Filesystem = field(default_factory=Filesystem)
    network: Network = field(default_factory=Network)
    environment: Environment = field(default_factory=Environment)
    secrets: List[SecretRule] = field(default_factory=list)
    resources: Resources = field(default_factory=Resources)
    syscalls: Syscalls = field(default_factory=Syscalls)
    learning: Learning = field(default_factory=Learning)
    audit: Audit = field(default_factory=Audit)
    _raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def transport(self) -> str:
        return str(self.target.get("transport", "stdio"))

    def to_dict(self) -> Dict[str, Any]:
        if self._raw:
            return copy.deepcopy(self._raw)
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "target": dict(self.target),
            "assurance": {"required": self.assurance.required, "on_unavailable": self.assurance.on_unavailable},
            "enforcement": {"mode": self.enforcement.mode, "on_violation": self.enforcement.on_violation},
            "filesystem": {
                "workdir": self.filesystem.workdir,
                "temp": self.filesystem.temp,
                "read": list(self.filesystem.read),
                "write": list(self.filesystem.write),
                "deny": list(self.filesystem.deny),
            },
            "network": {
                "default": self.network.default,
                "allow": [{"host": r.host, "ports": list(r.ports)} for r in self.network.allow],
                "block_reserved": self.network.block_reserved,
                "on_new_domain": self.network.on_new_domain,
                "enforcement": self.network.enforcement,
                "endpoint": self.network.endpoint,
                "pin_cert": self.network.pin_cert,
            },
            "environment": {
                "allow": list(self.environment.allow),
                "set": dict(self.environment.set),
                "scrub": self.environment.scrub,
            },
            "secrets": [
                {"ref": s.ref, "inject_as": s.inject_as, "name": s.name, "template": s.template, "to": s.to}
                for s in self.secrets
            ],
            "resources": {
                "cpu": self.resources.cpu,
                "memory": self.resources.memory,
                "wall_time": self.resources.wall_time,
                "max_processes": self.resources.max_processes,
                "max_open_files": self.resources.max_open_files,
            },
            "syscalls": {
                "profile": self.syscalls.profile,
                "deny_extra": list(self.syscalls.deny_extra),
                "allow_extra": list(self.syscalls.allow_extra),
            },
            "learning": {"mode": self.learning.mode, "observed": dict(self.learning.observed)},
            "audit": {"log": self.audit.log, "path": self.audit.path},
        }

    def required_controls(self) -> Dict[str, str]:
        """Controls the profile asks for, each marked block (fail-closed) or warn."""
        controls: Dict[str, str] = {}
        if self.enforcement.mode == "enforce":
            controls["filesystem"] = "block"
        if self.network.enforcement == "enforced" and self.network.default == "deny":
            if self.learning.mode in ("observe", "suggest"):
                controls["egress"] = "warn"
            else:
                controls["egress"] = "block" if not self.network.allow else "warn"
        if self.syscalls.profile in ("strict", "default"):
            controls["syscalls"] = "warn"
        if any(
            v is not None
            for v in (
                self.resources.cpu,
                self.resources.memory,
                self.resources.wall_time,
                self.resources.max_processes,
                self.resources.max_open_files,
            )
        ):
            controls["resources"] = "warn"
        return controls


def from_dict(data: Dict[str, Any]) -> SandboxProfile:
    data = data or {}
    net_raw = data.get("network", {}) or {}
    fs_raw = data.get("filesystem", {}) or {}
    env_raw = data.get("environment", {}) or {}
    res_raw = data.get("resources", {}) or {}
    sys_raw = data.get("syscalls", {}) or {}
    asr_raw = data.get("assurance", {}) or {}
    enf_raw = data.get("enforcement", {}) or {}
    lrn_raw = data.get("learning", {}) or {}
    aud_raw = data.get("audit", {}) or {}

    profile = SandboxProfile(
        schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
        name=str(data.get("name", "")),
        target=dict(data.get("target", {}) or {}),
        assurance=Assurance(
            required=str(asr_raw.get("required", "process")),
            on_unavailable=str(asr_raw.get("on_unavailable", "block")),
        ),
        enforcement=Enforcement(
            mode=str(enf_raw.get("mode", "enforce")),
            on_violation=str(enf_raw.get("on_violation", "block")),
        ),
        filesystem=Filesystem(
            workdir=str(fs_raw.get("workdir", "./")),
            temp=bool(fs_raw.get("temp", True)),
            read=list(fs_raw.get("read", []) or []),
            write=list(fs_raw.get("write", []) or []),
            deny=list(fs_raw.get("deny", DEFAULT_FS_DENY) or []),
        ),
        network=Network(
            default=str(net_raw.get("default", "deny")),
            allow=[HostRule.from_any(h) for h in (net_raw.get("allow", []) or [])],
            block_reserved=bool(net_raw.get("block_reserved", True)),
            on_new_domain=str(net_raw.get("on_new_domain", "ask")),
            enforcement=str(net_raw.get("enforcement", "enforced")),
            endpoint=net_raw.get("endpoint"),
            pin_cert=net_raw.get("pin_cert"),
        ),
        environment=Environment(
            allow=list(env_raw.get("allow", Environment().allow) or []),
            set=dict(env_raw.get("set", {}) or {}),
            scrub=bool(env_raw.get("scrub", True)),
        ),
        secrets=[
            SecretRule(
                ref=str(s.get("ref", "")),
                inject_as=str(s.get("inject_as", "header")),
                name=str(s.get("name", "")),
                template=str(s.get("template", "{secret}")),
                to=s.get("to"),
            )
            for s in (data.get("secrets", []) or [])
        ],
        resources=Resources(
            cpu=res_raw.get("cpu"),
            memory=res_raw.get("memory"),
            wall_time=res_raw.get("wall_time"),
            max_processes=res_raw.get("max_processes"),
            max_open_files=res_raw.get("max_open_files"),
        ),
        syscalls=Syscalls(
            profile=str(sys_raw.get("profile", "strict")),
            deny_extra=list(sys_raw.get("deny_extra", []) or []),
            allow_extra=list(sys_raw.get("allow_extra", []) or []),
        ),
        learning=Learning(mode=str(lrn_raw.get("mode", "off")), observed=dict(lrn_raw.get("observed", {}) or {})),
        audit=Audit(log=bool(aud_raw.get("log", True)), path=aud_raw.get("path")),
    )
    profile._raw = copy.deepcopy(data)
    return profile


def validate(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    if not isinstance(data, dict):
        return ["profile must be an object"]
    ver = str(data.get("schema_version", SCHEMA_VERSION))
    if ver.split(".", 1)[0] != SCHEMA_VERSION.split(".", 1)[0]:
        errors.append(f"unsupported schema_version '{ver}' (need {SCHEMA_VERSION.split('.', 1)[0]}.x)")
    asr = data.get("assurance", {}) or {}
    if asr.get("required") and asr["required"] not in _ASSURANCE_ORDER:
        errors.append(f"assurance.required must be one of {_ASSURANCE_ORDER}")
    if asr.get("on_unavailable") and asr["on_unavailable"] not in ("block", "warn", "downgrade"):
        errors.append("assurance.on_unavailable must be block|warn|downgrade")
    enf = data.get("enforcement", {}) or {}
    if enf.get("mode") and enf["mode"] not in ("observe", "warn", "enforce"):
        errors.append("enforcement.mode must be observe|warn|enforce")
    net = data.get("network", {}) or {}
    if net.get("default") and net["default"] not in ("deny", "allow"):
        errors.append("network.default must be deny|allow")
    for i, s in enumerate(data.get("secrets", []) or []):
        if not s.get("ref"):
            errors.append(f"secrets[{i}] missing 'ref'")
    return errors
