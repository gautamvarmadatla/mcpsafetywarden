from dataclasses import dataclass, field
from typing import Dict, Any, Literal

ObjectType = Literal[
    "agent_client",
    "mcp_config",
    "mcp_server",
    "tool",
    "package",
    "image",
    "iac_resource",
    "credential_surface",
    "finding",
    "cve",
    "runtime_call",
]

RelationType = Literal[
    "declares",
    "exposes",
    "depends_on",
    "affected_by",
    "uses_credential",
    "can_read",
    "can_write",
    "can_execute",
    "can_exfiltrate",
    "invoked",
    "blocked_by",
]


@dataclass
class InventoryObject:
    id: str
    type: ObjectType
    name: str
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InventoryRelation:
    source_id: str
    target_id: str
    relation: RelationType
    metadata: Dict[str, Any] = field(default_factory=dict)
