EXTERNAL_EFFECTS: frozenset = frozenset({"external_action", "destructive"})
READ_EFFECTS: frozenset = frozenset({"read_only"})
EXFILTRATION_EFFECTS: frozenset = frozenset({"external_action"})

RISK_TAG_TO_MITRE: dict = {
    "credential_exposure": "T1078",
    "arbitrary_exec": "T1059",
    "data_exfiltration": "T1041",
    "lateral_movement": "T1570",
    "prompt_injection": "T1190",
    "privilege_escalation": "T1068",
    "tool_poisoning": "T1195",
    "tool_shadowing": "T1036",
    "filesystem_access": "T1005",
}

MITRE_NAMES: dict = {
    "T1078": "T1078 Valid Accounts",
    "T1059": "T1059 Command Execution",
    "T1041": "T1041 Exfiltration",
    "T1570": "T1570 Lateral Tool Transfer",
    "T1190": "T1190 Exploit Public-Facing App",
    "T1068": "T1068 Privilege Escalation",
    "T1195": "T1195 Supply Chain Compromise",
    "T1036": "T1036 Masquerading",
    "T1005": "T1005 Data from Local System",
}
