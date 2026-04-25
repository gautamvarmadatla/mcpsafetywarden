# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.x     | Yes       |
| < 1.0   | No        |

## Reporting a Vulnerability

Open an issue at https://github.com/gautamvarmadatla/mcpsafetywarden/issues with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations

## Threat Model

mcpsafetywarden is a security proxy, not a sandbox. It provides:

- Argument-level threat detection (pattern matching + optional LLM verification)
- Output injection scanning before results reach the calling agent
- Risk gating and policy enforcement based on behavioral profiles
- Credential redaction from tool outputs and scan findings
- Rate limiting on management operations

It does **not** provide:

- OS-level process isolation or sandboxing of the wrapped server
- Network-level egress filtering
- Cryptographic integrity guarantees on tool outputs
- Protection against a malicious wrapped server that bypasses the proxy

## Security Controls

See the [TOOLS reference](docs/TOOLS.md) and inline documentation in
`mcpsafetywarden/mcpsafety_scanner.py` for the full list of security controls
applied during scanning and proxied tool calls.
