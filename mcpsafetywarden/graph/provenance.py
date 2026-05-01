"""
Package provenance detection for MCP servers.

Infers the package ecosystem and name from a server's registered command + args,
queries the local package manager (pip / npm) for installed metadata, checks
package registry attestations (PyPI PEP 740 / npm Sigstore), detects typosquatting,
computes per-tool schema fingerprints, and for HTTP servers captures the TLS cert
fingerprint and resolved IPs for change detection between inspections.
"""
from __future__ import annotations

import base64
import difflib
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_PKG_TIMEOUT = 5  # seconds for subprocess and HTTP calls

# ---------------------------------------------------------------------------
# Command-line pattern detectors
# Applied against the full command string: "<command> <arg0> <arg1> ..."
# Each entry: (ecosystem, compiled_pattern, capture_group_index)
# ---------------------------------------------------------------------------
_CMDLINE_DETECTORS: List[Tuple[str, re.Pattern, int]] = [
    # python -m pkg  /  python3.11 -m pkg  /  py -m pkg
    ("pypi", re.compile(r"(?:python[\d.]*|py(?:thon)?[\d.]*)\S*\s+.*?-m\s+(\S+)", re.I), 1),
    # uvx pkg[@version]
    ("pypi", re.compile(r"\buvx\s+([^\s@#]+)", re.I), 1),
    # uv tool run pkg  /  uv run pkg
    ("pypi", re.compile(r"\buv\s+(?:tool\s+run|run)\s+([^\s@#]+)", re.I), 1),
    # pipx run pkg
    ("pypi", re.compile(r"\bpipx\s+run\s+([^\s@#]+)", re.I), 1),
    # npx @scope/pkg  /  npx pkg
    ("npm", re.compile(r"\bnpx\s+(@?[^\s@#]+)", re.I), 1),
    # bunx pkg
    ("npm", re.compile(r"\bbunx\s+(@?[^\s@#]+)", re.I), 1),
    # deno run npm:pkg
    ("npm", re.compile(r"\bdeno\s+run\s+npm:([^\s@#/]+)", re.I), 1),
    # node_modules/.bin/pkg  (Unix or Windows path)
    ("npm", re.compile(r"node_modules[/\\]\.bin[/\\]([^\s/\\]+)", re.I), 1),
]

# Strip trailing version specifiers: pkg@1.0 → pkg, @scope/pkg@1.0 → @scope/pkg
# Lookbehind (?<=\w) ensures the @ or # is preceded by a word char so leading
# @ in scoped npm packages (@scope/pkg) is never stripped.
_VERSION_SUFFIX = re.compile(r"(?<=\w)[@#][^\s]*$")

# Known runtimes/tools that are not themselves PyPI packages
_RUNTIME_BINS = frozenset({
    "python", "python3", "python3.exe", "py", "node", "node.exe",
    "deno", "bun", "npx", "uvx", "uv", "pipx", "pip", "pip3",
    "sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh",
})

# Well-known MCP packages frequently impersonated in typosquatting attacks
_KNOWN_MCP_PACKAGES = frozenset({
    "anthropic", "mcp", "fastmcp", "modelcontextprotocol",
    "github-mcp-server", "filesystem-mcp-server", "brave-search-mcp",
    "fetch-mcp", "memory-mcp", "time-mcp", "everything-mcp",
    "aws-mcp-server", "gcp-mcp-server", "azure-mcp-server",
    "postgres-mcp", "sqlite-mcp", "mysql-mcp",
    "slack-mcp", "gmail-mcp", "google-drive-mcp",
    "docker-mcp", "kubernetes-mcp", "openai", "openai-mcp",
})

_UA = "mcpsafetywarden/provenance-check"


# ---------------------------------------------------------------------------
# Package detection
# ---------------------------------------------------------------------------

def detect_package(command: Optional[str], args: Optional[List[str]]) -> Dict[str, Any]:
    """
    Infer package ecosystem and name from a server's registered command + args.

    Returns:
      ecosystem:           "pypi" | "npm" | "unresolvable"
      package_name:        the package name as passed to the package manager, or None
      top_level_package:   for dotted module paths (my_pkg.sub), the installable top-level
      detection_method:    "cmdline_pattern" | "entrypoint_candidate" | "no_pattern_match" | "no_command"
      confidence:          "high" (explicit -m / uvx / npx) | "low" (bare binary fallback)
      python_executable:   (pypi only) the Python binary, for venv-aware pip queries
    """
    if not command:
        return {
            "ecosystem": "unresolvable",
            "package_name": None,
            "detection_method": "no_command",
            "confidence": "none",
        }

    parts = [command] + [str(a) for a in (args or [])]
    cmdline = " ".join(parts)
    cmdline_norm = cmdline.replace("\\", "/")

    for ecosystem, pattern, grp in _CMDLINE_DETECTORS:
        m = pattern.search(cmdline_norm)
        if not m:
            continue
        raw = m.group(grp).strip()
        if not raw:
            continue
        pkg = _VERSION_SUFFIX.sub("", raw)
        result: Dict[str, Any] = {
            "ecosystem": ecosystem,
            "package_name": pkg,
            "detection_method": "cmdline_pattern",
            "confidence": "high",
        }
        if ecosystem == "pypi" and "." in pkg and not pkg.startswith("."):
            result["top_level_package"] = pkg.split(".")[0]
        if ecosystem == "pypi":
            cmd_base = os.path.basename(command).lower().removesuffix(".exe")
            if "python" in cmd_base or cmd_base == "py":
                result["python_executable"] = command
        return result

    # Entrypoint fallback: bare binary installed via pip as a console_scripts entry point
    cmd_base = os.path.splitext(os.path.basename(command))[0]
    cmd_base_lower = cmd_base.lower()
    if (
        cmd_base
        and cmd_base_lower not in _RUNTIME_BINS
        and not cmd_base.startswith(".")
        and os.sep not in cmd_base
        and "/" not in cmd_base
        and re.match(r"^[a-zA-Z0-9_\-]+$", cmd_base)
    ):
        return {
            "ecosystem": "pypi",
            "package_name": cmd_base,
            "detection_method": "entrypoint_candidate",
            "confidence": "low",
            "note": "Package name inferred from binary name - verify manually.",
        }

    return {
        "ecosystem": "unresolvable",
        "package_name": None,
        "detection_method": "no_pattern_match",
        "confidence": "none",
    }


# ---------------------------------------------------------------------------
# Local package manager queries
# ---------------------------------------------------------------------------

def _query_pypi(package_name: str, python_executable: Optional[str] = None) -> Dict[str, Any]:
    """
    Run pip show and parse output.

    Tries (in order): the server's own Python binary, Safety Warden's Python, bare pip/pip3.
    """
    candidates: List[List[str]] = []
    if python_executable:
        candidates.append([python_executable, "-m", "pip", "show", "--", package_name])
    if sys.executable:
        entry = [sys.executable, "-m", "pip", "show", "--", package_name]
        if entry not in candidates:
            candidates.append(entry)
    for pip_bin in ("pip", "pip3"):
        if shutil.which(pip_bin):
            candidates.append([pip_bin, "show", "--", package_name])

    if not candidates:
        return {"status": "not_found", "error": "no pip executable found"}

    last_err = "no pip found"
    for cmd in candidates:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_PKG_TIMEOUT)
            if proc.returncode == 0 and proc.stdout.strip():
                return _parse_pip_show(proc.stdout)
            last_err = (proc.stderr or "").strip() or f"exit {proc.returncode}"
        except subprocess.TimeoutExpired:
            last_err = f"timed out after {_PKG_TIMEOUT}s"
        except (FileNotFoundError, PermissionError) as exc:
            last_err = str(exc)

    return {"status": "not_found", "error": last_err}


def _parse_pip_show(output: str) -> Dict[str, Any]:
    fields: Dict[str, str] = {}
    for line in output.splitlines():
        if ": " in line:
            key, _, val = line.partition(": ")
            fields[key.strip().lower().replace("-", "_")] = val.strip()

    requires_raw = fields.get("requires", "")
    requires = [r.strip() for r in requires_raw.split(",") if r.strip()] if requires_raw else []

    return {
        "status": "found",
        "name": fields.get("name", ""),
        "version": fields.get("version", ""),
        "location": fields.get("location", ""),
        "home_page": fields.get("home_page", ""),
        "summary": (fields.get("summary") or "")[:200],
        "author": fields.get("author", ""),
        "license": fields.get("license_", fields.get("license", "")),
        "requires": requires,
    }


def _query_npm(package_name: str) -> Dict[str, Any]:
    """
    Query npm for package metadata. Tries local npm list first, then npm info (registry).
    """
    if not shutil.which("npm"):
        return {"status": "not_found", "error": "npm not found in PATH"}

    try:
        proc = subprocess.run(
            ["npm", "list", "--json", "--depth=0", package_name],
            capture_output=True, text=True, timeout=_PKG_TIMEOUT,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                pkg_data = (data.get("dependencies") or {}).get(package_name)
                if pkg_data:
                    return {
                        "status": "found",
                        "name": package_name,
                        "version": pkg_data.get("version", ""),
                        "location": data.get("path", ""),
                    }
            except json.JSONDecodeError:
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    try:
        proc2 = subprocess.run(
            ["npm", "info", package_name, "--json"],
            capture_output=True, text=True, timeout=_PKG_TIMEOUT,
        )
        if proc2.returncode == 0 and proc2.stdout.strip():
            try:
                data2 = json.loads(proc2.stdout)
                if isinstance(data2, dict) and data2.get("name"):
                    return {
                        "status": "found_registry",
                        "name": data2.get("name", package_name),
                        "version": data2.get("version", ""),
                        "home_page": data2.get("homepage", ""),
                        "description": (data2.get("description") or "")[:200],
                        "note": "registry metadata; locally installed version may differ",
                    }
            except json.JSONDecodeError:
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        return {"status": "error", "error": str(exc)}

    return {"status": "not_found", "error": f"'{package_name}' not found via npm list or npm info"}


# ---------------------------------------------------------------------------
# Registry attestation checks (PyPI PEP 740 / npm Sigstore)
# ---------------------------------------------------------------------------

def _http_get_json(url: str) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_PKG_TIMEOUT) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        _log.debug("HTTP %s for %s", exc.code, url)
        return None
    except Exception as exc:
        _log.debug("registry fetch failed for %s: %s", url, exc)
        return None


def check_pypi_attestation(package: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Query the PyPI JSON API for provenance attestations (PEP 740).

    Returns attestation status, source repository URL, and registry version.
    """
    api_url = (
        f"https://pypi.org/pypi/{package}/{version}/json"
        if version else
        f"https://pypi.org/pypi/{package}/json"
    )
    data = _http_get_json(api_url)
    if data is None:
        return {"attestation_status": "not_on_registry", "has_attestation": False}

    info = data.get("info", {})
    urls = data.get("urls", [])
    has_attestation = any(u.get("attestations") for u in urls)

    project_urls = info.get("project_urls") or {}
    source_url = (
        project_urls.get("Source")
        or project_urls.get("source")
        or project_urls.get("Repository")
        or project_urls.get("repository")
        or info.get("project_url", "")
    )

    return {
        "attestation_status": "present" if has_attestation else "absent",
        "has_attestation": has_attestation,
        "registry_version": info.get("version", ""),
        "source_url": source_url,
        "registry_home_page": info.get("home_page", ""),
        "registry_author": info.get("author", ""),
    }


def check_npm_attestation(package: str, version: Optional[str] = None) -> Dict[str, Any]:
    """
    Query the npm registry for Sigstore provenance attestations.

    A 404 means the package has no attestations (common for older packages).
    """
    pkg_ref = f"{package}@{version}" if version else package
    data = _http_get_json(f"https://registry.npmjs.org/-/npm/v1/attestations/{pkg_ref}")
    if data is None:
        return {"attestation_status": "absent", "has_attestation": False}

    attestations = data.get("attestations", [])
    source_url = ""
    for a in attestations:
        try:
            payload_b64 = a.get("bundle", {}).get("dsseEnvelope", {}).get("payload", "")
            if payload_b64:
                payload = json.loads(base64.b64decode(payload_b64 + "==").decode())
                source_url = (
                    payload.get("predicate", {})
                    .get("buildDefinition", {})
                    .get("externalParameters", {})
                    .get("workflow", {})
                    .get("repository", "")
                )
                if source_url:
                    break
        except Exception:
            pass

    return {
        "attestation_status": "present" if attestations else "absent",
        "has_attestation": bool(attestations),
        "attestation_count": len(attestations),
        "source_url": source_url,
    }


# ---------------------------------------------------------------------------
# Typosquatting detection
# ---------------------------------------------------------------------------

def check_typosquatting(package_name: str) -> List[str]:
    """
    Check if package_name is suspiciously close to a well-known MCP package name.

    Returns list of known packages that might be being impersonated.
    Uses 0.82 similarity threshold (catches 1-2 char edits on typical package names).
    """
    if not package_name:
        return []
    name_norm = package_name.lower().replace("_", "-")
    if name_norm in _KNOWN_MCP_PACKAGES:
        return []
    suspects = []
    for known in _KNOWN_MCP_PACKAGES:
        if difflib.SequenceMatcher(None, name_norm, known).ratio() > 0.82:
            suspects.append(known)
    return sorted(suspects)


# ---------------------------------------------------------------------------
# HTTP server integrity checks (TLS + DNS)
# ---------------------------------------------------------------------------

def get_tls_cert_fingerprint(url: str) -> Optional[str]:
    """
    SHA-256 of the server's DER-encoded leaf TLS certificate.

    Stored at registration; any change on subsequent inspect indicates a cert
    rotation, MITM, or subdomain takeover.
    Returns None for non-HTTPS URLs or on connection failure.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=_PKG_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                return hashlib.sha256(cert_der).hexdigest()
    except Exception as exc:
        _log.debug("TLS fingerprint failed for %s: %s", url, exc)
        return None


def resolve_host_ips(url: str) -> Dict[str, Any]:
    """
    Resolve a server URL's hostname to IP addresses.

    Returns all IPs and flags any private/loopback ones (DNS rebinding risk).
    Stored at registration; changes indicate DNS hijacking or BGP reroute.
    """
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return {"ips": [], "private_ips": [], "error": "no hostname in URL"}
    try:
        infos = socket.getaddrinfo(host, None)
        all_ips = sorted(set(info[4][0] for info in infos))
        private: List[str] = []
        for ip in all_ips:
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local:
                    private.append(ip)
            except ValueError:
                pass
        return {"ips": all_ips, "private_ips": private}
    except socket.gaierror as exc:
        return {"ips": [], "private_ips": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# Schema fingerprinting
# ---------------------------------------------------------------------------

def compute_tool_fingerprint(
    name: str,
    description: Optional[str],
    input_schema: Dict[str, Any],
) -> str:
    """
    SHA-256 fingerprint of a tool's public surface: name + description + inputSchema.

    Any change between inspections (description rewrite, parameter add/remove,
    type change) produces a different fingerprint - the primary signal for
    detecting silent tool poisoning.
    """
    payload = json.dumps(
        {"name": name, "description": description or "", "inputSchema": input_schema},
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Unified provenance builder
# ---------------------------------------------------------------------------

def build_provenance_info(
    server_id: str,
    command: Optional[str],
    args: Optional[List[str]],
    url: Optional[str] = None,
    transport: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build full provenance info for a server.

    For all servers: package detection, local pip/npm query, registry attestation,
    typosquatting check.
    For HTTP/SSE servers additionally: TLS cert fingerprint, resolved IPs.

    Always returns (never raises) - errors are captured in the returned dict.
    """
    result: Dict[str, Any] = {"server_id": server_id}

    # --- HTTP-specific checks ---
    is_http = transport in ("sse", "streamable_http") or (not transport and url and not command)
    if is_http and url:
        result["tls_cert_fingerprint"] = get_tls_cert_fingerprint(url)
        dns = resolve_host_ips(url)
        result["resolved_ips"] = dns.get("ips", [])
        result["private_ips"] = dns.get("private_ips", [])
        if dns.get("error"):
            result["dns_error"] = dns["error"]

    # --- Package detection ---
    detection = detect_package(command, args)
    ecosystem = detection["ecosystem"]
    package_name = detection.get("package_name")
    top_level = detection.get("top_level_package") or package_name

    result.update({
        "ecosystem": ecosystem,
        "package_name": package_name,
        "detection_method": detection.get("detection_method"),
        "detection_confidence": detection.get("confidence", "none"),
    })
    if detection.get("note"):
        result["note"] = detection["note"]

    if ecosystem == "unresolvable" or not package_name:
        result.update({"status": "unresolvable", "verified": False})
        return result

    # --- Local package manager query ---
    try:
        if ecosystem == "pypi":
            metadata = _query_pypi(top_level, detection.get("python_executable"))
        elif ecosystem == "npm":
            metadata = _query_npm(package_name)
        else:
            metadata = {"status": "unsupported_ecosystem"}
    except Exception as exc:
        metadata = {"status": "error", "error": str(exc)}

    result.update({k: v for k, v in metadata.items() if k != "status"})
    result["status"] = metadata.get("status", "error")
    result["verified"] = metadata.get("status") == "found"

    # --- Registry attestation check ---
    installed_version = metadata.get("version") if metadata.get("status") == "found" else None
    try:
        if ecosystem == "pypi":
            attest = check_pypi_attestation(package_name, installed_version)
        elif ecosystem == "npm":
            attest = check_npm_attestation(package_name, installed_version)
        else:
            attest = {}
        result["attestation"] = attest
    except Exception as exc:
        result["attestation"] = {"attestation_status": "error", "error": str(exc)}

    # --- Version drift: installed vs latest on registry ---
    registry_version = (result.get("attestation") or {}).get("registry_version", "")
    if installed_version and registry_version and installed_version != registry_version:
        result["version_drift"] = {
            "installed": installed_version,
            "registry_latest": registry_version,
            "behind": True,
        }

    # --- Typosquatting check ---
    squats = check_typosquatting(package_name)
    if squats:
        result["typosquatting_suspects"] = squats

    return result
