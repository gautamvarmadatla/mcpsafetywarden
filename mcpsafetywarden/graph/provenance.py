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
import math
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

_PKG_TIMEOUT = 5

_CMDLINE_DETECTORS: List[Tuple[str, re.Pattern, int]] = [
    ("pypi", re.compile(r"(?:python[\d.]*|py(?:thon)?[\d.]*)\S*\s+.*?-m\s+(\S+)", re.I), 1),
    ("pypi", re.compile(r"\buvx\s+([^\s@#]+)", re.I), 1),
    ("pypi", re.compile(r"\buv\s+(?:tool\s+run|run)\s+([^\s@#]+)", re.I), 1),
    ("pypi", re.compile(r"\bpipx\s+run\s+([^\s@#]+)", re.I), 1),
    ("npm", re.compile(r"\bnpx\s+(@?[^\s@#]+)", re.I), 1),
    ("npm", re.compile(r"\bbunx\s+(@?[^\s@#]+)", re.I), 1),
    ("npm", re.compile(r"\bdeno\s+run\s+npm:([^\s@#/]+)", re.I), 1),
    ("npm", re.compile(r"node_modules[/\\]\.bin[/\\]([^\s/\\]+)", re.I), 1),
]

_VERSION_SUFFIX = re.compile(r"(?<=\w)[@#][^\s]*$")

_RUNTIME_BINS = frozenset(
    {
        "python",
        "python3",
        "python3.exe",
        "py",
        "node",
        "node.exe",
        "deno",
        "bun",
        "npx",
        "uvx",
        "uv",
        "pipx",
        "pip",
        "pip3",
        "sh",
        "bash",
        "zsh",
        "fish",
        "cmd",
        "powershell",
        "pwsh",
    }
)

# Well-known MCP packages frequently impersonated in typosquatting attacks
_KNOWN_MCP_PACKAGES = frozenset(
    {
        "anthropic",
        "openai",
        "mcp",
        "fastmcp",
        "mcp-server",
        "mcp-framework",
        "mcp-agent",
        "mcp-cli",
        "mcp-remote",
        "mcp-use",
        "mcp-installer",
        "fast-agent-mcp",
        "fastapi-mcp",
        "modelcontextprotocol",
        "@modelcontextprotocol/sdk",
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-git",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-time",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/create-server",
        "@playwright/mcp",
        "mcp-playwright",
        "mcp-browser",
        "mcp-brave-search",
        "brave-search-mcp",
        "mcp-perplexity",
        "mcp-exa",
        "mcp-fetch",
        "fetch-mcp",
        "filesystem-mcp-server",
        "memory-mcp",
        "time-mcp",
        "everything-mcp",
        "aws-mcp-server",
        "gcp-mcp-server",
        "azure-mcp-server",
        "mcp-cloudflare",
        "mcp-docker",
        "mcp-vercel",
        "mcp-neon",
        "docker-mcp",
        "kubernetes-mcp",
        "postgres-mcp",
        "sqlite-mcp",
        "mysql-mcp",
        "mcp-mongodb",
        "mcp-duckdb",
        "mcp-elasticsearch",
        "mcp-pinecone",
        "mcp-weaviate",
        "mcp-chroma",
        "mcp-qdrant",
        "mcp-milvus",
        "mcp-neo4j",
        "mcp-redis",
        "github-mcp-server",
        "mcp-github",
        "mcp-gitlab",
        "mcp-gitlab-server",
        "mcp-sentry",
        "mcp-linear",
        "mcp-jira",
        "atlassian-mcp-server",
        "slack-mcp",
        "mcp-slack",
        "gmail-mcp",
        "mcp-gmail",
        "mcp-twilio",
        "sendgrid-mcp",
        "mcp-notion",
        "mcp-figma",
        "mcp-obsidian",
        "mcp-google-drive",
        "mcp-google-sheets",
        "google-drive-mcp",
        "mcp-stripe",
        "mcp-hubspot",
        "mcp-salesforce",
        "mcp-paypal",
        "mcp-pypi",
        "arxiv-mcp-server",
        "supabase-mcp",
        "mcp-server-git",
        "mcp-server-fetch",
        "mcp-client-cli",
        "mcp-shell-tools",
        "weave-mcp",
        "openai-mcp",
        "openai-agents",
        "boto3",
        "packaging",
        "urllib3",
        "certifi",
        "requests",
        "typing-extensions",
        "idna",
        "charset-normalizer",
        "setuptools",
        "botocore",
        "cryptography",
        "aiobotocore",
        "python-dateutil",
        "six",
        "pyyaml",
        "cffi",
        "pydantic",
        "pygments",
        "click",
        "numpy",
        "grpcio-status",
        "pycparser",
        "pydantic-core",
        "pluggy",
        "s3transfer",
        "protobuf",
        "anyio",
        "attrs",
        "h11",
        "fsspec",
        "annotated-types",
        "pytest",
        "pandas",
        "httpx",
        "iniconfig",
        "httpcore",
        "s3fs",
        "markupsafe",
        "platformdirs",
        "python-dotenv",
        "pip",
        "jinja2",
        "pyjwt",
        "jmespath",
        "importlib-metadata",
        "rich",
        "filelock",
        "aiohttp",
        "zipp",
        "pathspec",
        "wheel",
        "jsonschema",
        "markdown-it-py",
        "pytz",
        "pyasn1",
        "multidict",
        "yarl",
        "mdurl",
        "googleapis-common-protos",
        "starlette",
        "uvicorn",
        "google-auth",
        "rpds-py",
        "tzdata",
        "propcache",
        "frozenlist",
        "referencing",
        "pillow",
        "tqdm",
        "google-api-core",
        "jsonschema-specifications",
        "virtualenv",
        "aiosignal",
        "grpcio",
        "fastapi",
        "colorama",
        "aiohappyeyeballs",
        "awscli",
        "greenlet",
        "pyasn1-modules",
        "pyarrow",
        "requests-oauthlib",
        "wrapt",
        "opentelemetry-api",
        "scipy",
        "tomli",
        "tenacity",
        "pyparsing",
        "sqlalchemy",
        "opentelemetry-sdk",
        "typer",
        "beautifulsoup4",
        "websockets",
        "oauthlib",
        "soupsieve",
        "trove-classifiers",
        "opentelemetry-semantic-conventions",
        "shellingham",
        "lodash",
        "chalk",
        "request",
        "commander",
        "react",
        "express",
        "debug",
        "async",
        "fs-extra",
        "moment",
        "prop-types",
        "react-dom",
        "bluebird",
        "underscore",
        "vue",
        "axios",
        "tslib",
        "mkdirp",
        "glob",
        "yargs",
        "colors",
        "inquirer",
        "webpack",
        "uuid",
        "classnames",
        "minimist",
        "body-parser",
        "rxjs",
        "core-js",
        "semver",
        "cheerio",
        "rimraf",
        "eslint",
        "dotenv",
        "typescript",
        "@types/node",
        "js-yaml",
        "winston",
        "redux",
        "object-assign",
        "node-fetch",
        "@babel/runtime",
        "handlebars",
        "aws-sdk",
        "mocha",
        "socket.io",
        "ws",
        "ramda",
        "react-redux",
        "@babel/core",
        "ejs",
        "superagent",
        "mongodb",
        "chai",
        "mongoose",
        "xml2js",
        "bootstrap",
        "jest",
        "redis",
        "vue-router",
        "ora",
        "prettier",
        "eslint-plugin-react",
    }
)

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
        "summary": fields.get("summary") or "",
        "author": fields.get("author", ""),
        "license": fields.get("license", ""),
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
            capture_output=True,
            text=True,
            timeout=_PKG_TIMEOUT,
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
            capture_output=True,
            text=True,
            timeout=_PKG_TIMEOUT,
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
                        "description": data2.get("description") or "",
                        "note": "registry metadata; locally installed version may differ",
                    }
            except json.JSONDecodeError:
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as exc:
        return {"status": "error", "error": str(exc)}

    return {"status": "not_found", "error": f"'{package_name}' not found via npm list or npm info"}


def _http_get_text(url: str) -> Optional[str]:
    if not url.startswith(("https://", "http://")):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_PKG_TIMEOUT) as resp:  # nosec B310
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        _log.debug("HTTP %s for %s", exc.code, url)
        return None
    except Exception as exc:
        _log.debug("text fetch failed for %s: %s", url, exc)
        return None


def _http_get_json(url: str) -> Optional[Dict[str, Any]]:
    if not url.startswith(("https://", "http://")):
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": _UA})
        with urllib.request.urlopen(req, timeout=_PKG_TIMEOUT) as resp:  # nosec B310
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
    api_url = f"https://pypi.org/pypi/{package}/{version}/json" if version else f"https://pypi.org/pypi/{package}/json"
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
        or project_urls.get("Source Code")
        or project_urls.get("source code")
        or project_urls.get("GitHub")
        or project_urls.get("github")
        or project_urls.get("Code")
        or project_urls.get("code")
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
                padding = "=" * ((-len(payload_b64)) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding).decode())
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


_PEP621_DEP_LINE = re.compile(r'"([A-Za-z0-9][A-Za-z0-9._-]*)')
_POETRY_DEP_KEY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", re.MULTILINE)
_REQ_PKG_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_VERSION_FROM_CONSTRAINT = re.compile(r"[=~^><!\s]*([0-9]+\.[0-9][0-9a-zA-Z._-]*)")


def _github_raw_base(github_url: str) -> Optional[str]:
    from urllib.parse import urlparse

    parsed = urlparse(github_url)
    if parsed.hostname not in ("github.com", "www.github.com"):
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1].removesuffix(".git")
    branch = "HEAD"
    if len(parts) >= 4 and parts[2] == "tree":
        branch = parts[3]
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}"


def _parse_pyproject_deps(content: str) -> List[str]:
    deps: List[str] = []
    seen: set = set()

    in_pep621 = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_pep621 = False
        if re.match(r"^dependencies\s*=\s*\[", stripped):
            in_pep621 = True
        if in_pep621:
            for m in _PEP621_DEP_LINE.finditer(line):
                name = m.group(1).lower().replace("_", "-")
                if name not in ("python",) and name not in seen:
                    deps.append(m.group(1))
                    seen.add(name)
            if "]" in stripped and not stripped.startswith("dependencies"):
                in_pep621 = False

    in_poetry = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[tool.poetry.dependencies]":
            in_poetry = True
            continue
        if stripped.startswith("[") and in_poetry:
            in_poetry = False
        if in_poetry and stripped and not stripped.startswith("#"):
            m = _POETRY_DEP_KEY.match(stripped)
            if m:
                name = m.group(1)
                norm = name.lower().replace("_", "-")
                if norm not in ("python",) and norm not in seen:
                    deps.append(name)
                    seen.add(norm)

    return deps


def _extract_version(constraint: str) -> Optional[str]:
    m = _VERSION_FROM_CONSTRAINT.search(constraint)
    return m.group(1) if m else None


def _parse_requirements_txt(content: str) -> List[str]:
    deps: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_PKG_NAME.match(line)
        if m:
            deps.append(m.group(1))
    return deps


def _parse_requirements_txt_versioned(content: str) -> List[Dict[str, Optional[str]]]:
    deps: List[Dict[str, Optional[str]]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = _REQ_PKG_NAME.match(line)
        if m:
            deps.append({"name": m.group(1), "version": _extract_version(line)})
    return deps


def _parse_pyproject_deps_versioned(content: str) -> List[Dict[str, Optional[str]]]:
    deps: List[Dict[str, Optional[str]]] = []
    seen: set = set()

    in_pep621 = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_pep621 = False
        if re.match(r"^dependencies\s*=\s*\[", stripped):
            in_pep621 = True
        if in_pep621:
            for m in _PEP621_DEP_LINE.finditer(line):
                raw = m.group(0)[1:]
                name_m = _REQ_PKG_NAME.match(raw)
                if name_m:
                    name = name_m.group(1)
                    norm = name.lower().replace("_", "-")
                    if norm not in ("python",) and norm not in seen:
                        deps.append({"name": name, "version": _extract_version(raw)})
                        seen.add(norm)
            if "]" in stripped and not stripped.startswith("dependencies"):
                in_pep621 = False

    in_poetry = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped == "[tool.poetry.dependencies]":
            in_poetry = True
            continue
        if stripped.startswith("[") and in_poetry:
            in_poetry = False
        if in_poetry and stripped and not stripped.startswith("#"):
            m = _POETRY_DEP_KEY.match(stripped)
            if m:
                name = m.group(1)
                norm = name.lower().replace("_", "-")
                if norm not in ("python",) and norm not in seen:
                    deps.append({"name": name, "version": _extract_version(stripped)})
                    seen.add(norm)

    return deps


def fetch_github_manifest(github_url: str) -> Dict[str, Any]:
    """
    Fetch and parse the dependency manifest from a GitHub repository.

    Tries package.json, pyproject.toml, and requirements.txt in order.
    Returns manifest_type, dependencies (names), dev_dependencies (names),
    and dependencies_versioned ({name, version}) for CVE checking.
    """
    base = _github_raw_base(github_url)
    if not base:
        return {"status": "invalid_url", "dependencies": [], "dev_dependencies": [], "dependencies_versioned": []}

    text = _http_get_text(f"{base}/package.json")
    if text:
        try:
            pkg = json.loads(text)
            raw_deps = pkg.get("dependencies") or {}
            raw_dev = pkg.get("devDependencies") or {}
            versioned = [{"name": n, "version": _extract_version(v), "dev": False} for n, v in raw_deps.items()] + [
                {"name": n, "version": _extract_version(v), "dev": True} for n, v in raw_dev.items()
            ]
            return {
                "status": "found",
                "manifest_type": "package.json",
                "dependencies": list(raw_deps.keys()),
                "dev_dependencies": list(raw_dev.keys()),
                "dependencies_versioned": versioned,
            }
        except (json.JSONDecodeError, TypeError):
            pass

    text = _http_get_text(f"{base}/pyproject.toml")
    if text:
        deps = _parse_pyproject_deps(text)
        versioned = _parse_pyproject_deps_versioned(text)
        if deps:
            return {
                "status": "found",
                "manifest_type": "pyproject.toml",
                "dependencies": deps,
                "dev_dependencies": [],
                "dependencies_versioned": [dict(d, dev=False) for d in versioned],
            }

    text = _http_get_text(f"{base}/requirements.txt")
    if text:
        deps = _parse_requirements_txt(text)
        versioned = _parse_requirements_txt_versioned(text)
        if deps:
            return {
                "status": "found",
                "manifest_type": "requirements.txt",
                "dependencies": deps,
                "dev_dependencies": [],
                "dependencies_versioned": [dict(d, dev=False) for d in versioned],
            }

    return {"status": "not_found", "dependencies": [], "dev_dependencies": [], "dependencies_versioned": []}


def check_dependency_typosquatting(dependencies: List[str]) -> List[Dict[str, Any]]:
    """
    Run typosquatting check against a list of dependency names.

    Returns entries with {dependency, suspects} for any suspicious matches.
    """
    findings = []
    for dep in dependencies:
        suspects = check_typosquatting(dep)
        if suspects:
            findings.append({"dependency": dep, "suspects": suspects})
    return findings


_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_TIMEOUT = _PKG_TIMEOUT * 2

_CVSS_V3_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_V3_AC = {"L": 0.77, "H": 0.44}
_CVSS_V3_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_CVSS_V3_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_CVSS_V3_UI = {"N": 0.85, "R": 0.62}
_CVSS_V3_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}
_CVSS_VECTOR_RE = re.compile(r"CVSS:[23]\.\d/(.+)")


def _cvss3_score(vector: str) -> Optional[float]:
    m = _CVSS_VECTOR_RE.match(vector)
    if not m:
        return None
    try:
        parts = dict(p.split(":") for p in m.group(1).split("/") if ":" in p)
        av = _CVSS_V3_AV.get(parts.get("AV", ""), 0.0)
        ac = _CVSS_V3_AC.get(parts.get("AC", ""), 0.0)
        s = parts.get("S", "U")
        pr = (_CVSS_V3_PR_C if s == "C" else _CVSS_V3_PR_U).get(parts.get("PR", ""), 0.0)
        ui = _CVSS_V3_UI.get(parts.get("UI", ""), 0.0)
        c = _CVSS_V3_CIA.get(parts.get("C", ""), 0.0)
        i_ = _CVSS_V3_CIA.get(parts.get("I", ""), 0.0)
        a = _CVSS_V3_CIA.get(parts.get("A", ""), 0.0)
        isc_base = 1 - (1 - c) * (1 - i_) * (1 - a)
        exploit = 8.22 * av * ac * pr * ui
        if s == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        if impact <= 0:
            return 0.0
        raw = min(exploit + impact, 10.0) if s == "U" else min(1.08 * (exploit + impact), 10.0)
        return math.ceil(raw * 10) / 10
    except Exception:
        return None


def _osv_severity(vuln: Dict[str, Any]) -> str:
    db_sev = ((vuln.get("database_specific") or {}).get("severity") or "").upper()
    if db_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return db_sev

    best = 0.0
    for s in vuln.get("severity", []):
        score_str = s.get("score", "")
        if s.get("type", "").startswith("CVSS_V"):
            computed = _cvss3_score(score_str)
            if computed and computed > best:
                best = computed
        else:
            try:
                val = float(score_str)
                if val > best:
                    best = val
            except (ValueError, TypeError):
                pass

    if best >= 9.0:
        return "CRITICAL"
    if best >= 7.0:
        return "HIGH"
    if best >= 4.0:
        return "MEDIUM"
    if best > 0:
        return "LOW"
    return "UNKNOWN"


def check_osv_vulns(
    packages: List[Dict[str, Any]],
    ecosystem: str,
) -> List[Dict[str, Any]]:
    """
    Query OSV.dev for known vulnerabilities in a list of packages.

    packages: list of {name, version (optional), dev (optional)}
    ecosystem: "PyPI" or "npm"
    Only returns HIGH and CRITICAL findings to reduce noise.
    """
    if not packages:
        return []

    osv_ecosystem = "PyPI" if ecosystem == "pypi" else "npm"
    queries = []
    for pkg in packages:
        q: Dict[str, Any] = {"package": {"name": pkg["name"], "ecosystem": osv_ecosystem}}
        if pkg.get("version"):
            q["version"] = pkg["version"]
        queries.append(q)

    findings: List[Dict[str, Any]] = []
    for chunk_start in range(0, len(queries), 1000):
        chunk_queries = queries[chunk_start : chunk_start + 1000]
        chunk_pkgs = packages[chunk_start : chunk_start + 1000]
        try:
            body = json.dumps({"queries": chunk_queries}).encode()
            req = urllib.request.Request(
                _OSV_BATCH_URL,
                data=body,
                headers={"Content-Type": "application/json", "User-Agent": _UA},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_OSV_TIMEOUT) as resp:  # nosec B310
                data = json.loads(resp.read())
        except Exception as exc:
            _log.debug("OSV batch query failed: %s", exc)
            continue

        for pkg, result in zip(chunk_pkgs, data.get("results", [])):
            for vuln in result.get("vulns", []):
                severity = _osv_severity(vuln)
                if severity not in ("HIGH", "CRITICAL"):
                    continue
                findings.append(
                    {
                        "package": pkg["name"],
                        "version": pkg.get("version"),
                        "dev": pkg.get("dev", False),
                        "vuln_id": vuln.get("id", ""),
                        "severity": severity,
                        "summary": vuln.get("summary") or "",
                        "aliases": vuln.get("aliases", []),
                    }
                )

    return findings


def _scan_pip_environment(python_executable: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
    """
    Return all packages installed in the Python environment as [{name, version, dev=False}].
    Uses `pip list --format=json`. Tries the server's Python first, then our own.
    """
    candidates: List[List[str]] = []
    if python_executable:
        candidates.append([python_executable, "-m", "pip", "list", "--format=json"])
    if sys.executable:
        entry = [sys.executable, "-m", "pip", "list", "--format=json"]
        if entry not in candidates:
            candidates.append(entry)
    for pip_bin in ("pip", "pip3"):
        if shutil.which(pip_bin):
            candidates.append([pip_bin, "list", "--format=json"])

    for cmd in candidates:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_PKG_TIMEOUT)
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                return [
                    {"name": p["name"], "version": p["version"], "dev": False}
                    for p in data
                    if p.get("name") and p.get("version")
                ]
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, PermissionError, KeyError):
            pass
    return None


def _scan_npm_environment() -> Optional[List[Dict[str, Any]]]:
    """
    Return all npm packages in the current project as [{name, version, dev=False}].
    Uses `npm list --json --all`.
    """
    if not shutil.which("npm"):
        return None
    try:
        proc = subprocess.run(
            ["npm", "list", "--json", "--all"],
            capture_output=True,
            text=True,
            timeout=_PKG_TIMEOUT * 3,
        )
        if not proc.stdout.strip():
            return None
        data = json.loads(proc.stdout)
        packages: List[Dict[str, Any]] = []
        seen: set = set()
        _flatten_npm_tree(data.get("dependencies", {}), packages, seen)
        return packages if packages else None
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError, PermissionError):
        return None


def _flatten_npm_tree(
    deps: Dict[str, Any],
    out: List[Dict[str, Any]],
    seen: set,
) -> None:
    for name, info in deps.items():
        version = info.get("version", "")
        key = f"{name}@{version}"
        if key not in seen:
            seen.add(key)
            if version:
                out.append({"name": name, "version": version, "dev": False})
        _flatten_npm_tree(info.get("dependencies", {}), out, seen)


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
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
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


_GITHUB_HOST_RE = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/", re.I)


def _is_github_url(url: Optional[str]) -> bool:
    return bool(url and _GITHUB_HOST_RE.match(url))


def _normalise_github_url(url: str) -> str:
    url = re.sub(r"^git\+", "", url.strip())
    url = re.sub(r"^git://", "https://", url)
    if url.endswith(".git"):
        url = url[:-4]
    return url.rstrip("/")


def _npm_source_url(package_name: str) -> Optional[str]:
    data = _http_get_json(f"https://registry.npmjs.org/{package_name}/latest")
    if not data:
        return None
    repo = data.get("repository") or {}
    raw = repo.get("url", "") if isinstance(repo, dict) else ""
    if not raw:
        return None
    raw = _normalise_github_url(raw)
    return raw if _is_github_url(raw) else None


def _mcp_registry_lookup(name_hint: str) -> Optional[str]:
    data = _http_get_json(
        f"https://registry.modelcontextprotocol.io/v0/servers?search={urllib.parse.quote(name_hint)}&limit=5"
    )
    if not data:
        return None
    for server in data.get("servers") or []:
        repo = server.get("repository") or {}
        repo_url = repo.get("url", "") if isinstance(repo, dict) else ""
        if _is_github_url(repo_url):
            return _normalise_github_url(repo_url)
    return None


def _auto_detect_github_url(
    package_name: Optional[str],
    ecosystem: Optional[str],
    url: Optional[str],
    is_http: bool,
    attestation_source_url: Optional[str] = None,
) -> Optional[str]:
    """
    Lookup chain:
    1. Attestation source_url already fetched from PyPI/npm registry
    2. npm registry repository.url (npm packages only)
    3. Official MCP registry search by package name or URL hostname hint
    """
    if _is_github_url(attestation_source_url):
        return _normalise_github_url(attestation_source_url)

    if ecosystem == "npm" and package_name:
        try:
            npm_url = _npm_source_url(package_name)
            if npm_url:
                return npm_url
        except Exception as exc:
            _log.debug("npm source url lookup failed for %s: %s", package_name, exc)

    name_hint: Optional[str] = None
    if package_name:
        name_hint = package_name
    elif is_http and url:
        host = (urllib.parse.urlparse(url).hostname or "").lower().replace("www.", "")
        parts = host.split(".")
        name_hint = parts[0] if parts and parts[0] else None

    if name_hint:
        try:
            mcp_url = _mcp_registry_lookup(name_hint)
            if mcp_url:
                return mcp_url
        except Exception as exc:
            _log.debug("MCP registry lookup failed for %s: %s", name_hint, exc)

    return None


def build_provenance_info(
    server_id: str,
    command: Optional[str],
    args: Optional[List[str]],
    url: Optional[str] = None,
    transport: Optional[str] = None,
    github_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build full provenance info for a server.

    For all servers: package detection, local pip/npm query, registry attestation,
    typosquatting check.
    For HTTP/SSE servers additionally: TLS cert fingerprint, resolved IPs.
    When github_url is provided: manifest fetch, dependency typosquatting scan,
    and source URL cross-check against registry attestation.

    Always returns (never raises) - errors are captured in the returned dict.
    """
    result: Dict[str, Any] = {"server_id": server_id}

    is_http = transport in ("sse", "streamable_http") or (not transport and url and not command)
    if is_http and url:
        result["tls_cert_fingerprint"] = get_tls_cert_fingerprint(url)
        dns = resolve_host_ips(url)
        result["resolved_ips"] = dns.get("ips", [])
        result["private_ips"] = dns.get("private_ips", [])
        if dns.get("error"):
            result["dns_error"] = dns["error"]

    detection = detect_package(command, args)
    ecosystem = detection["ecosystem"]
    package_name = detection.get("package_name")
    top_level = detection.get("top_level_package") or package_name

    result.update(
        {
            "ecosystem": ecosystem,
            "package_name": package_name,
            "detection_method": detection.get("detection_method"),
            "detection_confidence": detection.get("confidence", "none"),
        }
    )
    if detection.get("note"):
        result["note"] = detection["note"]

    if ecosystem == "unresolvable" or not package_name:
        result.update({"status": "unresolvable", "verified": False})
        return result

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

    registry_version = (result.get("attestation") or {}).get("registry_version", "")
    if installed_version and registry_version and installed_version != registry_version:
        result["version_drift"] = {
            "installed": installed_version,
            "registry_latest": registry_version,
            "behind": True,
        }

    squats = check_typosquatting(package_name)
    if squats:
        result["typosquatting_suspects"] = squats

    is_stdio = bool(command) and not is_http
    if is_stdio:
        try:
            if ecosystem == "pypi":
                env_pkgs = _scan_pip_environment(detection.get("python_executable"))
            elif ecosystem == "npm":
                env_pkgs = _scan_npm_environment()
            else:
                env_pkgs = None

            if env_pkgs:
                result["local_environment"] = {
                    "package_count": len(env_pkgs),
                    "source": "pip_list" if ecosystem == "pypi" else "npm_list",
                }
                dep_squats = check_dependency_typosquatting([p["name"] for p in env_pkgs])
                if dep_squats:
                    result["dependency_typosquatting"] = dep_squats
                cves = check_osv_vulns(env_pkgs, ecosystem)
                if cves:
                    result["dependency_cves"] = cves
        except Exception as exc:
            result["local_environment"] = {"source": "error", "error": str(exc)}

    if not github_url:
        try:
            attest_source = (result.get("attestation") or {}).get("source_url", "")
            detected = _auto_detect_github_url(
                package_name=package_name,
                ecosystem=ecosystem,
                url=url,
                is_http=is_http,
                attestation_source_url=attest_source,
            )
            if detected:
                github_url = detected
                result["github_url_detected"] = detected
        except Exception as exc:
            _log.debug("github url auto-detection failed for %s: %s", server_id, exc)

    if github_url:
        try:
            manifest = fetch_github_manifest(github_url)
            result["github_manifest"] = {
                "status": manifest.get("status"),
                "manifest_type": manifest.get("manifest_type"),
                "dependency_count": len(manifest.get("dependencies", [])),
            }
            if manifest.get("status") == "found":
                if not is_stdio:
                    all_deps = manifest.get("dependencies", []) + manifest.get("dev_dependencies", [])
                    dep_squats = check_dependency_typosquatting(all_deps)
                    if dep_squats:
                        result["dependency_typosquatting"] = dep_squats
                    versioned_deps = manifest.get("dependencies_versioned", [])
                    if versioned_deps:
                        cves = check_osv_vulns(versioned_deps, ecosystem)
                        if cves:
                            result["dependency_cves"] = cves

                attest_source = (result.get("attestation") or {}).get("source_url", "")
                if attest_source:
                    from urllib.parse import urlparse

                    gh_host = urlparse(github_url).netloc
                    at_host = urlparse(attest_source).netloc
                    result["attestation_source_matches_github"] = (
                        gh_host == at_host
                        and urlparse(github_url).path.strip("/").split("/")[:2]
                        == urlparse(attest_source).path.strip("/").split("/")[:2]
                    )
        except Exception as exc:
            result["github_manifest"] = {"status": "error", "error": str(exc)}

    return result
