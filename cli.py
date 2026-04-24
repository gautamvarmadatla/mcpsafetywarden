#!/usr/bin/env python3
"""Command-line interface for MCP Behavior Wrapper."""
import asyncio
import json
import sys
from typing import Any, Optional, Union

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

import database as _db
from server import (
    get_run_history as _get_run_history,
    get_retry_policy as _get_retry_policy,
    get_security_scan as _get_security_scan,
    get_tool_profile as _get_tool_profile,
    inspect_server as _inspect_server,
    list_server_tools as _list_server_tools,
    list_servers as _list_servers,
    onboard_server as _onboard_server,
    ping_server as _ping_server,
    preflight_tool_call as _preflight_tool_call,
    register_server as _register_server,
    run_replay_test as _run_replay_test,
    safe_tool_call as _safe_tool_call,
    scan_all_servers as _scan_all_servers,
    security_scan_server as _security_scan_server,
    set_tool_policy as _set_tool_policy,
    suggest_safer_alternative as _suggest_safer_alternative,
)

app = typer.Typer(name="mcp-wrapper", add_completion=False, no_args_is_help=True)
console = Console(legacy_windows=False)
err = Console(stderr=True, legacy_windows=False)


def _run(coro):
    return asyncio.run(coro)


def _load(s: str) -> Union[dict, list]:
    try:
        return json.loads(s)
    except Exception:
        return {"error": "Failed to parse server response"}


def _die(result):
    if isinstance(result, dict) and "error" in result:
        err.print(f"[red]Error:[/red] {result['error']}")
        raise typer.Exit(1)


def _parse_args(args_str: Optional[str]) -> dict:
    if not args_str:
        return {}
    try:
        parsed = json.loads(args_str)
        if not isinstance(parsed, dict):
            err.print("[red]--args must be a JSON object[/red]")
            raise typer.Exit(1)
        return parsed
    except json.JSONDecodeError as e:
        err.print(f"[red]Invalid --args JSON: {e}[/red]")
        raise typer.Exit(1)


def _parse_json_array(s: Optional[str], name: str) -> Optional[list]:
    if not s:
        return None
    try:
        parsed = json.loads(s)
        if not isinstance(parsed, list):
            err.print(f"[red]{name} must be a JSON array[/red]")
            raise typer.Exit(1)
        return parsed
    except json.JSONDecodeError as e:
        err.print(f"[red]Invalid JSON in {name}: {e}[/red]")
        raise typer.Exit(1)


def _parse_json_opt(s: Optional[str], name: str) -> Optional[dict]:
    if not s:
        return None
    try:
        parsed = json.loads(s)
    except json.JSONDecodeError as e:
        err.print(f"[red]Invalid JSON in {name}: {e}[/red]")
        raise typer.Exit(1)
    if not isinstance(parsed, dict):
        err.print(f"[red]{name} must be a JSON object (got {type(parsed).__name__})[/red]")
        raise typer.Exit(1)
    return parsed


def _risk_badge(risk: str) -> str:
    return {
        "high":       "[bold red]HIGH[/bold red]",
        "medium":     "[bold yellow]MEDIUM[/bold yellow]",
        "medium-low": "[yellow]MEDIUM-LOW[/yellow]",
        "low":        "[green]LOW[/green]",
        "none":       "[dim]NONE[/dim]",
    }.get(risk.lower() if risk else "", risk or "unknown")


def _effect_badge(effect: str) -> str:
    return {
        "read_only":      "[green]read_only[/green]",
        "additive_write": "[yellow]additive_write[/yellow]",
        "mutating_write": "[yellow]mutating_write[/yellow]",
        "external_action":"[red]external_action[/red]",
        "destructive":    "[bold red]destructive[/bold red]",
    }.get(effect, effect)



@app.command("list")
def cmd_list(
    server_id: Optional[str] = typer.Argument(None, help="Server ID - omit to list all servers"),
    json_output: bool = typer.Option(False, "--json", help="Machine-readable JSON output"),
):
    """List registered servers, or tools on a specific server."""
    if server_id:
        result = _load(_list_server_tools(server_id))
        _die(result)
        if json_output:
            console.print_json(json.dumps(result))
            return
        t = Table(title=f"Tools - {server_id}", box=box.SIMPLE_HEAD)
        t.add_column("Tool", style="cyan")
        t.add_column("Effect")
        t.add_column("Runs", justify="right")
        t.add_column("Confidence", justify="right")
        for tool in result.get("tools", []):
            t.add_row(
                tool["name"],
                _effect_badge(tool.get("effect_class", "unknown")),
                str(tool.get("run_count", 0)),
                f"{tool.get('confidence', 0):.0%}",
            )
        console.print(t)
    else:
        result = _load(_list_servers())
        if json_output:
            console.print_json(json.dumps(result))
            return
        if not isinstance(result, list) or not result:
            console.print("[yellow]No servers registered.[/yellow]")
            return
        t = Table(title="Registered Servers", box=box.SIMPLE_HEAD)
        t.add_column("Server ID", style="cyan")
        t.add_column("Transport")
        t.add_column("Tools", justify="right")
        t.add_column("Registered")
        for s in result:
            t.add_row(s["server_id"], s["transport"], str(s["tool_count"]), s["registered_at"][:10])
        console.print(t)


@app.command("onboard")
def cmd_onboard(
    server_id: str = typer.Argument(...),
    transport: str = typer.Option(..., "--transport", "-t", help="stdio | sse | streamable_http"),
    command: Optional[str] = typer.Option(None, "--command", "-c", help="stdio: executable path"),
    args: Optional[str] = typer.Option(None, "--args", help="stdio: JSON array of arguments"),
    url: Optional[str] = typer.Option(None, "--url", help="sse/streamable_http: server URL"),
    env: Optional[str] = typer.Option(None, "--env", help="JSON object of env vars"),
    headers: Optional[str] = typer.Option(None, "--headers", help="JSON object of HTTP headers"),
    scan_provider: Optional[str] = typer.Option(None, "--scan-provider", help="anthropic | openai | gemini | ollama | cisco | snyk"),
    scan_model: Optional[str] = typer.Option(None, "--scan-model"),
    scan_api_key: Optional[str] = typer.Option(None, "--scan-api-key"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Register + security scan + inspect in one shot."""
    confirm_scan = yes or (
        scan_provider is not None and Confirm.ask(
            f"Active security probing will be sent to [cyan]{server_id}[/cyan]. "
            "Confirm you own and are authorized to test it?"
        )
    )

    with console.status(f"Onboarding [cyan]{server_id}[/cyan]..."):
        result = _load(_run(_onboard_server(
            server_id=server_id, transport=transport,
            command=command,
            args=_parse_json_array(args, "--args"),
            url=url,
            env=_parse_json_opt(env, "--env"),
            headers=_parse_json_opt(headers, "--headers"),
            scan_provider=scan_provider,
            scan_model=scan_model,
            scan_api_key=scan_api_key,
            confirm_scan_authorized=bool(confirm_scan),
        )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return

    reg = result.get("register", {})
    tools_found = reg.get("tools_discovered", 0)
    console.print(f"[green]✓[/green] Registered [cyan]{server_id}[/cyan] - {tools_found} tool(s) discovered")

    scan = result.get("security_scan") or {}
    if scan.get("skipped"):
        console.print(f"[yellow]⚠[/yellow]  Scan skipped: {scan['skipped']}")
    elif scan.get("error"):
        console.print(f"[red]✗[/red]  Scan failed: {scan['error']}")
    elif scan:
        risk = (scan.get("overall_risk_level") or "unknown").lower()
        console.print(f"[green]✓[/green] Scan complete - overall risk: {_risk_badge(risk)}")


@app.command("register")
def cmd_register(
    server_id: str = typer.Argument(...),
    transport: str = typer.Option(..., "--transport", "-t"),
    command: Optional[str] = typer.Option(None, "--command", "-c"),
    args: Optional[str] = typer.Option(None, "--args", help="JSON array"),
    url: Optional[str] = typer.Option(None, "--url"),
    env: Optional[str] = typer.Option(None, "--env", help="JSON object"),
    headers: Optional[str] = typer.Option(None, "--headers", help="JSON object"),
    no_inspect: bool = typer.Option(False, "--no-inspect", help="Skip auto-inspect"),
    provider: Optional[str] = typer.Option(None, "--provider", help="LLM for classification"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Register a server (with optional immediate inspect)."""
    result = _load(_run(_register_server(
        server_id=server_id, transport=transport,
        command=command,
        args=_parse_json_array(args, "--args"),
        url=url,
        env=_parse_json_opt(env, "--env"),
        headers=_parse_json_opt(headers, "--headers"),
        auto_inspect=not no_inspect,
        classify_provider=provider,
    )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    console.print(f"[green]✓[/green] Registered [cyan]{server_id}[/cyan] - {result.get('tools_discovered', 0)} tool(s)")


@app.command("inspect")
def cmd_inspect(
    server_id: str = typer.Argument(...),
    provider: Optional[str] = typer.Option(None, "--provider"),
    model: Optional[str] = typer.Option(None, "--model"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Refresh tool list and behavior profiles for a registered server."""
    with console.status(f"Inspecting [cyan]{server_id}[/cyan]..."):
        result = _load(_run(_inspect_server(
            server_id, classify_provider=provider,
            classify_model=model, classify_api_key=api_key,
        )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    console.print(f"[green]✓[/green] Inspected [cyan]{server_id}[/cyan] - {result.get('tools_discovered', 0)} tool(s)")


@app.command("scan")
def cmd_scan(
    server_id: str = typer.Argument(...),
    provider: str = typer.Option(..., "--provider", "-p", help="anthropic | openai | gemini | ollama | cisco | snyk"),
    model: Optional[str] = typer.Option(None, "--model"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable path traversal / command injection probes"),
    skip_web_research: bool = typer.Option(True, "--skip-web-research/--web-research", help="Skip DuckDuckGo/HackerNews/Arxiv CVE research (default: skip to avoid leaking findings)"),
    timeout: int = typer.Option(300, "--timeout", help="Scan timeout in seconds"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Run a live security scan on a registered server."""
    confirmed = yes or Confirm.ask(
        f"Active security probing will be sent to [cyan]{server_id}[/cyan]. "
        "Confirm you own and are authorized to test it?"
    )
    if not confirmed:
        raise typer.Exit(0)

    with console.status("Scanning..."):
        result = _load(_run(_security_scan_server(
            server_id=server_id, provider=provider,
            model_id=model, api_key=api_key,
            confirm_authorized=True,
            allow_destructive_probes=destructive,
            skip_web_research=skip_web_research,
            scan_timeout_s=timeout,
        )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return

    risk = (result.get("overall_risk_level") or "unknown").lower()
    console.print(f"Overall risk: {_risk_badge(risk)}")
    if result.get("summary"):
        console.print(result["summary"])

    findings = result.get("tool_findings", [])
    if findings:
        t = Table(box=box.SIMPLE_HEAD)
        t.add_column("Tool", style="cyan")
        t.add_column("Risk")
        t.add_column("Finding")
        for f in findings:
            t.add_row(
                f.get("name", ""),
                _risk_badge((f.get("risk_level") or "").lower()),
                (f.get("finding") or "")[:80],
            )
        console.print(t)

    ns = result.get("network_scan")
    if ns:
        console.print(f"\n[bold]Kali network scan[/bold] - {ns.get('nmap_target', '')}")
        for key in ("quick_scan", "vulnerability_scan", "traceroute"):
            val = ns.get(key)
            if val and not val.startswith("[AUX"):
                console.print(Panel(val[:600], title=key, expand=False))

    burp_count = result.get("burp_findings_count", 0)
    if burp_count:
        console.print(f"\n[bold]Burp Suite[/bold] added [cyan]{burp_count}[/cyan] HTTP-layer finding(s) - use [dim]--json[/dim] for full detail")


@app.command("call")
def cmd_call(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    args: Optional[str] = typer.Option(None, "--args", "-a", help="JSON object of tool arguments"),
    approved: bool = typer.Option(False, "--approved", help="Bypass risk gate (for scripting)"),
    args_scan_override: bool = typer.Option(False, "--args-scan-override", help="Skip arg safety scan (use only when you have verified the args are safe)"),
    provider: Optional[str] = typer.Option(None, "--provider", help="LLM for alternatives"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Execute a tool safely with interactive risk gating."""
    parsed_args = _parse_args(args)

    result = _run(_safe_tool_call(
        server_id=server_id, tool_name=tool_name,
        args=parsed_args, approved=approved,
        args_scan_override=args_scan_override,
        llm_provider=provider,
    ))
    result = _load(result)

    if not result.get("blocked"):
        _print_call_result(result, json_output)
        return

    if result.get("reason") == "policy_blocked":
        err.print(f"[red]✗ Blocked by policy:[/red] {result.get('message', '')}")
        raise typer.Exit(1)

    if result.get("reason") == "arg_scan_blocked":
        console.print(Panel(
            f"[red]✗ Arg scan blocked[/red]\n"
            f"  Arg:        [yellow]{result.get('flagged_arg', '?')}[/yellow]\n"
            f"  Value:      [yellow]{result.get('flagged_value', '')[:120]}[/yellow]\n"
            f"  Categories: {', '.join(result.get('categories', []))}\n"
            f"  Verified:   {'LLM (confidence ' + str(result.get('llm_confidence', '')) + ')' if result.get('llm_verified') else 'pattern only'}",
            title="Security: argument scan",
        ))
        if result.get("llm_verified"):
            err.print(f"[red]LLM confirmed threat:[/red] {result.get('reason', '')}")
            raise typer.Exit(1)
        if Confirm.ask("[yellow]LLM not available - proceed anyway?[/yellow] (only if you trust these args)"):
            result = _load(_run(_safe_tool_call(
                server_id=server_id, tool_name=tool_name,
                args=parsed_args, approved=approved,
                args_scan_override=True, llm_provider=provider,
            )))
            _print_call_result(result, json_output)
        else:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(0)
        return

    alternatives = result.get("alternatives", [])
    risk = result.get("risk_level", "unknown")
    console.print(Panel(
        f"[yellow]⚠ Blocked[/yellow]  risk: {_risk_badge(risk)}",
        title=f"{tool_name}",
    ))
    for alt in alternatives:
        name = alt.get("tool", "")
        if name == "More options":
            console.print(f"  [dim]{alt['option']}.[/dim]  More options")
        else:
            console.print(
                f"  [cyan]{alt['option']}.[/cyan]  [bold]{name}[/bold]"
                f"  - reduction: {alt.get('risk_reduction', '?')}"
                f"  coverage: {alt.get('functional_coverage', '?')}"
            )

    choice = Prompt.ask("Pick").strip()
    more_idx = str(len(alternatives))

    if choice == more_idx:
        more = _load(_run(_safe_tool_call(
            server_id=server_id, tool_name=tool_name,
            args=parsed_args, show_more_options=True,
            llm_provider=provider,
        )))
        for opt in more.get("options", []):
            console.print(f"  [cyan]{opt['choice']}.[/cyan]  {opt['action']}")

        sub = Prompt.ask("Pick", choices=["B", "b", "C", "c"]).upper()
        if sub == "C":
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(0)

        result = _load(_run(_safe_tool_call(
            server_id=server_id, tool_name=tool_name,
            args=parsed_args, approved=True,
            args_scan_override=args_scan_override, llm_provider=provider,
        )))
        _print_call_result(result, json_output)
        return

    try:
        chosen = alternatives[int(choice) - 1]
    except (ValueError, IndexError):
        err.print("[red]Invalid choice.[/red]")
        raise typer.Exit(1)

    result = _load(_run(_safe_tool_call(
        server_id=server_id, tool_name=tool_name,
        args=parsed_args, use_alternative=chosen["tool"],
        args_scan_override=args_scan_override, llm_provider=provider,
    )))

    if result.get("blocked"):
        if result.get("reason") == "alternative_also_requires_approval":
            console.print(f"'{chosen['tool']}' also requires approval.")
            if Confirm.ask("Proceed anyway?"):
                result = _load(_run(_safe_tool_call(
                    server_id=server_id, tool_name=tool_name,
                    args=parsed_args, use_alternative=chosen["tool"],
                    approved=True, args_scan_override=args_scan_override, llm_provider=provider,
                )))
            else:
                console.print("[yellow]Aborted.[/yellow]")
                raise typer.Exit(0)
        else:
            err.print(f"[red]Blocked:[/red] {result.get('message') or result.get('reason', 'unknown reason')}")
            raise typer.Exit(1)

    _print_call_result(result, json_output)


def _print_call_result(result: dict, json_output: bool):
    if "error" in result:
        err.print(f"[red]Error:[/red] {result['error']}")
        raise typer.Exit(1)
    if json_output:
        console.print_json(json.dumps(result))
        return
    if result.get("quarantined"):
        console.print(Panel(
            f"[red]⚠ Output quarantined - possible injection attack[/red]\n{result.get('message', '')}",
            title="Security Warning",
        ))
        return
    tel = result.get("telemetry", {})
    items = result.get("result", [])
    text = "\n".join(
        i.get("text", str(i)) if isinstance(i, dict) else str(i)
        for i in items
    )
    executed_with = result.get("executed_with") or result.get("executed_tool")
    title = f"✓  {tel.get('latency_ms', '?')}ms"
    if executed_with:
        title += f"  [{executed_with}]"
    console.print(Panel(text[:4000] or "(empty response)", title=title))
    if result.get("warning"):
        console.print(f"[yellow]⚠[/yellow]  {result['warning']}")
    if tel.get("args_secret_warning"):
        console.print(f"[yellow]⚠[/yellow]  {tel['args_secret_warning']}")


@app.command("preflight")
def cmd_preflight(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="LLM provider for classification fallback"),
    model: Optional[str] = typer.Option(None, "--model"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Risk assessment for a tool without executing it."""
    result = _load(_run(_preflight_tool_call(
        server_id=server_id, tool_name=tool_name,
        llm_provider=provider, llm_model=model, llm_api_key=api_key,
    )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    a = result.get("assessment", {})
    lines = [
        f"Effect:          {_effect_badge(a.get('likely_effect', 'unknown'))}",
        f"Risk:            {_risk_badge(a.get('risk_level', 'unknown'))}",
        f"Destructiveness: {a.get('likely_destructiveness', 'unknown')}",
        f"Retry safety:    {a.get('likely_retry_safety', 'unknown')}",
        f"Approval needed: {a.get('approval_recommended', False)}",
        f"Latency band:    {a.get('expected_latency_band', 'unknown')}",
        f"Data source:     {result.get('data_source', 'unknown')}",
    ]
    console.print(Panel("\n".join(lines), title=f"Preflight - {tool_name}"))
    if result.get("security"):
        sec = result["security"]
        console.print(
            f"[red]Security:[/red] {sec.get('risk_level')} - {(sec.get('finding') or '')[:100]}"
        )
    if result.get("warning"):
        console.print(f"[yellow]⚠[/yellow]  {result['warning']}")


@app.command("profile")
def cmd_profile(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
):
    """Full observed behavior profile for a tool."""
    result = _load(_get_tool_profile(server_id=server_id, tool_name=tool_name))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    console.print_json(json.dumps(result.get("profile", {})))


@app.command("retry-policy")
def cmd_retry_policy(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    provider: Optional[str] = typer.Option(None, "--provider", "-p", help="LLM provider for classification fallback"),
    model: Optional[str] = typer.Option(None, "--model"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Retry and timeout recommendations for a tool."""
    result = _load(_get_retry_policy(
        server_id=server_id, tool_name=tool_name,
        llm_provider=provider, llm_model=model, llm_api_key=api_key,
    ))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    console.print(Panel(
        f"Policy:      {result.get('recommended_policy')}\n"
        f"Max retries: {result.get('max_retries')}\n"
        f"Backoff:     {result.get('backoff_strategy')}\n"
        f"Timeout:     {result.get('suggested_timeout_ms')}ms\n"
        f"Retry safety:{result.get('retry_safety', 'unknown')}",
        title=f"Retry Policy - {tool_name}",
    ))


@app.command("alternatives")
def cmd_alternatives(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    provider: Optional[str] = typer.Option(None, "--provider"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Find lower-risk alternatives for a tool on the same server."""
    result = _load(_suggest_safer_alternative(
        server_id=server_id, tool_name=tool_name, llm_provider=provider,
    ))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    alts = result.get("alternatives", [])
    if not alts:
        console.print(result.get("message", "[yellow]No alternatives found.[/yellow]"))
        return
    t = Table(box=box.SIMPLE_HEAD)
    t.add_column("Tool", style="cyan")
    t.add_column("Risk Reduction")
    t.add_column("Coverage")
    t.add_column("Why safer")
    for a in alts:
        t.add_row(
            a.get("tool", ""),
            a.get("risk_reduction", ""),
            a.get("functional_coverage", ""),
            (a.get("why_safer") or "")[:60],
        )
    console.print(t)


@app.command("replay")
def cmd_replay(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    args: Optional[str] = typer.Option(None, "--args", "-a"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Test idempotency by running a tool twice with identical args."""
    confirmed = yes or Confirm.ask(
        f"This will execute [cyan]{tool_name}[/cyan] TWICE. Confirm?"
    )
    if not confirmed:
        raise typer.Exit(0)

    result = _load(_run(_run_replay_test(
        server_id=server_id, tool_name=tool_name,
        args=_parse_args(args), approved=True,
    )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    verdict = result.get("verdict", "unknown")
    color = "green" if verdict == "likely_idempotent" else "yellow"
    console.print(f"[{color}]{verdict}[/{color}]  -  {result.get('interpretation', '')}")
    if result.get("burp_proxy_traffic"):
        console.print(Panel(result["burp_proxy_traffic"][:600], title="Burp proxy traffic", expand=False))


@app.command("policy")
def cmd_policy(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    set_policy: Optional[str] = typer.Option(None, "--set", help="allow | block | clear"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Get or set execution policy for a tool (allow / block / clear). Omit --set to read."""
    if set_policy is None:
        tool = _db.get_tool(server_id, tool_name)
        if not tool:
            err.print(f"[red]Error:[/red] Tool '{tool_name}' not found on server '{server_id}'.")
            raise typer.Exit(1)
        current = _db.get_tool_policy(server_id, tool_name) or "none"
        if json_output:
            console.print_json(json.dumps({"server_id": server_id, "tool": tool_name, "policy": current}))
            return
        color = {"allow": "green", "block": "red"}.get(current, "dim")
        console.print(f"[cyan]{tool_name}[/cyan] policy: [{color}]{current}[/{color}]")
        return

    policy_val = None if set_policy == "clear" else set_policy
    result = _load(_set_tool_policy(
        server_id=server_id, tool_name=tool_name, policy=policy_val,
    ))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    p = result.get("policy", "none")
    color = {"allow": "green", "block": "red", "cleared": "dim"}.get(p, "white")
    console.print(f"[cyan]{tool_name}[/cyan] policy: [{color}]{p}[/{color}]")


@app.command("history")
def cmd_history(
    server_id: str = typer.Argument(...),
    tool_name: str = typer.Argument(...),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of runs to show"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Recent execution history for a tool."""
    result = _load(_get_run_history(server_id=server_id, tool_name=tool_name, limit=limit))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    runs = result.get("runs", [])
    if not runs:
        console.print("[yellow]No runs recorded yet.[/yellow]")
        return
    t = Table(title=f"History - {tool_name}", box=box.SIMPLE_HEAD)
    t.add_column("ID", justify="right", style="dim")
    t.add_column("Timestamp")
    t.add_column("OK")
    t.add_column("Latency", justify="right")
    t.add_column("Output", justify="right")
    t.add_column("Notes")
    for r in runs:
        ok = "[green]✓[/green]" if r.get("success") else "[red]✗[/red]"
        t.add_row(
            str(r.get("run_id", "")),
            (r.get("timestamp") or "")[:19],
            ok,
            f"{r.get('latency_ms', 0):.0f}ms",
            f"{r.get('output_size', 0):,}B",
            (r.get("notes") or "")[:50],
        )
    console.print(t)


@app.command("ping")
def cmd_ping(
    server_id: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
):
    """Check if a registered server is reachable."""
    result = _load(_run(_ping_server(server_id=server_id)))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    status = result.get("status", "unknown")
    latency = result.get("latency_ms")
    if status == "reachable":
        console.print(f"[green]✓[/green]  {server_id}  -  reachable ({latency}ms)")
    elif status == "timeout":
        console.print(f"[yellow]⚠[/yellow]  {server_id}  -  timeout after {latency}ms")
        raise typer.Exit(1)
    else:
        console.print(f"[red]✗[/red]  {server_id}  -  unreachable: {result.get('error', '')}")
        raise typer.Exit(1)

    ns = result.get("network_scan")
    if ns:
        console.print(f"\n[bold]Kali network scan[/bold] - {ns.get('nmap_target', '')}")
        for key in ("quick_scan", "vulnerability_scan", "traceroute"):
            val = ns.get(key)
            if val and not val.startswith("[AUX"):
                console.print(Panel(val[:600], title=key, expand=False))


@app.command("get-scan")
def cmd_get_scan(
    server_id: str = typer.Argument(...),
    json_output: bool = typer.Option(False, "--json"),
):
    """Retrieve the latest stored security scan report."""
    result = _load(_get_security_scan(server_id=server_id))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return
    risk = (result.get("overall_risk_level") or "unknown").lower()
    console.print(f"Risk: {_risk_badge(risk)}")
    if result.get("summary_text"):
        console.print(result["summary_text"])
    findings = result.get("tool_findings", [])
    if findings:
        t = Table(box=box.SIMPLE_HEAD)
        t.add_column("Tool", style="cyan")
        t.add_column("Risk")
        t.add_column("Finding")
        for f in findings:
            t.add_row(
                f.get("name", ""),
                _risk_badge((f.get("risk_level") or "").lower()),
                (f.get("finding") or "")[:80],
            )
        console.print(t)


@app.command("scan-all")
def cmd_scan_all(
    provider: str = typer.Option(..., "--provider", "-p", help="anthropic | openai | gemini | ollama"),
    model: Optional[str] = typer.Option(None, "--model"),
    api_key: Optional[str] = typer.Option(None, "--api-key"),
    server_ids: Optional[str] = typer.Option(None, "--servers", help="Comma-separated server IDs to scan; omit for all"),
    destructive: bool = typer.Option(False, "--destructive", help="Enable path traversal / command injection probes"),
    skip_web_research: bool = typer.Option(True, "--skip-web-research/--web-research", help="Skip DuckDuckGo/HackerNews/Arxiv CVE research (default: skip to avoid leaking findings)"),
    timeout: int = typer.Option(300, "--timeout", help="Timeout per server in seconds"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Run the 5-stage MCPSafety pipeline against all registered servers (or a subset)."""
    sid_list = [s.strip() for s in server_ids.split(",")] if server_ids else None
    target = f"[cyan]{', '.join(sid_list)}[/cyan]" if sid_list else "all registered servers"

    confirmed = yes or Confirm.ask(
        f"Active security probing will be sent to {target}. "
        "Confirm you own and are authorized to test them?"
    )
    if not confirmed:
        raise typer.Exit(0)

    with console.status(f"Scanning {target}..."):
        result = _load(_run(_scan_all_servers(
            provider=provider,
            model_id=model,
            api_key=api_key,
            confirm_authorized=True,
            allow_destructive_probes=destructive,
            skip_web_research=skip_web_research,
            scan_timeout_s=timeout,
            server_ids=sid_list,
        )))
    _die(result)
    if json_output:
        console.print_json(json.dumps(result))
        return

    risk = (result.get("overall_risk_level") or "unknown").lower()
    n = result.get("servers_scanned", 0)
    console.print(f"Scanned {n} server(s) - overall risk: {_risk_badge(risk)}")

    top = result.get("top_findings", [])
    if top:
        t = Table(title="Top Findings", box=box.SIMPLE_HEAD)
        t.add_column("Server", style="dim")
        t.add_column("Tool", style="cyan")
        t.add_column("Risk")
        t.add_column("Finding")
        for f in top:
            t.add_row(
                f.get("_server_id", ""),
                f.get("name", ""),
                _risk_badge((f.get("risk_level") or "").lower()),
                (f.get("finding") or "")[:70],
            )
        console.print(t)

    skipped = result.get("skipped_servers", [])
    for s in skipped:
        console.print(f"[yellow]⚠[/yellow]  {s['server_id']} skipped: {s['reason']}")


if __name__ == "__main__":
    app()
