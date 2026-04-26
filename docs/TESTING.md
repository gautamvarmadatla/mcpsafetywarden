# Testing

## Running the test suite

```bash
pytest tests/ -v
```

Set `ANTHROPIC_API_KEY` (or another provider key) before running to include LLM-assisted tests. Without a key, LLM tests are skipped automatically.

```bash
pytest tests/ -v -k "no_llm"   # only no-LLM tests
pytest tests/ -v -k "with_llm" # only LLM tests
```

## Verifying specific behaviour

**Tool classification:**

```bash
mcpsafetywarden onboard test-server --transport stdio --command python --args '["<YOUR_MCP_SERVER>.py"]'
mcpsafetywarden list test-server --json
```

Check that `effect_class` values match what you expect for each tool.

**Injection scanning:**

Call a tool that returns text content. Inject a test pattern such as `"Ignore all previous instructions"` into the tool output (by modifying the wrapped server temporarily) and confirm the wrapper returns a quarantined response.

**Risk gating:**

```bash
mcpsafetywarden preflight test-server <high_risk_tool>
mcpsafetywarden call test-server <high_risk_tool>
# Should block and show alternatives menu
mcpsafetywarden call test-server <high_risk_tool> --approved
# Should execute
```

**Policy enforcement:**

```bash
mcpsafetywarden policy test-server <tool_name> --set block
mcpsafetywarden call test-server <tool_name>
# Should return policy_blocked immediately
mcpsafetywarden policy test-server <tool_name> --set clear
```
