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

**Credential protection (cref_ substitution):**

Register a server with a real credential and confirm the original value never appears in the response:

```bash
mcpsafetywarden register test-server --transport sse --url https://mcp.example.com \
  --headers '{"Authorization": "Bearer sk-ant-api03-test"}' --json
# Response should include credential_refs.headers.Authorization = "cref_<16hex>"
# Original "Bearer sk-ant-..." must NOT appear anywhere in the output
```

Confirm the credential is stored and resolved at connection time (use `--no-inspect` to skip a live server):

```bash
mcpsafetywarden register test-server --transport sse --url https://mcp.example.com \
  --headers '{"Authorization": "Bearer sk-ant-api03-test"}' --no-inspect --json | python -c "
import json, sys
r = json.load(sys.stdin)
crefs = r.get('credential_refs', {}).get('headers', {})
assert 'Authorization' in crefs, 'No cref created for Authorization header'
assert crefs['Authorization'].startswith('cref_'), 'Value is not a cref reference'
assert 'Bearer sk-ant' not in json.dumps(r), 'Real token leaked into response'
print('PASS: credential substituted correctly')
"
```
