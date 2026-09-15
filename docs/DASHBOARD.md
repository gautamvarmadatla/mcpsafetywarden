## Dashboard

A local web dashboard for the data mcpsafetywarden already collects: registered servers, tool behaviour profiles, security findings, call history, policies and the risk graph.

```bash
mcpsafetywarden dashboard                # opens http://127.0.0.1:7070
mcpsafetywarden dashboard --port 8080 --no-browser
```

The dashboard reads the same database as the CLI and MCP server (`MCP_DB_PATH`, or the platform data directory by default). It binds to `127.0.0.1` unless you pass `--host`.

### Screens

| Screen | What you can do |
|---|---|
| Overview | Posture at a glance: servers, tools, open findings, calls in the last 24 hours, tool risk and the findings that need attention. Start a scan of every server. |
| Findings | Tool findings and server-level risks from the latest scan of each server, sorted by severity. Open a finding to read the exploitation path and remediation, block or unblock the tool, or rescan its server. |
| History | Every call that passed through the proxy, grouped by day. Filter by outcome, server, tool or text, open a call to see its output preview, load older calls and export to CSV. |
| Servers | Registered servers with transport, tool count, 7 day call trend and latest risk. Add a server manually or register the ones found in your MCP client configs. |
| Server detail | Tools, the latest scan report, drift between tool snapshots, and the command or URL the server runs from. |
| Tools | Behaviour profiles for every tool, with server-side search, policy and effect filters and paging. Open a tool to set its policy, see findings, recent calls and the input schema. |
| Risk graph | Clients, servers, tools, findings and ATT&CK techniques as a layered dependency graph. Expand servers, select a node to trace its chain, double-click to drill in, and follow named attack paths. |
| Policies | Explicit allow and block rules. Add a rule, switch or remove it with undo, or block every tool with a critical or high finding after reviewing the list. |

### Scans from the dashboard

Scan buttons ask you to confirm that you own the servers or are authorized to test them, the same as the CLI. Scans are queued and run one server at a time, so scanning a large inventory does not start hundreds of probes at once. The top bar shows the server being scanned and lets you cancel the rest of the queue. Scans use the same auto-detected providers as `mcpsafetywarden scan`.

### Keyboard

| Keys | Action |
|---|---|
| `Ctrl K` / `Cmd K` | Command palette: jump to any page, server or finding, scan all servers, add a server, switch theme |
| `/` | Focus the search field on the current page |
| `j` / `k`, `Enter` | Move through findings and open one |
| `Esc` | Close the panel, dialog or palette; in the graph, clear the selection or step out of a drill-down |
| `F`, `+`, `-` | Fit, zoom in and zoom out in the risk graph |

### Themes

Light is the default. The sidebar switch offers Light, Dark and System, and the choice is remembered in the browser.

### Security model

Read endpoints are plain `GET` requests. Every request that changes state (policies, scans, registration) must carry the `X-Warden-Client: dashboard` header, and its `Origin`, when present, must match the dashboard host or be another loopback address. Browsers cannot attach that header cross-site without a CORS preflight, and the API does not answer preflights, so other websites cannot drive the dashboard. Registering a stdio server runs its command on this machine, exactly like `mcpsafetywarden register`.

Discovered client configs are returned without their environment variables or headers.

### Development

```bash
cd dashboard
npm install
npm run dev          # Vite on :5173, proxies /api to :7070
npm run build        # type-checks and writes mcpsafetywarden/static
```

Run the API with `mcpsafetywarden dashboard --no-browser` in another terminal. For realistic data without touching your real database, seed a throwaway one:

```bash
MCP_DB_PATH=/tmp/warden-demo.db python scripts/seed_dashboard_demo.py
MCP_DB_PATH=/tmp/warden-demo.db mcpsafetywarden dashboard --no-browser
```

API tests live in `tests/test_dashboard_api.py` and run against a temporary database.
